"""Parser for Checkov JSON output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.checkov")

# Check types that map to CLOUD finding type
_CLOUD_CHECK_TYPES = {"terraform", "cloudformation", "arm", "bicep"}

# Check types that map to CONTAINER finding type
_CONTAINER_CHECK_TYPES = {"dockerfile", "kubernetes", "helm", "k8s"}


class CheckovParser(BaseParser):
    """
    Parser for Checkov infrastructure-as-code scanner JSON output.

    Supports both the list format (multiple check types) and
    the dict format (single check type with passed/failed keys).
    """

    @property
    def tool_name(self) -> str:
        return "checkov"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is Checkov output."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                # List format: array of check type results
                if isinstance(data, list) and data:
                    return "check_type" in data[0]
                # Dict format: single result with passed/failed and check objects
                if isinstance(data, dict):
                    return (
                        "passed" in data
                        and "failed" in data
                        and "check_type" in data
                    )
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Checkov JSON output file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                findings = self._parse_list_format(data)
            elif isinstance(data, dict):
                findings = self._parse_dict_format(data)

        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_list_format(self, data: list[dict[str, Any]]) -> list[UnifiedFinding]:
        """Parse Checkov list format (array of check type results)."""
        findings = []
        for item in data:
            check_type = item.get("check_type", "")
            results = item.get("results", {})
            failed_checks = results.get("failed_checks", [])

            for check in failed_checks:
                try:
                    finding = self._parse_failed_check(check, check_type)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.warning("Skipping malformed Checkov check: %s", e)
                    continue

        return findings

    def _parse_dict_format(self, data: dict[str, Any]) -> list[UnifiedFinding]:
        """Parse Checkov dict format (single result with passed/failed)."""
        findings = []
        check_type = data.get("check_type", "")
        failed_checks = data.get("failed", [])

        for check in failed_checks:
            try:
                finding = self._parse_failed_check(check, check_type)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning("Skipping malformed Checkov check: %s", e)
                continue

        return findings

    def _parse_failed_check(
        self,
        check: dict[str, Any],
        check_type: str,
    ) -> UnifiedFinding | None:
        """Parse a single failed Checkov check."""
        check_id = check.get("check_id", "")
        if not check_id:
            return None

        name = check.get("name", check_id)
        description = check.get("description", name)

        # Map severity (Checkov may or may not include severity)
        severity_str = check.get("severity")
        if severity_str:
            severity = self._map_severity(severity_str)
        else:
            severity = Severity.MEDIUM  # Default for failed checks

        # Determine finding type from check_type
        finding_type = self._determine_finding_type(check_type)

        # Build location from file path and line range
        file_path_str = check.get("file_path")
        line_range = check.get("file_line_range", [])
        line_start = line_range[0] if len(line_range) >= 1 else None
        line_end = line_range[1] if len(line_range) >= 2 else None

        # Clean file_path (Checkov often prefixes with /)
        if file_path_str and file_path_str.startswith("/"):
            file_path_str = file_path_str.lstrip("/")

        location = FindingLocation(
            file_path=file_path_str,
            line_start=line_start,
            line_end=line_end,
            code_snippet=check.get("code_block") if check.get("code_block") else None,
        )

        # Extract CWE from bc_check_id if present
        cwe_ids = []
        bc_check_id = check.get("bc_check_id", "")
        if bc_check_id and bc_check_id.upper().startswith("CWE-"):
            cwe_ids.append(bc_check_id.upper())

        # Build tags
        tags = []
        if check_type:
            tags.append(check_type)
        guideline = check.get("guideline")
        if guideline:
            tags.append("has-guideline")

        # References
        references = []
        if guideline:
            references.append(guideline)

        # Remediation
        remediation = None
        if guideline:
            remediation = f"See guideline: {guideline}"

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=check_id,
            title=name,
            description=description,
            severity=severity,
            confidence=Confidence.FIRM,
            cwe_ids=cwe_ids,
            location=location,
            finding_type=finding_type,
            remediation=remediation,
            references=references,
            tags=tags,
            raw_data={
                "check_id": check_id,
                "check_type": check_type,
                "check_result": check.get("check_result", {}),
                "resource": check.get("resource", ""),
                "bc_check_id": bc_check_id,
            },
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Checkov severity to unified severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "none": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _determine_finding_type(self, check_type: str) -> FindingType:
        """Determine finding type based on Checkov check_type."""
        check_type_lower = check_type.lower()

        for cloud_type in _CLOUD_CHECK_TYPES:
            if cloud_type in check_type_lower:
                return FindingType.CLOUD

        for container_type in _CONTAINER_CHECK_TYPES:
            if container_type in check_type_lower:
                return FindingType.CONTAINER

        return FindingType.OTHER
