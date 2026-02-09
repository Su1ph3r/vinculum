"""Parser for Mobilicustos mobile security scanner JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.mobilicustos")

# Categories that indicate dynamic analysis findings
DYNAMIC_CATEGORIES = {"runtime", "network_traffic", "dynamic_analysis", "api_communication"}


class MobilicustosParser(BaseParser):
    """
    Parser for Mobilicustos mobile security scanner JSON export format.

    Mobilicustos performs static and dynamic analysis of mobile applications
    (Android/iOS), checking for OWASP MASVS compliance and common
    mobile security vulnerabilities.
    """

    @property
    def tool_name(self) -> str:
        return "mobilicustos"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Mobilicustos export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                if "app" not in data or "findings" not in data:
                    return False
                # Check that findings contain app_id to disambiguate
                findings = data.get("findings", [])
                if findings and isinstance(findings, list) and len(findings) > 0:
                    return "app_id" in findings[0]
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Mobilicustos JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if "app" not in data or "findings" not in data:
            raise ParseError("Not a valid Mobilicustos export", file_path)

        app_info = data.get("app", {})
        findings = []

        for raw_finding in data.get("findings", []):
            if raw_finding.get("status") == "false_positive":
                logger.debug(f"Skipping false positive: {raw_finding.get('title')}")
                continue

            finding = self._parse_finding(raw_finding, app_info)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_finding(
        self, raw: dict[str, Any], app_info: dict[str, Any]
    ) -> UnifiedFinding | None:
        """Parse a single Mobilicustos finding."""
        severity = Severity.from_string(raw.get("severity", "info"))
        confidence = Confidence.from_string(raw.get("confidence", "tentative"))

        # Determine finding type based on category
        category = raw.get("category", "").lower()
        finding_type = FindingType.DAST if category in DYNAMIC_CATEGORIES else FindingType.SAST

        # Build location
        location = FindingLocation(
            file_path=raw.get("file_path"),
            line_start=raw.get("line_number"),
        )

        # Extract CWEs
        cwe_ids = []
        if raw.get("cwe_id"):
            cwe_ids.append(raw["cwe_id"])
        cwe_ids = list(set(cwe_ids))

        # Build tags from MASVS/MASTG metadata and app info
        tags = list(raw.get("tags", []))
        if raw.get("owasp_masvs_category"):
            tags.append(f"masvs:{raw['owasp_masvs_category']}")
        if raw.get("control"):
            tags.append(f"masvs-control:{raw['control']}")
        if raw.get("mastg_test"):
            tags.append(f"mastg:{raw['mastg_test']}")

        # Add app metadata tags
        platform = app_info.get("platform")
        package_name = app_info.get("package_name")
        app_name = app_info.get("app_name")
        if platform:
            tags.append(f"platform:{platform}")
        if package_name:
            tags.append(f"package:{package_name}")
        if app_name:
            tags.append(f"app_name:{app_name}")

        # Include app metadata in raw_data for downstream extraction
        raw_data = dict(raw)
        raw_data["_app_info"] = app_info

        return UnifiedFinding(
            source_tool="mobilicustos",
            source_id=raw.get("finding_id", ""),
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            severity=severity,
            confidence=confidence,
            cwe_ids=cwe_ids,
            location=location,
            finding_type=finding_type,
            evidence=raw.get("poc_evidence"),
            remediation=raw.get("remediation"),
            references=raw.get("references", []),
            tags=tags,
            raw_data=raw_data,
        )
