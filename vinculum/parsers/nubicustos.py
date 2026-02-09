"""Parser for Nubicustos cloud security scanner JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nubicustos")


class NubicustosParser(BaseParser):
    """
    Parser for Nubicustos cloud security scanner JSON export format.

    Nubicustos scans cloud infrastructure (AWS, GCP, Azure) for
    misconfigurations, vulnerabilities, and compliance violations.
    """

    @property
    def tool_name(self) -> str:
        return "nubicustos"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Nubicustos export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return (
                    "export_timestamp" in data
                    and "total_findings" in data
                    and "findings" in data
                )
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nubicustos JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if not ("export_timestamp" in data and "total_findings" in data and "findings" in data):
            raise ParseError("Not a valid Nubicustos export", file_path)

        findings = []

        for raw_finding in data.get("findings", []):
            if raw_finding.get("status") == "false_positive":
                logger.debug(f"Skipping false positive: {raw_finding.get('title')}")
                continue

            finding = self._parse_finding(raw_finding)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_finding(self, raw: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single Nubicustos finding."""
        tool = raw.get("tool", "unknown")
        source_tool = f"nubicustos:{tool}"

        severity = Severity.from_string(raw.get("severity", "info"))
        confidence = Confidence.from_string(raw.get("confidence", "tentative"))

        # Extract CVEs
        cve_ids = []
        if raw.get("cve_id"):
            if isinstance(raw["cve_id"], list):
                cve_ids.extend(raw["cve_id"])
            else:
                cve_ids.append(raw["cve_id"])
        cve_ids = list(set(cve_ids))

        # Extract CWEs
        cwe_ids = []
        if raw.get("cwe_id"):
            cwe_ids.append(raw["cwe_id"])
        cwe_ids = list(set(cwe_ids))

        # CVSS score
        cvss_score = raw.get("cvss_score")

        # Build location
        location = FindingLocation(
            host=raw.get("resource_id"),
        )

        # Build tags from cloud metadata
        tags = list(raw.get("tags", []))
        if raw.get("cloud_provider"):
            tags.append(f"cloud:{raw['cloud_provider']}")
        if raw.get("region"):
            tags.append(f"region:{raw['region']}")
        if raw.get("resource_type"):
            tags.append(f"resource:{raw['resource_type']}")
        for framework in raw.get("compliance_frameworks", []):
            tags.append(f"compliance:{framework}")

        return UnifiedFinding(
            source_tool=source_tool,
            source_id=raw.get("finding_id", ""),
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            location=location,
            finding_type=FindingType.CLOUD,
            evidence=raw.get("evidence"),
            remediation=raw.get("remediation"),
            references=raw.get("references", []),
            tags=tags,
            raw_data=raw,
        )
