"""Parser for Ariadne/Vinculum knowledge-graph export JSON files (closed-loop feedback)."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.ariadne")


class AriadneParser(BaseParser):
    """
    Parser for Vinculum's own Ariadne export format (vinculum-ariadne-export v1.1).

    Enables closed-loop feedback: Ariadne output from a previous run can be
    re-ingested into Vinculum for incremental correlation and enrichment.
    """

    @property
    def tool_name(self) -> str:
        return "ariadne"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Detect by the 'format': 'vinculum-ariadne-export' key."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return data.get("format") == "vinculum-ariadne-export"
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Ariadne export JSON file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if data.get("format") != "vinculum-ariadne-export":
            raise ParseError("Not a valid Ariadne export (missing format key)", file_path)

        findings: list[UnifiedFinding] = []

        # Parse vulnerabilities
        for vuln in data.get("vulnerabilities", []):
            finding = self._parse_entry(vuln, is_vulnerability=True)
            if finding:
                findings.append(finding)

        # Parse misconfigurations
        for misconfig in data.get("misconfigurations", []):
            finding = self._parse_entry(misconfig, is_vulnerability=False)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_entry(
        self, entry: dict[str, Any], is_vulnerability: bool
    ) -> UnifiedFinding | None:
        """Parse a vulnerability or misconfiguration entry."""
        title = entry.get("title", "")
        if not title:
            return None

        severity = Severity.from_string(entry.get("severity", "info"))

        # Reconstruct location
        host_ip = entry.get("host_ip")
        port = entry.get("port")
        protocol = entry.get("protocol", "tcp")

        location = FindingLocation(
            host=host_ip,
            port=port,
            protocol=protocol,
        )

        # Extract CVE/CWE
        cve_ids = []
        if entry.get("cve_id"):
            cve_ids.append(entry["cve_id"])

        # Extract vinculum_metadata for provenance
        vm = entry.get("vinculum_metadata", {})
        correlation_id = vm.get("correlation_id")
        fingerprint = vm.get("fingerprint", "")
        source_tools = vm.get("source_tools", [])

        # Determine source_id — use correlation_id or check_id
        source_id = correlation_id or entry.get("check_id", title)

        # Determine finding type
        finding_type = FindingType.DAST if is_vulnerability else FindingType.NETWORK

        # Build confidence from source_tools count
        if len(source_tools) >= 2:
            confidence = Confidence.CERTAIN
        elif len(source_tools) == 1:
            confidence = Confidence.FIRM
        else:
            confidence = Confidence.TENTATIVE

        # Preserve vinculum_metadata in raw_data for round-trip
        raw_data: dict[str, Any] = {"vinculum_metadata": vm}

        # EPSS data
        epss_score = vm.get("epss_score")
        epss_percentile = vm.get("epss_percentile")

        # Tags from source tools
        tags = [f"source:{tool}" for tool in source_tools]

        return UnifiedFinding(
            source_tool="ariadne",
            source_id=source_id,
            title=title,
            description=entry.get("description", ""),
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cvss_score=entry.get("cvss_score"),
            location=location,
            finding_type=finding_type,
            remediation=entry.get("remediation"),
            fingerprint=fingerprint,
            correlation_id=correlation_id,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            tags=tags,
            raw_data=raw_data,
        )
