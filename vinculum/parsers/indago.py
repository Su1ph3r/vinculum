"""Parser for Indago API security scanner JSON export files."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.indago")


class IndagoParser(BaseParser):
    """
    Parser for Indago API security scanner JSON export format.

    Indago performs dynamic API security testing, discovering and
    testing endpoints for injection, authentication bypass, and other
    OWASP API Security Top 10 vulnerabilities.
    """

    @property
    def tool_name(self) -> str:
        return "indago"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is an Indago export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return "scan_id" in data and "target" in data and "findings" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Indago JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if not ("scan_id" in data and "target" in data and "findings" in data):
            raise ParseError("Not a valid Indago export", file_path)

        # Parse host/port from target URL
        target = data.get("target", "")
        target_host, target_port = self._parse_target(target)

        findings = []

        for raw_finding in data.get("findings", []):
            finding = self._parse_finding(raw_finding, target_host, target_port)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_target(self, target: str) -> tuple[str | None, int | None]:
        """Parse host and port from target URL."""
        try:
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            return host, port
        except Exception:
            return None, None

    def _parse_finding(
        self,
        raw: dict[str, Any],
        target_host: str | None,
        target_port: int | None,
    ) -> UnifiedFinding | None:
        """Parse a single Indago finding."""
        severity = Severity.from_string(raw.get("severity", "info"))
        confidence = Confidence.from_string(raw.get("confidence", "tentative"))

        # Build location
        endpoint = raw.get("endpoint", "")
        method = raw.get("method")
        parameter = raw.get("parameter")

        location = FindingLocation(
            url=endpoint,
            method=method,
            parameter=parameter,
            host=target_host,
            port=target_port,
        )

        # Extract CWEs
        cwe_ids = []
        if raw.get("cwe"):
            if isinstance(raw["cwe"], list):
                cwe_ids.extend(raw["cwe"])
            else:
                cwe_ids.append(raw["cwe"])
        cwe_ids = list(set(cwe_ids))

        # CVSS score
        cvss_score = raw.get("cvss")

        # Build evidence from request/response/payload
        evidence_parts = []
        if raw.get("evidence"):
            ev = raw["evidence"]
            if ev.get("request"):
                evidence_parts.append(f"REQUEST:\n{ev['request']}")
            if ev.get("response"):
                evidence_parts.append(f"RESPONSE:\n{ev['response']}")
            if ev.get("payload"):
                evidence_parts.append(f"PAYLOAD:\n{ev['payload']}")
        evidence = "\n\n".join(evidence_parts) if evidence_parts else None

        # Build raw_data including curl_command
        raw_data = dict(raw)

        # Build tags
        tags = list(raw.get("tags", []))

        return UnifiedFinding(
            source_tool="indago",
            source_id=raw.get("id", ""),
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            severity=severity,
            confidence=confidence,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            location=location,
            finding_type=FindingType.DAST,
            evidence=evidence,
            remediation=raw.get("remediation"),
            references=raw.get("references", []),
            tags=tags,
            raw_data=raw_data,
        )
