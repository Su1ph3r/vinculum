"""Parser for BypassBurrito WAF bypass testing JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.bypassburrito")

# WAF confidence to Confidence enum mapping
WAF_CONFIDENCE = {
    "high": Confidence.CERTAIN,
    "medium": Confidence.FIRM,
    "low": Confidence.TENTATIVE,
}


class BypassBurritoParser(BaseParser):
    """
    Parser for BypassBurrito WAF bypass testing JSON export format.

    BypassBurrito tests WAF rules by mutating payloads and attempting
    bypasses. Results include the original payload, WAF detection info,
    and any successful bypass payloads found.
    """

    @property
    def tool_name(self) -> str:
        return "bypassburrito"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a BypassBurrito export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return self._is_bypassburrito(data)
        except Exception:
            return False

    def _is_bypassburrito(self, data: Any) -> bool:
        """Check if data matches BypassBurrito format."""
        if isinstance(data, list):
            if len(data) > 0:
                return self._is_bypassburrito_item(data[0])
            return False
        return self._is_bypassburrito_item(data)

    def _is_bypassburrito_item(self, item: Any) -> bool:
        """Check if a single item matches BypassBurrito format."""
        if not isinstance(item, dict):
            return False
        return "original_payload" in item and (
            "waf_detected" in item or "successful_bypass" in item
        )

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse BypassBurrito JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if not self._is_bypassburrito(data):
            raise ParseError("Not a valid BypassBurrito export", file_path)

        # Normalize to list
        items = data if isinstance(data, list) else [data]

        findings = []
        for item in items:
            finding = self._parse_result(item)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_result(self, raw: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single BypassBurrito result."""
        bypass = raw.get("successful_bypass", {})
        waf = raw.get("waf_detected", {})
        success = bool(bypass and bypass.get("found", False))

        # Title from bypass payload type
        if success:
            payload_type = bypass.get("payload", {}).get("type", "unknown")
            title = f"WAF Bypass: {payload_type}"
            severity = Severity.HIGH
        else:
            title = "WAF Bypass: No Bypass Found"
            severity = Severity.INFO

        # Confidence from WAF detection confidence
        waf_confidence = waf.get("confidence", "low")
        confidence = WAF_CONFIDENCE.get(waf_confidence, Confidence.TENTATIVE)

        # Build tags
        tags = []
        if waf.get("type"):
            tags.append(f"waf:{waf['type']}")
        if waf.get("vendor"):
            tags.append(f"waf-vendor:{waf['vendor']}")
        for mutation in raw.get("mutations_applied", []):
            tags.append(f"mutation:{mutation}")

        # Build raw_data with curl_command and minimized_payload
        raw_data = dict(raw)

        # Build location from endpoint if available
        endpoint = raw.get("endpoint", "")
        method = raw.get("method")
        parameter = raw.get("parameter")

        location = FindingLocation(
            url=endpoint or None,
            method=method,
            parameter=parameter,
        )

        # Build evidence
        evidence_parts = []
        if raw.get("original_payload"):
            evidence_parts.append(f"Original Payload: {raw['original_payload']}")
        if success and bypass.get("payload", {}).get("value"):
            evidence_parts.append(f"Bypass Payload: {bypass['payload']['value']}")
        if bypass.get("minimized_payload"):
            evidence_parts.append(f"Minimized: {bypass['minimized_payload']}")
        evidence = "\n".join(evidence_parts) if evidence_parts else None

        # Build description
        desc_parts = []
        if waf.get("type"):
            desc_parts.append(f"WAF: {waf['type']}")
        if waf.get("vendor"):
            desc_parts.append(f"({waf['vendor']})")
        if success:
            desc_parts.append("- bypass found")
        else:
            desc_parts.append("- no bypass found")
        description = " ".join(desc_parts)

        return UnifiedFinding(
            source_tool="bypassburrito",
            source_id=raw.get("id", raw.get("test_id", "")),
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            location=location,
            finding_type=FindingType.DAST,
            evidence=evidence,
            tags=tags,
            raw_data=raw_data,
        )
