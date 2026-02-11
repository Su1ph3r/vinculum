"""BypassBurrito export formatter — extracts WAF-blocked findings for bypass testing."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vinculum import __version__
from vinculum.correlation.engine import CorrelationResult
from vinculum.models.finding import UnifiedFinding

# Response codes and keywords indicating WAF blocking
WAF_STATUS_CODES = {"403", "406", "429"}
WAF_KEYWORDS = {"blocked", "waf", "forbidden", "web application firewall", "access denied"}


class BurritoOutputFormatter:
    """
    Format correlation results as BypassBurrito input.

    Extracts WAF-blocked Indago findings and formats them as targets
    for BypassBurrito WAF bypass payload generation.
    """

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def format(self, result: CorrelationResult) -> str:
        """Format correlation result as BypassBurrito-compatible JSON string."""
        data = self._build_output(result)
        if self.pretty:
            return json.dumps(data, indent=2, default=self._json_serializer)
        return json.dumps(data, default=self._json_serializer)

    def write(self, result: CorrelationResult, output_path: Path) -> None:
        """Write BypassBurrito input to a JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(self.format(result))

    def _build_output(self, result: CorrelationResult) -> dict[str, Any]:
        """Build the BypassBurrito export structure."""
        targets: list[dict[str, Any]] = []

        for group in result.groups:
            for finding in group.findings:
                if self._is_waf_blocked(finding):
                    target = self._format_target(finding)
                    if target:
                        targets.append(target)

        metadata: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "vinculum_version": __version__,
            "total_targets": len(targets),
        }
        if result.metadata.get("run_id"):
            metadata["run_id"] = result.metadata["run_id"]

        return {
            "format": "vinculum-burrito-export",
            "metadata": metadata,
            "targets": targets,
        }

    def _is_waf_blocked(self, finding: UnifiedFinding) -> bool:
        """
        Determine if a finding represents a WAF-blocked request.

        Checks:
        - source_tool is "indago"
        - Evidence or response contains 403, WAF headers, or "blocked" indicators
        """
        if finding.source_tool != "indago":
            return False

        # Check evidence text for WAF indicators
        evidence = (finding.evidence or "").lower()
        raw_data = finding.raw_data

        # Check response in evidence for status codes
        for code in WAF_STATUS_CODES:
            if f" {code} " in evidence or f" {code}\n" in evidence or evidence.endswith(f" {code}"):
                return True

        # Check response in raw_data evidence block
        raw_evidence = raw_data.get("evidence", {})
        if isinstance(raw_evidence, dict):
            response = (raw_evidence.get("response", "") or "").lower()
            for code in WAF_STATUS_CODES:
                if f" {code} " in response or f" {code}\n" in response or response.endswith(f" {code}"):
                    return True
            for keyword in WAF_KEYWORDS:
                if keyword in response:
                    return True

        # Check evidence string for WAF keywords
        for keyword in WAF_KEYWORDS:
            if keyword in evidence:
                return True

        # Check tags for WAF-related indicators
        tags_lower = [t.lower() for t in finding.tags]
        if any("waf" in t or "blocked" in t for t in tags_lower):
            return True

        return False

    def _format_target(self, finding: UnifiedFinding) -> dict[str, Any] | None:
        """Format a WAF-blocked finding as a BypassBurrito target."""
        loc = finding.location
        endpoint = loc.url
        if not endpoint:
            return None

        # Extract original payload from evidence
        raw_evidence = finding.raw_data.get("evidence", {})
        original_payload = None
        if isinstance(raw_evidence, dict):
            original_payload = raw_evidence.get("payload")

        # Determine vulnerability type from CWE
        vuln_type = self._vuln_type_from_cwe(finding.cwe_ids)

        return {
            "endpoint": endpoint,
            "method": loc.method or "GET",
            "parameter": loc.parameter,
            "original_payload": original_payload,
            "source_finding_id": finding.source_id,
            "vulnerability_type": vuln_type,
        }

    @staticmethod
    def _vuln_type_from_cwe(cwe_ids: list[str]) -> str:
        """Map CWE IDs to vulnerability type labels."""
        cwe_map = {
            "CWE-79": "XSS",
            "CWE-89": "SQLi",
            "CWE-78": "Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-94": "Code Injection",
            "CWE-917": "Expression Language Injection",
            "CWE-611": "XXE",
        }
        for cwe in cwe_ids:
            if cwe in cwe_map:
                return cwe_map[cwe]
        return "Unknown"

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_burrito(result: CorrelationResult, pretty: bool = True) -> str:
    """Convenience function to format result as BypassBurrito input."""
    formatter = BurritoOutputFormatter(pretty=pretty)
    return formatter.format(result)
