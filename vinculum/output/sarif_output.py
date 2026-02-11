"""SARIF output formatter for CI/CD integration."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vinculum import __version__
from vinculum.correlation.engine import CorrelationResult
from vinculum.models.enums import Severity
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


class SARIFOutputFormatter:
    """
    Format correlation results as SARIF 2.1.0 for CI/CD integration.

    SARIF (Static Analysis Results Interchange Format) is an OASIS standard
    supported by GitHub, GitLab, Azure DevOps, and other CI/CD platforms.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, pretty: bool = True, include_raw: bool = False):
        """
        Initialize the SARIF formatter.

        Args:
            pretty: Whether to pretty-print JSON
            include_raw: Whether to include raw_data in properties
        """
        self.pretty = pretty
        self.include_raw = include_raw

    def format(self, result: CorrelationResult) -> str:
        """Format correlation result as SARIF JSON string."""
        sarif = self._build_sarif(result)
        if self.pretty:
            return json.dumps(sarif, indent=2, default=self._json_serializer)
        return json.dumps(sarif, default=self._json_serializer)

    def write(self, result: CorrelationResult, output_path: Path) -> None:
        """Write correlation result to a SARIF file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(self.format(result))

    def _build_sarif(self, result: CorrelationResult) -> dict[str, Any]:
        """Build the SARIF document structure."""
        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._build_run(result)],
        }

    def _build_run(self, result: CorrelationResult) -> dict[str, Any]:
        """Build a SARIF run object."""
        # Collect all results from primary findings in each group
        results = []
        rules = {}

        for group in result.groups:
            if group.primary_finding:
                sarif_result = self._finding_to_result(group.primary_finding, group)
                results.append(sarif_result)

                # Collect rule definitions
                rule_id = self._get_rule_id(group.primary_finding)
                if rule_id not in rules:
                    rules[rule_id] = self._build_rule(group.primary_finding)

        return {
            "tool": self._build_tool(list(rules.values())),
            "results": results,
            "invocations": [self._build_invocation(result)],
        }

    def _build_tool(self, rules: list[dict]) -> dict[str, Any]:
        """Build SARIF tool descriptor."""
        return {
            "driver": {
                "name": "Vinculum",
                "version": __version__,
                "informationUri": "https://github.com/security-team/vinculum",
                "rules": rules,
            }
        }

    def _build_rule(self, finding: UnifiedFinding) -> dict[str, Any]:
        """Build a SARIF rule definition from a finding."""
        rule = {
            "id": self._get_rule_id(finding),
            "name": finding.title[:100],  # Limit length
            "shortDescription": {"text": finding.title},
        }

        if finding.description:
            rule["fullDescription"] = {"text": finding.description[:2000]}

        # Add help URL from references
        if finding.references:
            rule["helpUri"] = finding.references[0]

        # Add default configuration
        rule["defaultConfiguration"] = {
            "level": self._severity_to_level(finding.severity)
        }

        # Add properties for CWE/CVE
        properties = {}
        if finding.cwe_ids:
            properties["cwe"] = finding.cwe_ids
        if finding.cve_ids:
            properties["cve"] = finding.cve_ids
        if properties:
            rule["properties"] = properties

        return rule

    def _finding_to_result(
        self, finding: UnifiedFinding, group: CorrelationGroup
    ) -> dict[str, Any]:
        """Convert a UnifiedFinding to a SARIF result."""
        result: dict[str, Any] = {
            "ruleId": self._get_rule_id(finding),
            "level": self._severity_to_level(finding.severity),
            "message": {"text": self._build_message(finding)},
            "locations": self._build_locations(finding),
        }

        # Add fingerprints for deduplication
        result["partialFingerprints"] = {
            "vinculum/fingerprint/v1": finding.fingerprint,
            "vinculum/correlationId/v1": finding.correlation_id or "",
        }

        # Add properties with additional context
        properties: dict[str, Any] = {
            "severity": str(finding.severity),
            "confidence": str(finding.confidence),
            "findingType": str(finding.finding_type),
            "sourceTool": finding.source_tool,
            "sourceId": finding.source_id,
        }

        # Add multi-tool detection info
        if len(group.tool_sources) > 1:
            properties["detectedBy"] = list(group.tool_sources)
            properties["multiToolDetection"] = True

        # Add vulnerability identifiers
        if finding.cve_ids:
            properties["cveIds"] = finding.cve_ids
        if finding.cwe_ids:
            properties["cweIds"] = finding.cwe_ids

        # Add CVSS scores
        if finding.cvss_score is not None:
            properties["cvssScore"] = finding.cvss_score
        if finding.cvss3_score is not None:
            properties["cvss3Score"] = finding.cvss3_score

        # Add EPSS data
        if finding.epss_score is not None:
            properties["epssScore"] = finding.epss_score
        if finding.epss_percentile is not None:
            properties["epssPercentile"] = finding.epss_percentile
        if finding.exploit_available is not None:
            properties["exploitAvailable"] = finding.exploit_available

        # Add tags
        if finding.tags:
            properties["tags"] = finding.tags

        # Optionally include raw data
        if self.include_raw and finding.raw_data:
            properties["rawData"] = finding.raw_data

        result["properties"] = properties

        # Add fix suggestions if available
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation[:1000]},
                }
            ]

        return result

    def _build_message(self, finding: UnifiedFinding) -> str:
        """Build the result message text."""
        parts = [finding.title]

        if finding.description:
            # Add truncated description
            desc = finding.description[:500]
            if len(finding.description) > 500:
                desc += "..."
            parts.append(desc)

        if finding.cve_ids:
            parts.append(f"CVEs: {', '.join(finding.cve_ids)}")

        return "\n\n".join(parts)

    def _build_locations(self, finding: UnifiedFinding) -> list[dict[str, Any]]:
        """Build SARIF locations from finding location."""
        locations = []

        loc = finding.location

        # File-based location (SAST)
        if loc.file_path:
            physical_location: dict[str, Any] = {
                "artifactLocation": {"uri": loc.file_path}
            }

            if loc.line_start is not None:
                region: dict[str, Any] = {"startLine": loc.line_start}
                if loc.line_end is not None:
                    region["endLine"] = loc.line_end
                if loc.code_snippet:
                    region["snippet"] = {"text": loc.code_snippet[:500]}
                physical_location["region"] = region

            locations.append({"physicalLocation": physical_location})

        # URL-based location (DAST)
        elif loc.url:
            # SARIF doesn't have native URL support, use logical location
            logical_location: dict[str, Any] = {"name": loc.url}

            if loc.method:
                logical_location["decoratedName"] = f"{loc.method} {loc.url}"

            if loc.parameter:
                logical_location["fullyQualifiedName"] = (
                    f"{loc.url}?{loc.parameter}=..."
                )

            locations.append({"logicalLocations": [logical_location]})

        # Network location
        elif loc.host:
            name = loc.host
            if loc.port:
                name = f"{loc.host}:{loc.port}"
            if loc.service:
                name = f"{loc.service}://{name}"

            locations.append({"logicalLocations": [{"name": name}]})

        # Fallback - always return at least one location
        if not locations:
            locations.append(
                {"logicalLocations": [{"name": finding.source_tool}]}
            )

        return locations

    def _build_invocation(self, result: CorrelationResult) -> dict[str, Any]:
        """Build SARIF invocation metadata."""
        properties: dict[str, Any] = {
            "totalFindings": result.original_count,
            "uniqueIssues": result.unique_count,
            "duplicatesRemoved": result.duplicate_count,
            "deduplicationRate": round(result.dedup_rate, 1),
        }
        if result.metadata.get("run_id"):
            properties["runId"] = result.metadata["run_id"]
        return {
            "executionSuccessful": True,
            "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "toolExecutionNotifications": [],
            "properties": properties,
        }

    def _get_rule_id(self, finding: UnifiedFinding) -> str:
        """Generate a rule ID for a finding."""
        # Use CWE if available, otherwise use a combination of tool and type
        if finding.cwe_ids:
            return finding.cwe_ids[0]
        if finding.cve_ids:
            return finding.cve_ids[0]
        # Create a generic rule ID
        return f"{finding.source_tool}/{finding.finding_type}".upper()

    def _severity_to_level(self, severity: Severity | str) -> str:
        """Map Vinculum severity to SARIF level."""
        if isinstance(severity, str):
            severity = Severity.from_string(severity)

        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_sarif(
    result: CorrelationResult, pretty: bool = True, include_raw: bool = False
) -> str:
    """Convenience function to format result as SARIF."""
    formatter = SARIFOutputFormatter(pretty=pretty, include_raw=include_raw)
    return formatter.format(result)
