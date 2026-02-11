"""JSON output formatter for correlation results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vinculum import __version__
from vinculum.correlation.engine import CorrelationResult
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


class JSONOutputFormatter:
    """Format correlation results as JSON."""

    def __init__(self, pretty: bool = True, include_raw: bool = False):
        """
        Initialize the formatter.

        Args:
            pretty: Whether to pretty-print JSON
            include_raw: Whether to include raw_data from findings
        """
        self.pretty = pretty
        self.include_raw = include_raw

    def format(self, result: CorrelationResult) -> str:
        """Format correlation result as JSON string."""
        data = self._build_output(result)
        if self.pretty:
            return json.dumps(data, indent=2, default=self._json_serializer)
        return json.dumps(data, default=self._json_serializer)

    def write(self, result: CorrelationResult, output_path: Path) -> None:
        """Write correlation result to a JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(self.format(result))

    def _build_output(self, result: CorrelationResult) -> dict[str, Any]:
        """Build the output dictionary."""
        metadata: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "vinculum_version": __version__,
        }
        if result.metadata.get("run_id"):
            metadata["run_id"] = result.metadata["run_id"]
        return {
            "metadata": metadata,
            "summary": {
                "total_findings": result.original_count,
                "unique_issues": result.unique_count,
                "duplicates_removed": result.duplicate_count,
                "deduplication_rate": round(result.dedup_rate, 1),
                "by_severity": result.by_severity(),
                "by_tool": result.by_tool(),
                "multi_tool_detections": len(result.multi_tool_findings()),
            },
            "groups": [self._format_group(g) for g in result.groups],
        }

    def _format_group(self, group: CorrelationGroup) -> dict[str, Any]:
        """Format a correlation group."""
        return {
            "correlation_id": group.correlation_id,
            "max_severity": group.max_severity,
            "cves": list(group.all_cves),
            "detected_by": list(group.tool_sources),
            "finding_count": len(group.findings),
            "primary": self._format_finding(group.primary_finding) if group.primary_finding else None,
            "findings": [self._format_finding(f) for f in group.findings],
        }

    def _format_finding(self, finding: UnifiedFinding) -> dict[str, Any]:
        """Format a single finding."""
        data = {
            "id": finding.id,
            "source_tool": finding.source_tool,
            "source_id": finding.source_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "finding_type": finding.finding_type,
            "cve_ids": finding.cve_ids,
            "cwe_ids": finding.cwe_ids,
            "cvss_score": finding.cvss_score,
            "cvss3_score": finding.cvss3_score,
            "location": {
                "url": finding.location.url,
                "host": finding.location.host,
                "port": finding.location.port,
                "file_path": finding.location.file_path,
                "line_start": finding.location.line_start,
                "line_end": finding.location.line_end,
            },
            "fingerprint": finding.fingerprint,
            "correlation_id": finding.correlation_id,
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "epss_score": finding.epss_score,
            "epss_percentile": finding.epss_percentile,
            "exploit_available": finding.exploit_available,
            "remediation": finding.remediation,
            "references": finding.references,
            "tags": finding.tags,
        }

        # Optionally include evidence (can be large)
        if finding.evidence:
            data["evidence"] = finding.evidence[:5000]  # Truncate large evidence

        # Optionally include raw data
        if self.include_raw:
            data["raw_data"] = finding.raw_data

        # Remove None values for cleaner output
        return {k: v for k, v in data.items() if v is not None}

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_json(result: CorrelationResult, pretty: bool = True, include_raw: bool = False) -> str:
    """Convenience function to format result as JSON."""
    formatter = JSONOutputFormatter(pretty=pretty, include_raw=include_raw)
    return formatter.format(result)
