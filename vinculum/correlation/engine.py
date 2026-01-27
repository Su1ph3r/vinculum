"""Correlation engine for deduplicating and grouping findings."""

from collections import defaultdict
from uuid import uuid4

from vinculum.correlation.fingerprint import (
    are_similar_findings,
    generate_fingerprint,
)
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


class CorrelationEngine:
    """
    Engine for correlating and deduplicating security findings.

    Uses a layered approach:
    1. Exact match on source_tool + source_id (same finding re-imported)
    2. CVE match on same asset (same vulnerability, different tools)
    3. Fingerprint match (normalized title + location + severity + CWE)
    4. Optional AI semantic match (for findings that don't match above)
    """

    def __init__(self, ai_correlator=None):
        """
        Initialize the correlation engine.

        Args:
            ai_correlator: Optional AI correlator for semantic matching
        """
        self.ai_correlator = ai_correlator
        self._groups: dict[str, CorrelationGroup] = {}
        self._fingerprint_index: dict[str, str] = {}  # fingerprint -> correlation_id
        self._cve_location_index: dict[str, str] = {}  # "cve:location" -> correlation_id
        self._source_id_index: dict[str, str] = {}  # "tool:source_id" -> correlation_id

    def correlate(self, findings: list[UnifiedFinding]) -> list[CorrelationGroup]:
        """
        Correlate a list of findings into groups.

        Args:
            findings: List of findings to correlate

        Returns:
            List of CorrelationGroup objects
        """
        self._reset_indices()

        for finding in findings:
            # Generate fingerprint if not present
            if not finding.fingerprint:
                finding.fingerprint = generate_fingerprint(finding)

            # Try to find existing group
            group_id = self._find_matching_group(finding)

            if group_id:
                # Add to existing group
                self._groups[group_id].add_finding(finding)
            else:
                # Create new group
                group = CorrelationGroup()
                group.add_finding(finding)
                self._groups[group.correlation_id] = group
                self._index_finding(finding, group.correlation_id)

        return list(self._groups.values())

    def _reset_indices(self) -> None:
        """Reset all correlation indices."""
        self._groups = {}
        self._fingerprint_index = {}
        self._cve_location_index = {}
        self._source_id_index = {}

    def _find_matching_group(self, finding: UnifiedFinding) -> str | None:
        """
        Find an existing group that this finding should belong to.

        Uses layered matching strategy.
        """
        # Layer 1: Exact source ID match (re-import detection)
        source_key = f"{finding.source_tool}:{finding.source_id}"
        if source_key in self._source_id_index:
            return self._source_id_index[source_key]

        # Layer 2: CVE + location match
        if finding.cve_ids:
            location_key = finding.location.normalized_key()
            for cve in finding.cve_ids:
                cve_loc_key = f"{cve}:{location_key}"
                if cve_loc_key in self._cve_location_index:
                    return self._cve_location_index[cve_loc_key]

        # Layer 3: Fingerprint match
        if finding.fingerprint in self._fingerprint_index:
            return self._fingerprint_index[finding.fingerprint]

        # Layer 4: Heuristic similarity check
        for group in self._groups.values():
            if group.primary_finding and are_similar_findings(finding, group.primary_finding):
                return group.correlation_id

        # Layer 5: Optional AI correlation
        if self.ai_correlator:
            for group in self._groups.values():
                if group.primary_finding:
                    if self.ai_correlator.are_same_issue(finding, group.primary_finding):
                        return group.correlation_id

        return None

    def _index_finding(self, finding: UnifiedFinding, group_id: str) -> None:
        """Add finding to all relevant indices."""
        # Source ID index
        source_key = f"{finding.source_tool}:{finding.source_id}"
        self._source_id_index[source_key] = group_id

        # Fingerprint index
        if finding.fingerprint:
            self._fingerprint_index[finding.fingerprint] = group_id

        # CVE + location index
        if finding.cve_ids:
            location_key = finding.location.normalized_key()
            for cve in finding.cve_ids:
                cve_loc_key = f"{cve}:{location_key}"
                self._cve_location_index[cve_loc_key] = group_id


class CorrelationResult:
    """Result of correlation operation with statistics."""

    def __init__(self, groups: list[CorrelationGroup], original_count: int):
        self.groups = groups
        self.original_count = original_count

    @property
    def unique_count(self) -> int:
        """Number of unique issues after deduplication."""
        return len(self.groups)

    @property
    def duplicate_count(self) -> int:
        """Number of findings identified as duplicates."""
        return self.original_count - self.unique_count

    @property
    def dedup_rate(self) -> float:
        """Percentage of findings that were duplicates."""
        if self.original_count == 0:
            return 0.0
        return (self.duplicate_count / self.original_count) * 100

    def by_severity(self) -> dict[str, int]:
        """Count groups by max severity."""
        counts: dict[str, int] = defaultdict(int)
        for group in self.groups:
            counts[group.max_severity] += 1
        return dict(counts)

    def by_tool(self) -> dict[str, int]:
        """Count findings by source tool."""
        counts: dict[str, int] = defaultdict(int)
        for group in self.groups:
            for finding in group.findings:
                counts[finding.source_tool] += 1
        return dict(counts)

    def multi_tool_findings(self) -> list[CorrelationGroup]:
        """Return groups detected by multiple tools."""
        return [g for g in self.groups if len(g.tool_sources) > 1]

    def all_findings(self) -> list[UnifiedFinding]:
        """Return all findings from all groups."""
        findings = []
        for group in self.groups:
            findings.extend(group.findings)
        return findings


def correlate_findings(
    findings: list[UnifiedFinding], ai_correlator=None
) -> CorrelationResult:
    """
    Convenience function to correlate findings.

    Args:
        findings: List of findings to correlate
        ai_correlator: Optional AI correlator for semantic matching

    Returns:
        CorrelationResult with groups and statistics
    """
    engine = CorrelationEngine(ai_correlator=ai_correlator)
    groups = engine.correlate(findings)
    return CorrelationResult(groups, len(findings))
