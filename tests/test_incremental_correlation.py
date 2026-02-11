"""Tests for incremental ingestion and selective re-correlation (--baseline)."""

import json

import pytest

from vinculum.correlation.engine import (
    CorrelationEngine,
    CorrelationResult,
    correlate_findings,
)
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import CorrelationGroup, FindingLocation, UnifiedFinding


def _make_finding(**overrides) -> UnifiedFinding:
    defaults = {
        "source_tool": "test",
        "source_id": "t-001",
        "title": "Test Finding",
        "severity": Severity.HIGH,
        "confidence": Confidence.FIRM,
        "finding_type": FindingType.DAST,
        "location": FindingLocation(host="10.0.0.1", port=443),
    }
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


class TestCorrelationResultSerialization:
    def test_to_dict_basic(self):
        findings = [_make_finding(source_id="a"), _make_finding(source_id="b", title="Other")]
        result = correlate_findings(findings, metadata={"run_id": "test-001"})
        data = result.to_dict()

        assert data["metadata"]["run_id"] == "test-001"
        assert data["original_count"] == 2
        assert isinstance(data["groups"], list)
        assert len(data["groups"]) >= 1

    def test_to_dict_groups_have_findings(self):
        findings = [_make_finding()]
        result = correlate_findings(findings)
        data = result.to_dict()

        group = data["groups"][0]
        assert "correlation_id" in group
        assert "findings" in group
        assert len(group["findings"]) == 1

    def test_from_dict_roundtrip(self):
        findings = [
            _make_finding(source_id="a", title="SQLi", cve_ids=["CVE-2024-1234"]),
            _make_finding(source_id="b", title="XSS"),
        ]
        original = correlate_findings(findings, metadata={"run_id": "rt-001"})
        data = original.to_dict()

        restored = CorrelationResult.from_dict(data)

        assert restored.metadata["run_id"] == "rt-001"
        assert restored.original_count == original.original_count
        assert len(restored.groups) == len(original.groups)

    def test_from_dict_preserves_findings(self):
        findings = [_make_finding(source_id="a", title="SQLi", severity=Severity.CRITICAL)]
        original = correlate_findings(findings)
        data = original.to_dict()

        restored = CorrelationResult.from_dict(data)

        restored_finding = restored.groups[0].findings[0]
        assert restored_finding.title == "SQLi"
        assert restored_finding.severity == "critical"

    def test_from_dict_json_roundtrip(self):
        """Full JSON serialization roundtrip."""
        findings = [_make_finding(source_id="a")]
        original = correlate_findings(findings, metadata={"run_id": "json-rt"})

        json_str = json.dumps(original.to_dict(), default=str)
        data = json.loads(json_str)
        restored = CorrelationResult.from_dict(data)

        assert restored.metadata["run_id"] == "json-rt"
        assert len(restored.groups) == len(original.groups)

    def test_from_dict_provenance_chain_preserved(self):
        findings = [_make_finding(source_id="a")]
        result = correlate_findings(findings)
        result.groups[0].provenance_chain = [{"tool": "indago", "role": "tested"}]
        data = result.to_dict()

        restored = CorrelationResult.from_dict(data)
        assert restored.groups[0].provenance_chain == [{"tool": "indago", "role": "tested"}]


class TestIncrementalCorrelate:
    def test_new_finding_added_to_existing_group(self):
        # Baseline: one finding with CVE
        baseline_findings = [
            _make_finding(
                source_tool="nuclei", source_id="n-1", title="Log4j",
                cve_ids=["CVE-2021-44228"],
                location=FindingLocation(host="10.0.0.1", port=443),
            ),
        ]
        baseline = correlate_findings(baseline_findings)

        # New finding with same CVE on same location
        new_findings = [
            _make_finding(
                source_tool="burp", source_id="b-1", title="Log4j RCE",
                cve_ids=["CVE-2021-44228"],
                location=FindingLocation(host="10.0.0.1", port=443),
            ),
        ]

        engine = CorrelationEngine()
        groups = engine.incremental_correlate(new_findings, baseline)

        # Should still be 1 group, but with 2 findings
        assert len(groups) == 1
        assert len(groups[0].findings) == 2

    def test_new_finding_creates_new_group(self):
        baseline_findings = [
            _make_finding(source_id="a", title="SQLi"),
        ]
        baseline = correlate_findings(baseline_findings)

        new_findings = [
            _make_finding(source_id="b", title="Completely Different Issue",
                          severity=Severity.LOW),
        ]

        engine = CorrelationEngine()
        groups = engine.incremental_correlate(new_findings, baseline)

        assert len(groups) == 2

    def test_baseline_findings_not_reprocessed(self):
        baseline_findings = [
            _make_finding(source_id="a", title="Finding A"),
            _make_finding(source_id="b", title="Finding B"),
        ]
        baseline = correlate_findings(baseline_findings)
        baseline_group_count = len(baseline.groups)

        # No new findings
        engine = CorrelationEngine()
        groups = engine.incremental_correlate([], baseline)

        assert len(groups) == baseline_group_count

    def test_incremental_with_fingerprint_match(self):
        f1 = _make_finding(source_tool="nuclei", source_id="n-1", title="XSS",
                           location=FindingLocation(host="10.0.0.1", port=80))
        baseline = correlate_findings([f1])

        # Same fingerprint (same title+location+severity+CWE)
        f2 = _make_finding(source_tool="zap", source_id="z-1", title="XSS",
                           location=FindingLocation(host="10.0.0.1", port=80))

        engine = CorrelationEngine()
        groups = engine.incremental_correlate([f2], baseline)

        assert len(groups) == 1
        assert len(groups[0].findings) == 2

    def test_incremental_preserves_baseline_metadata(self):
        baseline_findings = [_make_finding(source_id="a")]
        baseline = correlate_findings(baseline_findings, metadata={"run_id": "base-001"})

        # Metadata is on the result level, not groups
        assert baseline.metadata["run_id"] == "base-001"

    def test_incremental_result_counts(self):
        baseline_findings = [_make_finding(source_id="a")]
        baseline = correlate_findings(baseline_findings)

        new_findings = [_make_finding(source_id="b", title="New Issue")]

        engine = CorrelationEngine()
        groups = engine.incremental_correlate(new_findings, baseline)
        baseline_total = sum(len(g.findings) for g in baseline.groups)
        result = CorrelationResult(groups, baseline_total + len(new_findings))

        assert result.original_count == 2
        assert result.unique_count == 2

    def test_serialized_baseline_incremental(self):
        """Test incremental correlation using a serialized/deserialized baseline."""
        baseline_findings = [
            _make_finding(source_tool="nuclei", source_id="n-1", title="SQLi",
                          cve_ids=["CVE-2024-1234"],
                          location=FindingLocation(host="10.0.0.1", port=443)),
        ]
        original_baseline = correlate_findings(baseline_findings, metadata={"run_id": "base"})

        # Serialize and deserialize
        data = original_baseline.to_dict()
        json_str = json.dumps(data, default=str)
        restored_baseline = CorrelationResult.from_dict(json.loads(json_str))

        # New finding matching by CVE
        new_findings = [
            _make_finding(source_tool="burp", source_id="b-1", title="SQL Injection",
                          cve_ids=["CVE-2024-1234"],
                          location=FindingLocation(host="10.0.0.1", port=443)),
        ]

        engine = CorrelationEngine()
        groups = engine.incremental_correlate(new_findings, restored_baseline)

        assert len(groups) == 1
        assert len(groups[0].findings) == 2
