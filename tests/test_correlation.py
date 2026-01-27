"""Tests for correlation engine."""

import pytest

from vinculum.correlation.engine import CorrelationEngine, correlate_findings
from vinculum.correlation.fingerprint import (
    are_similar_findings,
    generate_fingerprint,
    normalize_title,
)
from vinculum.models.enums import FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding


class TestFingerprint:
    """Tests for fingerprint generation."""

    def test_generate_fingerprint_deterministic(self):
        finding = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title="SQL Injection",
            severity=Severity.HIGH,
            location=FindingLocation(url="https://example.com/login"),
        )

        fp1 = generate_fingerprint(finding)
        fp2 = generate_fingerprint(finding)

        assert fp1 == fp2

    def test_different_findings_different_fingerprints(self):
        f1 = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title="SQL Injection",
            severity=Severity.HIGH,
            location=FindingLocation(url="https://example.com/login"),
        )
        f2 = UnifiedFinding(
            source_tool="test",
            source_id="2",
            title="XSS",
            severity=Severity.HIGH,
            location=FindingLocation(url="https://example.com/search"),
        )

        assert generate_fingerprint(f1) != generate_fingerprint(f2)

    def test_same_issue_same_fingerprint(self):
        # Same vulnerability, different tools
        f1 = UnifiedFinding(
            source_tool="burp",
            source_id="burp-1",
            title="SQL Injection vulnerability",
            severity=Severity.HIGH,
            cwe_ids=["CWE-89"],
            location=FindingLocation(url="https://example.com/users"),
        )
        f2 = UnifiedFinding(
            source_tool="zap",
            source_id="zap-1",
            title="SQL Injection vulnerability",  # Same title
            severity=Severity.HIGH,
            cwe_ids=["CWE-89"],  # Same CWE
            location=FindingLocation(url="https://example.com/users"),  # Same location
        )

        assert generate_fingerprint(f1) == generate_fingerprint(f2)

    def test_normalize_title(self):
        assert normalize_title("Potential SQL Injection") == "sql injection"
        assert normalize_title("Detected XSS vulnerability") == "xss vulnerability"
        assert normalize_title("WARNING: CSRF token missing") == "csrf token missing"


class TestSimilarFindings:
    """Tests for similar findings detection."""

    def test_same_cve_is_similar(self):
        f1 = UnifiedFinding(
            source_tool="nessus",
            source_id="1",
            title="Apache Struts RCE",
            cve_ids=["CVE-2017-5638"],
            location=FindingLocation(host="192.168.1.1", port=80),
        )
        f2 = UnifiedFinding(
            source_tool="qualys",
            source_id="2",
            title="Struts 2 Remote Code Execution",
            cve_ids=["CVE-2017-5638"],
            location=FindingLocation(host="192.168.1.1", port=80),
        )

        assert are_similar_findings(f1, f2)

    def test_different_location_not_similar(self):
        f1 = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title="XSS",
            cwe_ids=["CWE-79"],
            location=FindingLocation(url="https://example.com/page1"),
        )
        f2 = UnifiedFinding(
            source_tool="test",
            source_id="2",
            title="XSS",
            cwe_ids=["CWE-79"],
            location=FindingLocation(url="https://example.com/page2"),
        )

        # Same CWE but different location - not automatically similar
        # (would need same normalized location)
        assert not are_similar_findings(f1, f2)


class TestCorrelationEngine:
    """Tests for correlation engine."""

    def test_correlate_empty_list(self):
        engine = CorrelationEngine()
        groups = engine.correlate([])
        assert len(groups) == 0

    def test_correlate_single_finding(self):
        engine = CorrelationEngine()
        finding = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title="Test Finding",
        )
        groups = engine.correlate([finding])

        assert len(groups) == 1
        assert len(groups[0].findings) == 1
        assert groups[0].findings[0].correlation_id is not None

    def test_correlate_duplicates_by_fingerprint(self):
        engine = CorrelationEngine()

        # Same vulnerability, different tools
        findings = [
            UnifiedFinding(
                source_tool="burp",
                source_id="1",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
            UnifiedFinding(
                source_tool="zap",
                source_id="2",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
        ]

        groups = engine.correlate(findings)

        assert len(groups) == 1
        assert len(groups[0].findings) == 2
        assert groups[0].tool_sources == {"burp", "zap"}

    def test_correlate_duplicates_by_cve(self):
        engine = CorrelationEngine()

        findings = [
            UnifiedFinding(
                source_tool="nessus",
                source_id="1",
                title="Apache Struts RCE",
                cve_ids=["CVE-2017-5638"],
                location=FindingLocation(host="192.168.1.1", port=80),
            ),
            UnifiedFinding(
                source_tool="qualys",
                source_id="2",
                title="Struts 2 Remote Code Execution",
                cve_ids=["CVE-2017-5638"],
                location=FindingLocation(host="192.168.1.1", port=80),
            ),
        ]

        groups = engine.correlate(findings)

        assert len(groups) == 1
        assert "CVE-2017-5638" in groups[0].all_cves

    def test_correlate_different_findings(self):
        engine = CorrelationEngine()

        findings = [
            UnifiedFinding(
                source_tool="test",
                source_id="1",
                title="SQL Injection",
                severity=Severity.HIGH,
                location=FindingLocation(url="https://example.com/page1"),
            ),
            UnifiedFinding(
                source_tool="test",
                source_id="2",
                title="XSS",
                severity=Severity.MEDIUM,
                location=FindingLocation(url="https://example.com/page2"),
            ),
        ]

        groups = engine.correlate(findings)

        assert len(groups) == 2

    def test_primary_finding_is_highest_severity(self):
        engine = CorrelationEngine()

        findings = [
            UnifiedFinding(
                source_tool="tool1",
                source_id="1",
                title="SQL Injection",
                severity=Severity.MEDIUM,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
            UnifiedFinding(
                source_tool="tool2",
                source_id="2",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
        ]

        groups = engine.correlate(findings)

        assert groups[0].primary_finding.severity == Severity.HIGH


class TestCorrelationResult:
    """Tests for correlation result statistics."""

    def test_correlation_result_stats(self):
        findings = [
            UnifiedFinding(
                source_tool="burp",
                source_id="1",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
            UnifiedFinding(
                source_tool="zap",
                source_id="2",
                title="SQL Injection",
                severity=Severity.HIGH,
                cwe_ids=["CWE-89"],
                location=FindingLocation(url="https://example.com/login"),
            ),
            UnifiedFinding(
                source_tool="semgrep",
                source_id="3",
                title="Hardcoded Password",
                severity=Severity.MEDIUM,
            ),
        ]

        result = correlate_findings(findings)

        assert result.original_count == 3
        assert result.unique_count == 2
        assert result.duplicate_count == 1
        assert result.dedup_rate == pytest.approx(33.33, rel=0.1)

    def test_multi_tool_findings(self):
        findings = [
            UnifiedFinding(
                source_tool="burp",
                source_id="1",
                title="XSS",
                cwe_ids=["CWE-79"],
                location=FindingLocation(url="https://example.com/search"),
            ),
            UnifiedFinding(
                source_tool="zap",
                source_id="2",
                title="XSS",
                cwe_ids=["CWE-79"],
                location=FindingLocation(url="https://example.com/search"),
            ),
            UnifiedFinding(
                source_tool="semgrep",
                source_id="3",
                title="Something Else",
            ),
        ]

        result = correlate_findings(findings)
        multi_tool = result.multi_tool_findings()

        assert len(multi_tool) == 1
        assert len(multi_tool[0].tool_sources) == 2
