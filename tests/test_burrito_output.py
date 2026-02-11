"""Tests for BypassBurrito export formatter."""

import json

import pytest

from vinculum.correlation.engine import CorrelationResult, correlate_findings
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import CorrelationGroup, FindingLocation, UnifiedFinding
from vinculum.output.burrito_output import BurritoOutputFormatter


def _make_finding(**overrides) -> UnifiedFinding:
    defaults = {
        "source_tool": "indago",
        "source_id": "ind-001",
        "title": "SQL Injection",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.CERTAIN,
        "finding_type": FindingType.DAST,
        "cwe_ids": ["CWE-89"],
        "location": FindingLocation(
            url="https://api.example.com/search",
            method="GET",
            parameter="q",
            host="api.example.com",
            port=443,
        ),
    }
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


def _waf_blocked_finding(**overrides) -> UnifiedFinding:
    """Create an Indago finding that looks WAF-blocked."""
    defaults = {
        "source_tool": "indago",
        "source_id": "ind-waf-001",
        "title": "SQL Injection (WAF Blocked)",
        "severity": Severity.HIGH,
        "finding_type": FindingType.DAST,
        "cwe_ids": ["CWE-89"],
        "evidence": "REQUEST:\nGET /search?q=test\nRESPONSE:\nHTTP/1.1 403 Forbidden\nX-WAF: blocked",
        "location": FindingLocation(
            url="https://api.example.com/search",
            method="GET",
            parameter="q",
            host="api.example.com",
            port=443,
        ),
        "raw_data": {
            "evidence": {
                "request": "GET /search?q=test",
                "response": "HTTP/1.1 403 Forbidden\nX-WAF: blocked",
                "payload": "' OR 1=1--",
            }
        },
    }
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


@pytest.fixture
def formatter():
    return BurritoOutputFormatter(pretty=True)


class TestBurritoOutputFormat:
    def test_output_has_format_key(self, formatter):
        result = correlate_findings([_waf_blocked_finding()])
        data = json.loads(formatter.format(result))
        assert data["format"] == "vinculum-burrito-export"

    def test_output_has_metadata(self, formatter):
        result = correlate_findings([_waf_blocked_finding()])
        data = json.loads(formatter.format(result))
        assert "generated_at" in data["metadata"]
        assert "vinculum_version" in data["metadata"]

    def test_run_id_in_metadata(self, formatter):
        result = correlate_findings(
            [_waf_blocked_finding()], metadata={"run_id": "test-run"}
        )
        data = json.loads(formatter.format(result))
        assert data["metadata"]["run_id"] == "test-run"

    def test_total_targets_count(self, formatter):
        result = correlate_findings([_waf_blocked_finding()])
        data = json.loads(formatter.format(result))
        assert data["metadata"]["total_targets"] == 1


class TestWAFBlockedDetection:
    def test_403_in_evidence_detected(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert len(data["targets"]) == 1

    def test_blocked_keyword_in_response(self, formatter):
        f = _make_finding(
            evidence="RESPONSE:\nHTTP/1.1 200 OK\nblocked by WAF",
            raw_data={"evidence": {"response": "blocked by WAF"}},
        )
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert len(data["targets"]) == 1

    def test_waf_tag_detected(self, formatter):
        f = _make_finding(tags=["waf-blocked", "injection"])
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert len(data["targets"]) == 1

    def test_non_indago_findings_excluded(self, formatter):
        f = _make_finding(
            source_tool="burp",
            evidence="HTTP/1.1 403 Forbidden",
        )
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert len(data["targets"]) == 0

    def test_non_waf_indago_finding_excluded(self, formatter):
        f = _make_finding(
            evidence="HTTP/1.1 200 OK\nSuccess",
            raw_data={"evidence": {"response": "HTTP/1.1 200 OK"}},
        )
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert len(data["targets"]) == 0


class TestTargetFormatting:
    def test_target_has_required_fields(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        target = data["targets"][0]

        assert "endpoint" in target
        assert "method" in target
        assert "parameter" in target
        assert "source_finding_id" in target
        assert "vulnerability_type" in target

    def test_endpoint_from_location(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        target = data["targets"][0]
        assert target["endpoint"] == "https://api.example.com/search"

    def test_method_from_location(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["method"] == "GET"

    def test_parameter_from_location(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["parameter"] == "q"

    def test_original_payload_extracted(self, formatter):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["original_payload"] == "' OR 1=1--"

    def test_vuln_type_from_cwe_sqli(self, formatter):
        f = _waf_blocked_finding(cwe_ids=["CWE-89"])
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["vulnerability_type"] == "SQLi"

    def test_vuln_type_from_cwe_xss(self, formatter):
        f = _waf_blocked_finding(cwe_ids=["CWE-79"])
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["vulnerability_type"] == "XSS"

    def test_vuln_type_unknown_cwe(self, formatter):
        f = _waf_blocked_finding(cwe_ids=["CWE-999"])
        result = correlate_findings([f])
        data = json.loads(formatter.format(result))
        assert data["targets"][0]["vulnerability_type"] == "Unknown"


class TestBurritoWrite:
    def test_write_creates_file(self, formatter, tmp_path):
        f = _waf_blocked_finding()
        result = correlate_findings([f])
        out = tmp_path / "burrito.json"
        formatter.write(result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["format"] == "vinculum-burrito-export"
