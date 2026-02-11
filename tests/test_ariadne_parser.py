"""Tests for Ariadne parser (closed-loop feedback)."""

import json
from pathlib import Path

import pytest

from vinculum.parsers.ariadne import AriadneParser
from vinculum.parsers.base import ParseError

FIXTURES = Path(__file__).parent / "fixtures"
ARIADNE_SAMPLE = FIXTURES / "ariadne_sample.json"


@pytest.fixture
def parser():
    return AriadneParser()


class TestAriadneParserDetection:
    def test_tool_name(self, parser):
        assert parser.tool_name == "ariadne"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_ariadne_file(self, parser):
        assert parser.supports_file(ARIADNE_SAMPLE) is True

    def test_rejects_non_ariadne_json(self, parser):
        indago_file = FIXTURES / "indago_sample.json"
        assert parser.supports_file(indago_file) is False

    def test_rejects_non_json_extension(self, parser, tmp_path):
        xml_file = tmp_path / "test.xml"
        xml_file.write_text("<root/>")
        assert parser.supports_file(xml_file) is False


class TestAriadneParsing:
    def test_parse_finding_count(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        # 2 vulnerabilities + 1 misconfiguration = 3
        assert len(findings) == 3

    def test_vulnerability_parsing(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)

        assert sql_injection.source_tool == "ariadne"
        assert sql_injection.severity == "critical"
        assert "CVE-2024-1234" in sql_injection.cve_ids
        assert sql_injection.cvss_score == 9.8
        assert sql_injection.location.host == "10.0.1.50"
        assert sql_injection.location.port == 443

    def test_misconfiguration_parsing(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        misconfig = next(f for f in findings if "X-Frame-Options" in f.title)

        assert misconfig.severity == "medium"
        assert misconfig.remediation == "Add X-Frame-Options: DENY header"

    def test_vinculum_metadata_preserved(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)

        assert sql_injection.fingerprint == "fp-abc123"
        assert sql_injection.correlation_id == "corr-001"
        assert "vinculum_metadata" in sql_injection.raw_data
        vm = sql_injection.raw_data["vinculum_metadata"]
        assert set(vm["source_tools"]) == {"indago", "burp"}
        assert vm["finding_count"] == 2

    def test_epss_data_preserved(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)

        assert sql_injection.epss_score == 0.85
        assert sql_injection.epss_percentile == 0.97

    def test_confidence_from_multi_tool(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)
        jwt_finding = next(f for f in findings if "JWT" in f.title)

        # SQL Injection has 2 source_tools → CERTAIN
        assert sql_injection.confidence == "certain"
        # JWT has 1 source_tool → FIRM
        assert jwt_finding.confidence == "firm"

    def test_source_tool_tags(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)

        assert "source:indago" in sql_injection.tags
        assert "source:burp" in sql_injection.tags

    def test_description_parsed(self, parser):
        findings = parser.parse(ARIADNE_SAMPLE)
        sql_injection = next(f for f in findings if "SQL Injection" in f.title)
        assert "user search endpoint" in sql_injection.description


class TestAriadneParserErrors:
    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad_file)

    def test_wrong_format_raises_parse_error(self, parser, tmp_path):
        wrong_file = tmp_path / "wrong.json"
        wrong_file.write_text(json.dumps({"format": "something-else"}))
        with pytest.raises(ParseError):
            parser.parse(wrong_file)

    def test_empty_vulnerabilities_returns_empty(self, parser, tmp_path):
        empty_file = tmp_path / "empty.json"
        empty_file.write_text(json.dumps({
            "format": "vinculum-ariadne-export",
            "format_version": "1.1",
            "vulnerabilities": [],
            "misconfigurations": [],
        }))
        findings = parser.parse(empty_file)
        assert findings == []
