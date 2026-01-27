"""Tests for security tool parsers."""

from pathlib import Path

import pytest

from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.parsers.base import ParseError, ParserRegistry
from vinculum.parsers.burp import BurpParser
from vinculum.parsers.nessus import NessusParser
from vinculum.parsers.nuclei import NucleiParser
from vinculum.parsers.semgrep import SemgrepParser
from vinculum.parsers.trivy import TrivyParser
from vinculum.parsers.zap import ZAPParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestBurpParser:
    """Tests for Burp Suite XML parser."""

    @pytest.fixture
    def parser(self):
        return BurpParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "burp_sample.xml"

    def test_tool_name(self, parser):
        assert parser.tool_name == "burp"

    def test_supported_extensions(self, parser):
        assert ".xml" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_parse_xss_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross-site scripting" in f.title.lower())

        assert xss.source_tool == "burp"
        assert xss.severity == Severity.HIGH
        assert xss.confidence == Confidence.CERTAIN
        assert "CWE-79" in xss.cwe_ids
        assert xss.finding_type == FindingType.DAST
        assert xss.location.url is not None
        assert "example.com" in xss.location.url

    def test_parse_sql_injection(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "sql injection" in f.title.lower())

        assert sqli.severity == Severity.HIGH
        assert "CWE-89" in sqli.cwe_ids

    def test_parse_info_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        info = next(f for f in findings if "tls certificate" in f.title.lower())

        assert info.severity == Severity.INFO

    def test_parse_includes_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross-site scripting" in f.title.lower())

        assert xss.evidence is not None
        assert "REQUEST:" in xss.evidence


class TestNessusParser:
    """Tests for Nessus XML parser."""

    @pytest.fixture
    def parser(self):
        return NessusParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nessus_sample.nessus"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nessus"

    def test_supported_extensions(self, parser):
        assert ".nessus" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # Should have 4 findings (including info)
        assert len(findings) == 4

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        struts = next(f for f in findings if "struts" in f.title.lower())

        assert struts.source_tool == "nessus"
        assert struts.severity == Severity.CRITICAL
        assert "CVE-2017-5638" in struts.cve_ids
        assert struts.finding_type == FindingType.NETWORK
        assert struts.location.host == "192.168.1.100"
        assert struts.location.port == 80
        assert struts.exploit_available is True

    def test_parse_cvss_scores(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssl = next(f for f in findings if "ssl" in f.title.lower())

        assert ssl.cvss_score == 6.4
        assert ssl.cvss3_score == 7.4
        assert ssl.cvss_vector is not None
        assert ssl.cvss3_vector is not None

    def test_parse_cwe(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssh = next(f for f in findings if "ssh" in f.title.lower())

        assert "CWE-310" in ssh.cwe_ids

    def test_parse_includes_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssl = next(f for f in findings if "ssl" in f.title.lower())

        assert ssl.remediation is not None
        assert "certificate" in ssl.remediation.lower()


class TestSemgrepParser:
    """Tests for Semgrep JSON parser."""

    @pytest.fixture
    def parser(self):
        return SemgrepParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "semgrep_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "semgrep"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_parse_command_injection(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cmd_inj = next(f for f in findings if "subprocess" in f.title.lower())

        assert cmd_inj.source_tool == "semgrep"
        assert cmd_inj.severity == Severity.HIGH  # ERROR maps to HIGH
        assert cmd_inj.confidence == Confidence.CERTAIN  # HIGH confidence
        assert "CWE-78" in cmd_inj.cwe_ids
        assert cmd_inj.finding_type == FindingType.SAST
        assert cmd_inj.location.file_path == "app/utils/shell.py"
        assert cmd_inj.location.line_start == 45

    def test_parse_hardcoded_password(self, parser, sample_file):
        findings = parser.parse(sample_file)
        passwd = next(f for f in findings if "password" in f.title.lower())

        assert passwd.severity == Severity.MEDIUM  # WARNING maps to MEDIUM
        assert "CWE-798" in passwd.cwe_ids

    def test_parse_includes_code_snippet(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cmd_inj = next(f for f in findings if "subprocess" in f.title.lower())

        assert cmd_inj.location.code_snippet is not None
        assert "subprocess" in cmd_inj.location.code_snippet

    def test_parse_includes_references(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cmd_inj = next(f for f in findings if "subprocess" in f.title.lower())

        assert len(cmd_inj.references) > 0

    def test_parse_includes_fix_suggestion(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "xss" in f.title.lower())

        assert xss.remediation is not None
        assert "fix" in xss.remediation.lower()


class TestParserRegistry:
    """Tests for parser registry."""

    def test_register_and_get_parser(self):
        ParserRegistry.clear()
        parser = BurpParser()
        ParserRegistry.register(parser)

        assert parser in ParserRegistry.get_all_parsers()

    def test_get_parser_for_file(self):
        ParserRegistry.clear()
        ParserRegistry.register(BurpParser())
        ParserRegistry.register(NessusParser())
        ParserRegistry.register(SemgrepParser())

        burp_file = FIXTURES_DIR / "burp_sample.xml"
        nessus_file = FIXTURES_DIR / "nessus_sample.nessus"
        semgrep_file = FIXTURES_DIR / "semgrep_sample.json"

        assert ParserRegistry.get_parser_for_file(burp_file).tool_name == "burp"
        assert ParserRegistry.get_parser_for_file(nessus_file).tool_name == "nessus"
        assert ParserRegistry.get_parser_for_file(semgrep_file).tool_name == "semgrep"

    def test_no_parser_for_unknown_file(self):
        ParserRegistry.clear()
        ParserRegistry.register(BurpParser())

        unknown_file = Path("/tmp/unknown.xyz")
        assert ParserRegistry.get_parser_for_file(unknown_file) is None


class TestParseErrors:
    """Tests for parser error handling."""

    def test_burp_invalid_xml(self, tmp_path):
        parser = BurpParser()
        bad_file = tmp_path / "bad.xml"
        bad_file.write_text("this is not xml")

        with pytest.raises(ParseError):
            parser.parse(bad_file)

    def test_nessus_invalid_xml(self, tmp_path):
        parser = NessusParser()
        bad_file = tmp_path / "bad.nessus"
        bad_file.write_text("this is not xml")

        with pytest.raises(ParseError):
            parser.parse(bad_file)

    def test_semgrep_invalid_json(self, tmp_path):
        parser = SemgrepParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestNucleiParser:
    """Tests for Nuclei JSONL parser."""

    @pytest.fixture
    def parser(self):
        return NucleiParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nuclei_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nuclei"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions
        assert ".jsonl" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "log4j" in f.title.lower())

        assert log4j.source_tool == "nuclei"
        assert log4j.severity == Severity.CRITICAL
        assert "CVE-2021-44228" in log4j.cve_ids
        assert log4j.finding_type == FindingType.DAST

    def test_parse_xss_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross-site scripting" in f.title.lower())

        assert xss.severity == Severity.MEDIUM
        assert "CWE-79" in xss.cwe_ids

    def test_parse_info_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssl = next(f for f in findings if "ssl" in f.title.lower() or "certificate" in f.title.lower())

        assert ssl.severity == Severity.INFO

    def test_nuclei_invalid_json_skips_bad_lines(self, tmp_path):
        """Nuclei parser skips invalid JSON lines instead of raising errors."""
        parser = NucleiParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        # Nuclei parser skips invalid lines gracefully
        findings = parser.parse(bad_file)
        assert len(findings) == 0


class TestTrivyParser:
    """Tests for Trivy JSON parser."""

    @pytest.fixture
    def parser(self):
        return TrivyParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "trivy_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "trivy"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 3 vulnerabilities + 1 misconfiguration
        assert len(findings) == 4

    def test_parse_critical_vulnerability(self, parser, sample_file):
        findings = parser.parse(sample_file)
        critical = next(f for f in findings if "requests" in f.raw_data.get("package", "").lower())

        assert critical.source_tool == "trivy"
        assert critical.severity == Severity.CRITICAL
        assert critical.finding_type == FindingType.DEPENDENCY

    def test_parse_container_vulnerability(self, parser, sample_file):
        findings = parser.parse(sample_file)
        container = next(f for f in findings if "libnghttp2" in f.raw_data.get("package", "").lower())

        assert container.severity == Severity.HIGH
        assert container.finding_type == FindingType.CONTAINER
        assert "CVE-2023-44487" in container.cve_ids

    def test_parse_cvss_scores(self, parser, sample_file):
        findings = parser.parse(sample_file)
        container = next(f for f in findings if "libnghttp2" in f.raw_data.get("package", "").lower())

        assert container.cvss3_score == 7.5

    def test_parse_misconfiguration(self, parser, sample_file):
        findings = parser.parse(sample_file)
        misconfig = next(f for f in findings if "root user" in f.title.lower())

        assert misconfig.severity == Severity.HIGH
        assert misconfig.finding_type == FindingType.SAST  # Misconfigs are SAST-like

    def test_parse_includes_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        vuln = next(f for f in findings if f.remediation and "upgrade" in f.remediation.lower())

        assert "1.43.0-1+deb11u1" in vuln.remediation

    def test_trivy_invalid_json(self, tmp_path):
        parser = TrivyParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestZAPParser:
    """Tests for OWASP ZAP XML parser."""

    @pytest.fixture
    def parser(self):
        return ZAPParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "zap_sample.xml"

    def test_tool_name(self, parser):
        assert parser.tool_name == "zap"

    def test_supported_extensions(self, parser):
        assert ".xml" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_parse_high_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross site scripting" in f.title.lower())

        assert xss.source_tool == "zap"
        assert xss.severity == Severity.HIGH
        assert xss.confidence == Confidence.CERTAIN
        assert "CWE-79" in xss.cwe_ids
        assert xss.finding_type == FindingType.DAST

    def test_parse_medium_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xframe = next(f for f in findings if "x-frame-options" in f.title.lower())

        assert xframe.severity == Severity.MEDIUM
        assert xframe.confidence == Confidence.FIRM

    def test_parse_low_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        leak = next(f for f in findings if "version" in f.title.lower())

        assert leak.severity == Severity.LOW

    def test_parse_includes_url(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross site scripting" in f.title.lower())

        assert xss.location.url is not None
        assert "testapp.example.com" in xss.location.url

    def test_parse_includes_parameter(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross site scripting" in f.title.lower())

        assert xss.location.parameter == "q"

    def test_parse_includes_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "cross site scripting" in f.title.lower())

        assert xss.evidence is not None
        assert "script" in xss.evidence.lower()

    def test_zap_invalid_xml(self, tmp_path):
        parser = ZAPParser()
        bad_file = tmp_path / "bad.xml"
        bad_file.write_text("this is not xml")

        with pytest.raises(ParseError):
            parser.parse(bad_file)
