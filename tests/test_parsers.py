"""Tests for security tool parsers."""

from pathlib import Path

import pytest

from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.parsers.base import ParseError, ParserRegistry
from vinculum.parsers.burp import BurpParser
from vinculum.parsers.bypassburrito import BypassBurritoParser
from vinculum.parsers.cepheus import CepheusParser
from vinculum.parsers.indago import IndagoParser
from vinculum.parsers.mobilicustos import MobilicustosParser
from vinculum.parsers.nessus import NessusParser
from vinculum.parsers.nubicustos import NubicustosParser
from vinculum.parsers.nuclei import NucleiParser
from vinculum.parsers.reticustos import ReticustosParser
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


class TestReticustosParser:
    """Tests for Reticustos JSON parser."""

    @pytest.fixture
    def parser(self):
        return ReticustosParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "reticustos_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "reticustos"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_reticustos_json(self, parser, tmp_path):
        """Should not match generic JSON files."""
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 6 scanner findings (7 minus 1 false_positive) + 3 SSL findings
        # SSL: expired cert, weak protocols, poodle
        assert len(findings) == 9

    def test_parse_skips_false_positive(self, parser, sample_file):
        findings = parser.parse(sample_file)
        titles = [f.title for f in findings]
        assert "WordPress Login Page Exposed" not in titles

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "Log4j" in f.title)

        assert log4j.source_tool == "reticustos:nuclei"
        assert log4j.severity == Severity.CRITICAL
        assert "CVE-2021-44228" in log4j.cve_ids
        assert "CVE-2021-45046" in log4j.cve_ids
        assert "CWE-917" in log4j.cwe_ids
        assert log4j.cvss_score == 10.0
        assert log4j.finding_type == FindingType.DAST
        assert log4j.location.host == "192.168.1.10"
        assert log4j.location.port == 443

    def test_parse_network_finding_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        nmap_finding = next(f for f in findings if "MySQL" in f.title)

        assert nmap_finding.source_tool == "reticustos:nmap"
        assert nmap_finding.finding_type == FindingType.NETWORK
        assert nmap_finding.severity == Severity.HIGH

    def test_parse_dast_finding_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        nikto_finding = next(f for f in findings if "X-Frame-Options" in f.title)

        assert nikto_finding.source_tool == "reticustos:nikto"
        assert nikto_finding.finding_type == FindingType.DAST

    def test_parse_mitre_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "Log4j" in f.title)

        assert "mitre:tactic:Initial Access" in log4j.tags
        assert "mitre:tactic:Execution" in log4j.tags
        assert "mitre:technique:T1190" in log4j.tags
        assert "mitre:technique:T1059" in log4j.tags

    def test_parse_ssl_expired_cert(self, parser, sample_file):
        findings = parser.parse(sample_file)
        expired = next(f for f in findings if "Certificate Expired" in f.title)

        assert expired.source_tool == "reticustos:testssl"
        assert expired.severity == Severity.HIGH
        assert "CWE-295" in expired.cwe_ids
        assert expired.finding_type == FindingType.OTHER

    def test_parse_ssl_weak_protocols(self, parser, sample_file):
        findings = parser.parse(sample_file)
        weak = next(f for f in findings if "Weak TLS" in f.title)

        assert weak.severity == Severity.MEDIUM
        assert "TLSv1.0" in weak.description
        assert "TLSv1.1" in weak.description

    def test_parse_ssl_poodle(self, parser, sample_file):
        findings = parser.parse(sample_file)
        poodle = next(f for f in findings if "POODLE" in f.title)

        assert poodle.severity == Severity.MEDIUM
        assert "CVE-2014-3566" in poodle.cve_ids

    def test_parse_includes_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "Log4j" in f.title)

        assert log4j.evidence is not None
        assert "JNDI" in log4j.evidence

    def test_parse_includes_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "Log4j" in f.title)

        assert log4j.remediation is not None
        assert "2.17.1" in log4j.remediation

    def test_reticustos_invalid_json(self, tmp_path):
        parser = ReticustosParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


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


class TestNubicustosParser:
    """Tests for Nubicustos cloud security scanner parser."""

    @pytest.fixture
    def parser(self):
        return NubicustosParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nubicustos_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nubicustos"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_nubicustos_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 5 findings minus 1 false_positive = 4
        assert len(findings) == 4

    def test_parse_skips_false_positive(self, parser, sample_file):
        findings = parser.parse(sample_file)
        titles = [f.title for f in findings]
        assert "CloudTrail Logging Disabled" not in titles

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssh = next(f for f in findings if "Unrestricted SSH" in f.title)

        assert ssh.source_tool == "nubicustos:scout"
        assert ssh.severity == Severity.CRITICAL
        assert ssh.cvss_score == 9.1
        assert ssh.finding_type == FindingType.CLOUD

    def test_parse_cloud_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 Bucket" in f.title)

        assert "cloud:aws" in s3.tags
        assert "region:us-east-1" in s3.tags
        assert "resource:s3_bucket" in s3.tags

    def test_parse_compliance_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 Bucket" in f.title)

        assert "compliance:CIS-AWS-1.4" in s3.tags
        assert "compliance:SOC2" in s3.tags

    def test_parse_cve(self, parser, sample_file):
        findings = parser.parse(sample_file)
        rds = next(f for f in findings if "RDS" in f.title)

        assert "CVE-2023-22515" in rds.cve_ids

    def test_parse_includes_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 Bucket" in f.title)

        assert s3.evidence is not None
        assert "AllUsers" in s3.evidence

    def test_parse_includes_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 Bucket" in f.title)

        assert s3.remediation is not None
        assert "Block Public Access" in s3.remediation

    def test_nubicustos_invalid_json(self, tmp_path):
        parser = NubicustosParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestIndagoParser:
    """Tests for Indago API security scanner parser."""

    @pytest.fixture
    def parser(self):
        return IndagoParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "indago_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "indago"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_indago_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli.source_tool == "indago"
        assert sqli.severity == Severity.CRITICAL
        assert sqli.confidence == Confidence.CERTAIN
        assert "CWE-89" in sqli.cwe_ids
        assert sqli.cvss_score == 9.8
        assert sqli.finding_type == FindingType.DAST

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli.location.url == "https://api.example.com:8443/api/v1/users/search"
        assert sqli.location.method == "GET"
        assert sqli.location.parameter == "query"
        assert sqli.location.host == "api.example.com"
        assert sqli.location.port == 8443

    def test_parse_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli.evidence is not None
        assert "REQUEST:" in sqli.evidence
        assert "RESPONSE:" in sqli.evidence
        assert "PAYLOAD:" in sqli.evidence

    def test_parse_curl_in_raw_data(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert "curl_command" in sqli.raw_data

    def test_parse_includes_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli.remediation is not None
        assert "parameterized" in sqli.remediation.lower()

    def test_indago_invalid_json(self, tmp_path):
        parser = IndagoParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestMobilicustosParser:
    """Tests for Mobilicustos mobile security scanner parser."""

    @pytest.fixture
    def parser(self):
        return MobilicustosParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "mobilicustos_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "mobilicustos"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_mobilicustos_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"app": {}, "findings": [{"no_app_id": true}]}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 5 findings minus 1 false_positive = 4
        assert len(findings) == 4

    def test_parse_skips_false_positive(self, parser, sample_file):
        findings = parser.parse(sample_file)
        titles = [f.title for f in findings]
        assert "Weak Encryption Algorithm Used" not in titles

    def test_parse_sast_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api_key = next(f for f in findings if "API Key" in f.title)

        assert api_key.source_tool == "mobilicustos"
        assert api_key.severity == Severity.HIGH
        assert api_key.finding_type == FindingType.SAST
        assert "CWE-798" in api_key.cwe_ids

    def test_parse_dast_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cert_pin = next(f for f in findings if "Certificate Pinning" in f.title)

        # network_traffic category → DAST
        assert cert_pin.finding_type == FindingType.DAST

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api_key = next(f for f in findings if "API Key" in f.title)

        assert api_key.location.file_path == "com/acme/pay/network/ApiClient.java"
        assert api_key.location.line_start == 28

    def test_parse_masvs_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api_key = next(f for f in findings if "API Key" in f.title)

        assert "masvs:MASVS-CODE" in api_key.tags
        assert "masvs-control:MSTG-CODE-1" in api_key.tags
        assert "mastg:MASTG-TEST-0001" in api_key.tags

    def test_parse_app_metadata_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api_key = next(f for f in findings if "API Key" in f.title)

        assert "platform:android" in api_key.tags
        assert "package:com.acme.pay" in api_key.tags

    def test_parse_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api_key = next(f for f in findings if "API Key" in f.title)

        assert api_key.evidence is not None
        assert "sk_live_abc123" in api_key.evidence

    def test_mobilicustos_invalid_json(self, tmp_path):
        parser = MobilicustosParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestCepheusParser:
    """Tests for Cepheus container escape analysis parser."""

    @pytest.fixture
    def parser(self):
        return CepheusParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "cepheus_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "cepheus"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_cepheus_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 2 chain findings + 2 standalone CVE findings (CVE-2022-0185, CVE-2021-25741)
        assert len(findings) == 4

    def test_parse_chain_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        chain = next(f for f in findings if "privileged_container" in f.title and "Container Escape:" in f.title)

        assert chain.source_tool == "cepheus"
        assert chain.severity == Severity.CRITICAL
        assert chain.cvss_score == 9.8
        assert chain.finding_type == FindingType.CONTAINER
        assert "privileged_container" in chain.title
        assert "nsenter_escape" in chain.title

    def test_parse_chain_cves(self, parser, sample_file):
        findings = parser.parse(sample_file)
        chain = next(f for f in findings if "privileged_container" in f.title and "Container Escape:" in f.title)

        assert "CVE-2022-0185" in chain.cve_ids

    def test_parse_chain_mitre_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        chain = next(f for f in findings if "privileged_container" in f.title and "Container Escape:" in f.title)

        assert "mitre:T1611" in chain.tags

    def test_parse_chain_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        chain = next(f for f in findings if "privileged_container" in f.title and "Container Escape:" in f.title)

        assert chain.remediation is not None
        assert "privileged" in chain.remediation.lower()

    def test_parse_standalone_cve_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cve_finding = next(f for f in findings if "CVE-2022-0185" in f.title and "Container Vulnerability:" in f.title)

        assert cve_finding.source_tool == "cepheus"
        assert "CVE-2022-0185" in cve_finding.cve_ids
        assert cve_finding.finding_type == FindingType.CONTAINER

    def test_parse_confidence_mapping(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # Chain 1 has all high reliability steps → CERTAIN confidence
        chain1 = next(f for f in findings if "privileged_container" in f.title and "Container Escape:" in f.title)
        assert chain1.confidence == Confidence.CERTAIN

        # Chain 2 has a medium reliability step → FIRM confidence
        chain2 = next(f for f in findings if "writable_hostpath" in f.title and "Container Escape:" in f.title)
        assert chain2.confidence == Confidence.FIRM

    def test_cepheus_invalid_json(self, tmp_path):
        parser = CepheusParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)


class TestBypassBurritoParser:
    """Tests for BypassBurrito WAF bypass testing parser."""

    @pytest.fixture
    def parser(self):
        return BypassBurritoParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "bypassburrito_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "bypassburrito"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_bypassburrito_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_parse_successful_bypass(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert xss.source_tool == "bypassburrito"
        assert xss.severity == Severity.HIGH
        assert xss.finding_type == FindingType.DAST
        assert "WAF Bypass:" in xss.title

    def test_parse_no_bypass(self, parser, sample_file):
        findings = parser.parse(sample_file)
        no_bypass = next(f for f in findings if "No Bypass Found" in f.title)

        assert no_bypass.severity == Severity.INFO

    def test_parse_waf_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert "waf:cloud_waf" in xss.tags
        assert "waf-vendor:CloudFlare" in xss.tags

    def test_parse_mutation_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert "mutation:tag_substitution" in xss.tags
        assert "mutation:event_handler_swap" in xss.tags

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert xss.location.url == "https://app.example.com/search"
        assert xss.location.method == "GET"
        assert xss.location.parameter == "q"

    def test_parse_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert xss.evidence is not None
        assert "Original Payload:" in xss.evidence
        assert "Bypass Payload:" in xss.evidence

    def test_parse_curl_in_raw_data(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xss = next(f for f in findings if "XSS" in f.title)

        assert "curl_command" in xss.raw_data

    def test_supports_single_object(self, parser, tmp_path):
        """Should support single object (non-array) format."""
        single = tmp_path / "single.json"
        single.write_text('{"original_payload": "test", "waf_detected": {"type": "waf"}, "successful_bypass": {"found": false}}')
        assert parser.supports_file(single)

    def test_bypassburrito_invalid_json(self, tmp_path):
        parser = BypassBurritoParser()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")

        with pytest.raises(ParseError):
            parser.parse(bad_file)
