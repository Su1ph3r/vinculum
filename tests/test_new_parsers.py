"""Tests for the 10 new parsers added in v0.4.0."""

from pathlib import Path

import pytest

from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.parsers.base import ParseError, ParserRegistry

# Ecosystem parsers
from vinculum.parsers.ariadne_report import AriadneReportParser
from vinculum.parsers.nubicustos_containers import NubicustosContainersParser
from vinculum.parsers.reticustos_endpoints import ReticustosEndpointsParser

# Third-party JSON parsers
from vinculum.parsers.checkov import CheckovParser
from vinculum.parsers.grype import GrypeParser
from vinculum.parsers.mobsf import MobSFParser
from vinculum.parsers.snyk import SnykParser

# Third-party XML parsers
from vinculum.parsers.dependency_check import DependencyCheckParser
from vinculum.parsers.nikto import NiktoParser
from vinculum.parsers.nmap import NmapParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ===========================================================================
# Ecosystem Parsers
# ===========================================================================


class TestReticustosEndpointsParser:
    """Tests for Reticustos endpoint inventory parser."""

    @pytest.fixture
    def parser(self):
        return ReticustosEndpointsParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "reticustos_endpoints_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "reticustos:endpoints"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_non_endpoints_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"format": "something-else", "data": []}')
        assert not parser.supports_file(other)

    def test_does_not_support_reticustos_findings(self, parser):
        """Must not match the existing reticustos findings fixture."""
        assert not parser.supports_file(FIXTURES_DIR / "reticustos_sample.json")

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_all_findings_are_info_severity(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.severity == Severity.INFO

    def test_all_findings_are_dast_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.finding_type == FindingType.DAST

    def test_parse_endpoint_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ep1 = next(f for f in findings if "ep-001" in f.source_id)

        assert ep1.location.url == "https://api.example.com/api/v1/users"
        assert ep1.location.method == "GET"
        assert ep1.location.host == "api.example.com"
        assert ep1.location.port == 443

    def test_parse_endpoint_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ep1 = next(f for f in findings if "ep-001" in f.source_id)

        assert "discovered_by:crawl" in ep1.tags
        assert "content_type:application/json" in ep1.tags

    def test_parse_authenticated_endpoint_tag(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ep2 = next(f for f in findings if "ep-002" in f.source_id)

        assert "authenticated" in ep2.tags

    def test_parse_empty_endpoints(self, parser, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text('{"format": "reticustos-endpoints", "endpoints": []}')
        findings = parser.parse(empty)
        assert findings == []

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestNubicustosContainersParser:
    """Tests for Nubicustos container inventory parser."""

    @pytest.fixture
    def parser(self):
        return NubicustosContainersParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nubicustos_containers_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nubicustos:containers"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_nubicustos_findings(self, parser):
        """Must not match the existing nubicustos cloud findings fixture."""
        assert not parser.supports_file(FIXTURES_DIR / "nubicustos_sample.json")

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_all_findings_are_info_severity(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.severity == Severity.INFO

    def test_all_findings_are_container_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.finding_type == FindingType.CONTAINER

    def test_parse_container_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api = next(f for f in findings if "api-server" in f.title)
        assert api.location.host == "10.0.1.10"

    def test_parse_container_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        api = next(f for f in findings if "api-server" in f.title)

        assert "image:acme/api-server:v2.3.1" in api.tags
        assert "namespace:production" in api.tags

    def test_privileged_container_tag(self, parser, sample_file):
        findings = parser.parse(sample_file)
        mon = next(f for f in findings if "monitoring-agent" in f.title)

        assert "privileged" in mon.tags
        assert "PRIVILEGED" in mon.description

    def test_parse_empty_containers(self, parser, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text('{"format": "nubicustos-containers", "containers": []}')
        findings = parser.parse(empty)
        assert findings == []

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestAriadneReportParser:
    """Tests for Ariadne attack path report parser."""

    @pytest.fixture
    def parser(self):
        return AriadneReportParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "ariadne_report_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "ariadne:report"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_ariadne_export(self, parser):
        """Must not match the existing ariadne (vinculum-ariadne-export) fixture."""
        assert not parser.supports_file(FIXTURES_DIR / "ariadne_sample.json")

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 3

    def test_severity_from_highest_node(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        # The vulnerability node has severity "critical"
        assert sqli_path.severity == Severity.CRITICAL

    def test_container_escape_path(self, parser, sample_file):
        findings = parser.parse(sample_file)
        escape = next(f for f in findings if "Container Escape" in f.title)

        assert escape.severity == Severity.HIGH

    def test_medium_path(self, parser, sample_file):
        findings = parser.parse(sample_file)
        redis = next(f for f in findings if "Redis" in f.title)

        assert redis.severity == Severity.MEDIUM

    def test_cve_extraction(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        assert "CVE-2024-1234" in sqli_path.cve_ids

    def test_cwe_extraction(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        assert "CWE-89" in sqli_path.cwe_ids

    def test_mitre_technique_tags(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        assert "mitre:technique:T1190" in sqli_path.tags

    def test_playbook_as_evidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli_path.evidence is not None
        assert "Exploit SQLi" in sqli_path.evidence

    def test_location_from_first_node(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli_path = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli_path.location.host == "api.corp.example.com"
        assert sqli_path.location.port == 443

    def test_parse_empty_paths(self, parser, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text('{"format": "ariadne-report", "attack_paths": []}')
        findings = parser.parse(empty)
        assert findings == []

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


# ===========================================================================
# Third-Party JSON Parsers
# ===========================================================================


class TestSnykParser:
    """Tests for Snyk vulnerability scanner parser."""

    @pytest.fixture
    def parser(self):
        return SnykParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "snyk_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "snyk"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_generic_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_parse_critical_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        rce = next(f for f in findings if "Remote Code Execution" in f.title)

        assert rce.source_tool == "snyk"
        assert rce.severity == Severity.CRITICAL
        assert "CVE-2021-23337" in rce.cve_ids
        assert "CWE-94" in rce.cwe_ids
        assert rce.cvss_score == 9.8
        assert rce.finding_type == FindingType.DEPENDENCY

    def test_parse_high_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        sqli = next(f for f in findings if "SQL Injection" in f.title)

        assert sqli.severity == Severity.HIGH
        assert "CVE-2023-22578" in sqli.cve_ids
        assert "CWE-89" in sqli.cwe_ids

    def test_parse_medium_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        proto = next(f for f in findings if "Prototype Pollution" in f.title)

        assert proto.severity == Severity.MEDIUM

    def test_parse_low_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        redos = next(f for f in findings if "ReDoS" in f.title)

        assert redos.severity == Severity.LOW

    def test_parse_remediation(self, parser, sample_file):
        findings = parser.parse(sample_file)
        rce = next(f for f in findings if "Remote Code Execution" in f.title)

        assert rce.remediation is not None
        assert "4.17.21" in rce.remediation

    def test_parse_references(self, parser, sample_file):
        findings = parser.parse(sample_file)
        rce = next(f for f in findings if "Remote Code Execution" in f.title)

        assert len(rce.references) > 0
        assert any("nvd.nist.gov" in r for r in rce.references)

    def test_parse_cvss_vector(self, parser, sample_file):
        findings = parser.parse(sample_file)
        rce = next(f for f in findings if "Remote Code Execution" in f.title)

        assert rce.cvss3_vector is not None
        assert "CVSS:3.1" in rce.cvss3_vector

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestGrypeParser:
    """Tests for Grype vulnerability scanner parser."""

    @pytest.fixture
    def parser(self):
        return GrypeParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "grype_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "grype"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_generic_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"matches": [], "descriptor": {"name": "not-grype"}}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_parse_critical_os_package(self, parser, sample_file):
        findings = parser.parse(sample_file)
        nghttp = next(f for f in findings if "CVE-2023-44487" in f.title)

        assert nghttp.severity == Severity.CRITICAL
        assert "CVE-2023-44487" in nghttp.cve_ids
        assert nghttp.finding_type == FindingType.CONTAINER  # deb package
        assert nghttp.cvss3_score == 7.5

    def test_parse_high_language_package(self, parser, sample_file):
        findings = parser.parse(sample_file)
        requests = next(f for f in findings if "CVE-2023-32681" in f.title)

        assert requests.severity == Severity.HIGH
        assert requests.finding_type == FindingType.DEPENDENCY  # python package

    def test_parse_medium_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        py = next(f for f in findings if "CVE-2022-42969" in f.title)

        assert py.severity == Severity.MEDIUM

    def test_parse_negligible_as_info(self, parser, sample_file):
        findings = parser.parse(sample_file)
        apt = next(f for f in findings if "CVE-2011-3374" in f.title)

        assert apt.severity == Severity.INFO

    def test_parse_remediation_fixed(self, parser, sample_file):
        findings = parser.parse(sample_file)
        nghttp = next(f for f in findings if "CVE-2023-44487" in f.title)

        assert nghttp.remediation is not None
        assert "1.52.0" in nghttp.remediation

    def test_parse_remediation_not_fixed(self, parser, sample_file):
        findings = parser.parse(sample_file)
        py = next(f for f in findings if "CVE-2022-42969" in f.title)

        assert py.remediation is not None
        assert "No fix available" in py.remediation

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        nghttp = next(f for f in findings if "CVE-2023-44487" in f.title)

        assert nghttp.location.file_path is not None

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestCheckovParser:
    """Tests for Checkov IaC scanner parser."""

    @pytest.fixture
    def parser(self):
        return CheckovParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "checkov_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "checkov"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_generic_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 2 failed terraform + 1 failed dockerfile + 1 failed kubernetes = 4
        assert len(findings) == 4

    def test_parse_terraform_cloud_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 bucket has server-side encryption" in f.title)

        assert s3.source_tool == "checkov"
        assert s3.finding_type == FindingType.CLOUD
        assert s3.severity == Severity.HIGH

    def test_parse_dockerfile_container_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        docker = next(f for f in findings if "HEALTHCHECK" in f.title)

        assert docker.finding_type == FindingType.CONTAINER

    def test_parse_kubernetes_container_type(self, parser, sample_file):
        findings = parser.parse(sample_file)
        k8s = next(f for f in findings if "privileged containers" in f.title)

        assert k8s.finding_type == FindingType.CONTAINER
        assert k8s.severity == Severity.CRITICAL

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 bucket has server-side encryption" in f.title)

        assert s3.location.file_path is not None
        assert "main.tf" in s3.location.file_path
        assert s3.location.line_start == 17
        assert s3.location.line_end == 30

    def test_parse_cwe_from_bc_check_id(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 bucket has server-side encryption" in f.title)

        assert "CWE-311" in s3.cwe_ids

    def test_parse_guideline_reference(self, parser, sample_file):
        findings = parser.parse(sample_file)
        s3 = next(f for f in findings if "S3 bucket has server-side encryption" in f.title)

        assert len(s3.references) > 0
        assert any("prismacloud" in r for r in s3.references)

    def test_default_severity_for_no_severity_field(self, parser, sample_file):
        findings = parser.parse(sample_file)
        docker = next(f for f in findings if "HEALTHCHECK" in f.title)

        # No severity field on this check → defaults to MEDIUM
        assert docker.severity == Severity.MEDIUM

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestMobSFParser:
    """Tests for MobSF mobile security scanner parser."""

    @pytest.fixture
    def parser(self):
        return MobSFParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "mobsf_sample.json"

    def test_tool_name(self, parser):
        assert parser.tool_name == "mobsf"

    def test_supported_extensions(self, parser):
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_generic_json(self, parser, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"results": []}')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # code: hardcoded_secret(2 files) + insecure_random(1 file) + manifest(2) + binary(1) + cert(1) = 7
        assert len(findings) == 7

    def test_parse_code_analysis_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        code_findings = [f for f in findings if "code_analysis" in f.tags]

        # 3 code analysis findings (2 hardcoded_secret files + 1 insecure_random)
        assert len(code_findings) == 3

    def test_parse_manifest_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        debuggable = next(f for f in findings if "debuggable" in f.title.lower())

        assert debuggable.source_tool == "mobsf"
        assert debuggable.severity == Severity.HIGH
        assert debuggable.finding_type == FindingType.SAST

    def test_parse_binary_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        binary = next(f for f in findings if "insecure API" in f.title)

        assert binary.severity == Severity.HIGH
        assert binary.finding_type == FindingType.SAST

    def test_parse_certificate_finding(self, parser, sample_file):
        findings = parser.parse(sample_file)
        cert = next(f for f in findings if "debug certificate" in f.title)

        assert cert.severity == Severity.MEDIUM  # "warning" maps to MEDIUM

    def test_parse_platform_tag(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert "android" in f.tags

    def test_invalid_json_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(ParseError):
            parser.parse(bad)


# ===========================================================================
# Third-Party XML Parsers
# ===========================================================================


class TestDependencyCheckParser:
    """Tests for OWASP Dependency-Check parser."""

    @pytest.fixture
    def parser(self):
        return DependencyCheckParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "dependency_check_sample.xml"

    def test_tool_name(self, parser):
        assert parser.tool_name == "dependency-check"

    def test_supported_extensions(self, parser):
        assert ".xml" in parser.supported_extensions
        assert ".json" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_generic_xml(self, parser, tmp_path):
        other = tmp_path / "other.xml"
        other.write_text('<?xml version="1.0"?><root><data/></root>')
        assert not parser.supports_file(other)

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # log4j(1) + commons-text(1) + jackson(2) = 4
        assert len(findings) == 4

    def test_parse_critical_log4j(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "CVE-2021-44228" in f.source_id)

        assert log4j.source_tool == "dependency-check"
        assert log4j.severity == Severity.CRITICAL
        assert "CVE-2021-44228" in log4j.cve_ids
        assert log4j.cvss3_score == 10.0
        assert log4j.finding_type == FindingType.DEPENDENCY

    def test_parse_cwe_extraction(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "CVE-2021-44228" in f.source_id)

        assert "CWE-917" in log4j.cwe_ids

    def test_parse_high_severity(self, parser, sample_file):
        findings = parser.parse(sample_file)
        jackson_high = next(f for f in findings if "CVE-2022-42003" in f.source_id)

        assert jackson_high.severity == Severity.HIGH
        assert jackson_high.cvss3_score == 7.5

    def test_parse_medium_severity(self, parser, sample_file):
        findings = parser.parse(sample_file)
        jackson_med = next(f for f in findings if "CVE-2020-36518" in f.source_id)

        # CVSS v2 score 5.0 → >=4 → MEDIUM
        assert jackson_med.severity == Severity.MEDIUM

    def test_parse_references(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "CVE-2021-44228" in f.source_id)

        assert len(log4j.references) > 0
        assert any("nvd.nist.gov" in r for r in log4j.references)

    def test_parse_location(self, parser, sample_file):
        findings = parser.parse(sample_file)
        log4j = next(f for f in findings if "CVE-2021-44228" in f.source_id)

        assert log4j.location.file_path is not None

    def test_invalid_xml_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("not xml at all")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestNiktoParser:
    """Tests for Nikto web scanner parser."""

    @pytest.fixture
    def parser(self):
        return NiktoParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nikto_sample.xml"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nikto"

    def test_supported_extensions(self, parser):
        assert ".xml" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_nmap_xml(self, parser):
        """Must not match the Nmap fixture."""
        assert not parser.supports_file(FIXTURES_DIR / "nmap_sample.xml")

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        assert len(findings) == 4

    def test_all_findings_are_dast(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.finding_type == FindingType.DAST

    def test_all_findings_are_firm_confidence(self, parser, sample_file):
        findings = parser.parse(sample_file)
        for f in findings:
            assert f.confidence == Confidence.FIRM

    def test_severity_heuristic_low(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # X-Frame-Options: "header" keyword → LOW, no OSVDB → stays LOW
        xframe = next(f for f in findings if "X-Frame-Options" in f.description)
        assert xframe.severity == Severity.LOW

    def test_severity_heuristic_osvdb_bump(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # /admin/: "directory indexing" → LOW, has OSVDB 3092 → bumped to MEDIUM
        admin = next(f for f in findings if "/admin/" in f.description)
        assert admin.severity == Severity.MEDIUM

    def test_osvdb_tag(self, parser, sample_file):
        findings = parser.parse(sample_file)
        admin = next(f for f in findings if "/admin/" in f.description)
        assert "osvdb:3092" in admin.tags

    def test_parse_location_url(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xframe = next(f for f in findings if "X-Frame-Options" in f.description)
        assert xframe.location.url is not None
        assert "example.com" in xframe.location.url

    def test_parse_location_host_port(self, parser, sample_file):
        findings = parser.parse(sample_file)
        xframe = next(f for f in findings if "X-Frame-Options" in f.description)
        assert xframe.location.host == "example.com"
        assert xframe.location.port == 443

    def test_invalid_xml_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("not xml at all")
        with pytest.raises(ParseError):
            parser.parse(bad)


class TestNmapParser:
    """Tests for Nmap XML parser."""

    @pytest.fixture
    def parser(self):
        return NmapParser()

    @pytest.fixture
    def sample_file(self):
        return FIXTURES_DIR / "nmap_sample.xml"

    def test_tool_name(self, parser):
        assert parser.tool_name == "nmap"

    def test_supported_extensions(self, parser):
        assert ".xml" in parser.supported_extensions

    def test_supports_file(self, parser, sample_file):
        assert parser.supports_file(sample_file)

    def test_does_not_support_nikto_xml(self, parser):
        """Must not match the Nikto fixture."""
        assert not parser.supports_file(FIXTURES_DIR / "nikto_sample.xml")

    def test_parse_returns_findings(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # 4 open ports + 2 NSE script findings = 6
        assert len(findings) == 6

    def test_parse_port_findings_are_info(self, parser, sample_file):
        findings = parser.parse(sample_file)
        port_findings = [f for f in findings if f.source_id.startswith("port-")]

        assert len(port_findings) == 4
        for pf in port_findings:
            assert pf.severity == Severity.INFO
            assert pf.finding_type == FindingType.NETWORK
            assert pf.confidence == Confidence.CERTAIN

    def test_parse_open_port_details(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssh = next(f for f in findings if "22" in f.title and f.source_id.startswith("port-"))

        assert "Open Port" in ssh.title
        assert ssh.location.host == "192.168.1.100"
        assert ssh.location.port == 22
        assert ssh.location.protocol == "tcp"
        assert ssh.location.service == "ssh"

    def test_parse_nse_heartbleed(self, parser, sample_file):
        findings = parser.parse(sample_file)
        heartbleed = next(f for f in findings if "ssl-heartbleed" in f.source_id)

        assert heartbleed.severity == Severity.HIGH  # Has CVE
        assert "CVE-2014-0160" in heartbleed.cve_ids
        assert heartbleed.confidence == Confidence.FIRM
        assert heartbleed.finding_type == FindingType.NETWORK

    def test_parse_nse_csrf(self, parser, sample_file):
        findings = parser.parse(sample_file)
        csrf = next(f for f in findings if "http-csrf" in f.source_id)

        assert csrf.severity == Severity.MEDIUM  # No CVE
        assert len(csrf.cve_ids) == 0

    def test_skips_not_vulnerable_script(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # mysql-vuln-cve2012-2122 output says "NOT VULNERABLE" → should be skipped
        mysql_nse = [f for f in findings if "mysql-vuln" in f.source_id]
        assert len(mysql_nse) == 0

    def test_skips_non_finding_script(self, parser, sample_file):
        findings = parser.parse(sample_file)
        # http-server-header just reports version → no VULNERABLE/FOUND → skipped
        header_nse = [f for f in findings if "http-server-header" in f.source_id]
        assert len(header_nse) == 0

    def test_parse_hostname(self, parser, sample_file):
        findings = parser.parse(sample_file)
        ssh = next(f for f in findings if "22" in f.title and f.source_id.startswith("port-"))

        assert "web01.example.com" in ssh.description

    def test_invalid_xml_raises_parse_error(self, parser, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("not xml at all")
        with pytest.raises(ParseError):
            parser.parse(bad)


# ===========================================================================
# Cross-parser coexistence tests
# ===========================================================================


class TestEcosystemCoexistence:
    """Ensure new ecosystem parsers don't conflict with existing ones."""

    def test_reticustos_endpoints_rejects_reticustos_findings(self):
        parser = ReticustosEndpointsParser()
        assert not parser.supports_file(FIXTURES_DIR / "reticustos_sample.json")

    def test_reticustos_findings_rejects_endpoints(self):
        from vinculum.parsers.reticustos import ReticustosParser

        parser = ReticustosParser()
        assert not parser.supports_file(FIXTURES_DIR / "reticustos_endpoints_sample.json")

    def test_nubicustos_containers_rejects_nubicustos_findings(self):
        parser = NubicustosContainersParser()
        assert not parser.supports_file(FIXTURES_DIR / "nubicustos_sample.json")

    def test_nubicustos_findings_rejects_containers(self):
        from vinculum.parsers.nubicustos import NubicustosParser

        parser = NubicustosParser()
        assert not parser.supports_file(FIXTURES_DIR / "nubicustos_containers_sample.json")

    def test_ariadne_report_rejects_ariadne_export(self):
        parser = AriadneReportParser()
        assert not parser.supports_file(FIXTURES_DIR / "ariadne_sample.json")

    def test_ariadne_export_rejects_report(self):
        from vinculum.parsers.ariadne import AriadneParser

        parser = AriadneParser()
        assert not parser.supports_file(FIXTURES_DIR / "ariadne_report_sample.json")


# ===========================================================================
# Registry collision test
# ===========================================================================


class TestRegistryCollision:
    """Verify all 23 parsers route each fixture to the correct parser."""

    @pytest.fixture(autouse=True)
    def _setup_registry(self):
        """Register all 23 parsers in the correct order."""
        from vinculum.parsers.ariadne import AriadneParser
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

        ParserRegistry.clear()
        # Ecosystem (specific format key)
        ParserRegistry.register(AriadneParser())
        ParserRegistry.register(AriadneReportParser())
        ParserRegistry.register(ReticustosEndpointsParser())
        ParserRegistry.register(NubicustosContainersParser())
        # Existing
        ParserRegistry.register(BurpParser())
        ParserRegistry.register(BypassBurritoParser())
        ParserRegistry.register(CepheusParser())
        ParserRegistry.register(IndagoParser())
        ParserRegistry.register(MobilicustosParser())
        ParserRegistry.register(NessusParser())
        ParserRegistry.register(NubicustosParser())
        ParserRegistry.register(NucleiParser())
        ParserRegistry.register(ReticustosParser())
        # New third-party
        ParserRegistry.register(GrypeParser())
        ParserRegistry.register(SnykParser())
        ParserRegistry.register(DependencyCheckParser())
        ParserRegistry.register(CheckovParser())
        ParserRegistry.register(MobSFParser())
        ParserRegistry.register(NiktoParser())
        ParserRegistry.register(NmapParser())
        # Broad-match LAST
        ParserRegistry.register(SemgrepParser())
        ParserRegistry.register(TrivyParser())
        ParserRegistry.register(ZAPParser())
        yield
        ParserRegistry.clear()

    # New ecosystem parsers
    def test_ariadne_report_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "ariadne_report_sample.json")
        assert p is not None
        assert p.tool_name == "ariadne:report"

    def test_reticustos_endpoints_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "reticustos_endpoints_sample.json")
        assert p is not None
        assert p.tool_name == "reticustos:endpoints"

    def test_nubicustos_containers_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nubicustos_containers_sample.json")
        assert p is not None
        assert p.tool_name == "nubicustos:containers"

    # Existing ecosystem parsers still route correctly
    def test_ariadne_export_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "ariadne_sample.json")
        assert p is not None
        assert p.tool_name == "ariadne"

    def test_reticustos_findings_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "reticustos_sample.json")
        assert p is not None
        assert p.tool_name == "reticustos"

    def test_nubicustos_findings_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nubicustos_sample.json")
        assert p is not None
        assert p.tool_name == "nubicustos"

    # New third-party parsers
    def test_snyk_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "snyk_sample.json")
        assert p is not None
        assert p.tool_name == "snyk"

    def test_grype_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "grype_sample.json")
        assert p is not None
        assert p.tool_name == "grype"

    def test_checkov_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "checkov_sample.json")
        assert p is not None
        assert p.tool_name == "checkov"

    def test_mobsf_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "mobsf_sample.json")
        assert p is not None
        assert p.tool_name == "mobsf"

    def test_dependency_check_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "dependency_check_sample.xml")
        assert p is not None
        assert p.tool_name == "dependency-check"

    def test_nikto_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nikto_sample.xml")
        assert p is not None
        assert p.tool_name == "nikto"

    def test_nmap_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nmap_sample.xml")
        assert p is not None
        assert p.tool_name == "nmap"

    # Existing third-party parsers still route correctly
    def test_burp_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "burp_sample.xml")
        assert p is not None
        assert p.tool_name == "burp"

    def test_nessus_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nessus_sample.nessus")
        assert p is not None
        assert p.tool_name == "nessus"

    def test_semgrep_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "semgrep_sample.json")
        assert p is not None
        assert p.tool_name == "semgrep"

    def test_trivy_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "trivy_sample.json")
        assert p is not None
        assert p.tool_name == "trivy"

    def test_zap_routes_correctly(self):
        p = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "zap_sample.xml")
        assert p is not None
        assert p.tool_name == "zap"

    def test_total_registered_parsers(self):
        assert len(ParserRegistry.get_all_parsers()) == 23
