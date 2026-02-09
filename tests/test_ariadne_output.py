"""Tests for Ariadne output formatter."""

import json

import pytest

from vinculum.correlation.engine import CorrelationResult, correlate_findings
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.output.ariadne_output import AriadneOutputFormatter


def _make_finding(**kwargs) -> UnifiedFinding:
    """Helper to create a finding with defaults."""
    defaults = {
        "source_tool": "test",
        "source_id": "1",
        "title": "Test Finding",
        "severity": Severity.MEDIUM,
        "finding_type": FindingType.DAST,
    }
    defaults.update(kwargs)
    return UnifiedFinding(**defaults)


@pytest.fixture
def formatter():
    return AriadneOutputFormatter(pretty=True)


@pytest.fixture
def sample_result():
    """Create a sample correlation result with mixed finding types."""
    findings = [
        _make_finding(
            source_tool="nuclei",
            source_id="log4j-1",
            title="Log4j RCE",
            severity=Severity.CRITICAL,
            finding_type=FindingType.DAST,
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
            location=FindingLocation(
                host="192.168.1.10",
                port=443,
                protocol="tcp",
                service="https",
                url="https://example.com/api",
            ),
        ),
        _make_finding(
            source_tool="nikto",
            source_id="xframe-1",
            title="X-Frame-Options Missing",
            severity=Severity.INFO,
            finding_type=FindingType.DAST,
            location=FindingLocation(
                host="192.168.1.10",
                port=443,
                protocol="tcp",
                service="https",
            ),
            remediation="Add X-Frame-Options header",
        ),
        _make_finding(
            source_tool="nmap",
            source_id="mysql-1",
            title="MySQL Remote Access",
            severity=Severity.HIGH,
            finding_type=FindingType.NETWORK,
            location=FindingLocation(
                host="192.168.1.20",
                port=3306,
                protocol="tcp",
                service="mysql",
            ),
        ),
        _make_finding(
            source_tool="testssl",
            source_id="ssl-expired-1",
            title="SSL Certificate Expired",
            severity=Severity.HIGH,
            finding_type=FindingType.OTHER,
            cwe_ids=["CWE-295"],
            location=FindingLocation(
                host="192.168.1.10",
                port=443,
                protocol="tcp",
            ),
        ),
    ]
    return correlate_findings(findings)


class TestAriadneOutputFormatter:
    """Tests for the Ariadne output formatter."""

    def test_format_returns_valid_json(self, formatter, sample_result):
        output = formatter.format(sample_result)
        data = json.loads(output)
        assert data is not None

    def test_format_has_required_top_level_keys(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        assert data["format"] == "vinculum-ariadne-export"
        assert data["format_version"] == "1.0"
        assert "metadata" in data
        assert "hosts" in data
        assert "services" in data
        assert "vulnerabilities" in data
        assert "misconfigurations" in data
        assert "relationships" in data

    def test_format_extracts_unique_hosts(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        hosts = data["hosts"]
        host_ips = [h["ip"] for h in hosts]
        assert "192.168.1.10" in host_ips
        assert "192.168.1.20" in host_ips
        # Should be unique
        assert len(host_ips) == len(set(host_ips))

    def test_format_extracts_services(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        services = data["services"]
        assert len(services) > 0
        svc = next(s for s in services if s["port"] == 443)
        assert svc["host_ip"] == "192.168.1.10"
        assert svc["protocol"] == "tcp"

    def test_vulnerability_classification(self, formatter, sample_result):
        """Findings with CVEs should be classified as vulnerabilities."""
        data = json.loads(formatter.format(sample_result))
        vulns = data["vulnerabilities"]
        vuln_titles = [v["title"] for v in vulns]
        assert "Log4j RCE" in vuln_titles

    def test_misconfiguration_classification(self, formatter, sample_result):
        """Info-level findings without CVE should be misconfigurations."""
        data = json.loads(formatter.format(sample_result))
        misconfigs = data["misconfigurations"]
        misconfig_titles = [m["title"] for m in misconfigs]
        assert "X-Frame-Options Missing" in misconfig_titles

    def test_network_finding_is_vulnerability(self, formatter, sample_result):
        """Non-info NETWORK findings without CVE should be vulnerabilities."""
        data = json.loads(formatter.format(sample_result))
        vulns = data["vulnerabilities"]
        vuln_titles = [v["title"] for v in vulns]
        assert "MySQL Remote Access" in vuln_titles

    def test_vinculum_metadata_present(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        for vuln in data["vulnerabilities"]:
            assert "vinculum_metadata" in vuln
            meta = vuln["vinculum_metadata"]
            assert "correlation_id" in meta
            assert "fingerprint" in meta
            assert "source_tools" in meta
            assert "finding_count" in meta

    def test_relationships_include_runs_on(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        runs_on = [r for r in data["relationships"] if r["relation_type"] == "runs_on"]
        assert len(runs_on) > 0
        for rel in runs_on:
            assert rel["source_type"] == "service"
            assert rel["target_type"] == "host"

    def test_relationships_include_has_vulnerability(self, formatter, sample_result):
        data = json.loads(formatter.format(sample_result))
        has_vuln = [r for r in data["relationships"] if r["relation_type"] == "has_vulnerability"]
        assert len(has_vuln) > 0

    def test_write_to_file(self, formatter, sample_result, tmp_path):
        output_path = tmp_path / "ariadne_out.json"
        formatter.write(sample_result, output_path)
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["format"] == "vinculum-ariadne-export"

    def test_compact_format(self, sample_result):
        formatter = AriadneOutputFormatter(pretty=False)
        output = formatter.format(sample_result)
        # Compact format should not have indentation
        assert "\n" not in output
        data = json.loads(output)
        assert data["format"] == "vinculum-ariadne-export"

    def test_empty_result(self, formatter):
        result = correlate_findings([])
        data = json.loads(formatter.format(result))
        assert data["hosts"] == []
        assert data["services"] == []
        assert data["vulnerabilities"] == []
        assert data["misconfigurations"] == []
        assert data["relationships"] == []
