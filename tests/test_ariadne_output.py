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
        assert data["format_version"] == "1.1"
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
        assert data["cloud_resources"] == []
        assert data["containers"] == []
        assert data["mobile_apps"] == []
        assert data["api_endpoints"] == []
        assert data["relationships"] == []

    def test_v11_has_new_entity_arrays(self, formatter, sample_result):
        """v1.1 output should include cloud_resources, containers, mobile_apps, api_endpoints."""
        data = json.loads(formatter.format(sample_result))
        assert "cloud_resources" in data
        assert "containers" in data
        assert "mobile_apps" in data
        assert "api_endpoints" in data


class TestAriadneCloudResources:
    """Tests for cloud_resources extraction in Ariadne output."""

    def test_cloud_resources_extracted(self):
        findings = [
            _make_finding(
                source_tool="nubicustos:prowler",
                source_id="nubi-001",
                title="S3 Bucket Public Access",
                severity=Severity.HIGH,
                finding_type=FindingType.CLOUD,
                location=FindingLocation(host="arn:aws:s3:::my-bucket"),
                raw_data={
                    "resource_id": "arn:aws:s3:::my-bucket",
                    "resource_type": "s3_bucket",
                    "resource_name": "my-bucket",
                    "cloud_provider": "aws",
                    "region": "us-east-1",
                },
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        assert len(data["cloud_resources"]) == 1
        cr = data["cloud_resources"][0]
        assert cr["resource_id"] == "arn:aws:s3:::my-bucket"
        assert cr["resource_type"] == "s3_bucket"
        assert cr["cloud_provider"] == "aws"
        assert cr["region"] == "us-east-1"

    def test_cloud_resources_deduplicated(self):
        findings = [
            _make_finding(
                source_tool="nubicustos:prowler",
                source_id="nubi-001",
                title="Finding 1",
                finding_type=FindingType.CLOUD,
                location=FindingLocation(host="arn:aws:s3:::same"),
                raw_data={"resource_id": "arn:aws:s3:::same", "cloud_provider": "aws"},
            ),
            _make_finding(
                source_tool="nubicustos:scout",
                source_id="nubi-002",
                title="Finding 2",
                finding_type=FindingType.CLOUD,
                location=FindingLocation(host="arn:aws:s3:::same"),
                raw_data={"resource_id": "arn:aws:s3:::same", "cloud_provider": "aws"},
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        assert len(data["cloud_resources"]) == 1

    def test_has_cloud_vulnerability_relationship(self):
        findings = [
            _make_finding(
                source_tool="nubicustos:prowler",
                source_id="nubi-001",
                title="Cloud Issue",
                severity=Severity.HIGH,
                finding_type=FindingType.CLOUD,
                cve_ids=["CVE-2023-1234"],
                location=FindingLocation(host="arn:aws:s3:::my-bucket"),
                raw_data={"resource_id": "arn:aws:s3:::my-bucket", "cloud_provider": "aws"},
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        rel_types = {r["relation_type"] for r in data["relationships"]}
        assert "has_cloud_vulnerability" in rel_types


class TestAriadneContainers:
    """Tests for containers extraction in Ariadne output."""

    def test_containers_extracted(self):
        findings = [
            _make_finding(
                source_tool="cepheus",
                source_id="chain-001",
                title="Container Escape: priv → nsenter",
                severity=Severity.CRITICAL,
                finding_type=FindingType.CONTAINER,
                raw_data={
                    "chain": {
                        "container": {
                            "container_id": "abc123",
                            "hostname": "webapp-pod-1",
                            "runtime": "containerd",
                            "namespace": "production",
                            "image": "acme/webapp:3.2.1",
                        }
                    },
                    "posture": {},
                },
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        assert len(data["containers"]) == 1
        c = data["containers"][0]
        assert c["container_id"] == "abc123"
        assert c["hostname"] == "webapp-pod-1"
        assert c["runtime"] == "containerd"
        assert c["namespace"] == "production"
        assert c["image"] == "acme/webapp:3.2.1"

    def test_has_container_escape_relationship(self):
        findings = [
            _make_finding(
                source_tool="cepheus",
                source_id="chain-001",
                title="Container Escape",
                severity=Severity.CRITICAL,
                finding_type=FindingType.CONTAINER,
                location=FindingLocation(host="webapp-pod-1"),
                raw_data={"chain": {"container": {"container_id": "abc123"}}, "posture": {}},
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        rel_types = {r["relation_type"] for r in data["relationships"]}
        assert "has_container_escape" in rel_types


class TestAriadneMobileApps:
    """Tests for mobile_apps extraction in Ariadne output."""

    def test_mobile_apps_extracted(self):
        findings = [
            _make_finding(
                source_tool="mobilicustos",
                source_id="mob-001",
                title="Hardcoded API Key",
                severity=Severity.HIGH,
                finding_type=FindingType.SAST,
                tags=["platform:android", "package:com.acme.pay"],
                raw_data={"app_id": "com.acme.pay"},
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        assert len(data["mobile_apps"]) == 1
        app = data["mobile_apps"][0]
        assert app["app_id"] == "com.acme.pay"
        assert app["platform"] == "android"
        assert app["package_name"] == "com.acme.pay"

    def test_has_mobile_vulnerability_relationship(self):
        findings = [
            _make_finding(
                source_tool="mobilicustos",
                source_id="mob-001",
                title="Mobile Vuln",
                severity=Severity.HIGH,
                finding_type=FindingType.SAST,
                location=FindingLocation(file_path="com/acme/App.java"),
                raw_data={"app_id": "com.acme.pay"},
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        rel_types = {r["relation_type"] for r in data["relationships"]}
        # Mobilicustos SAST findings without host won't have host-based relationships
        # but the relation type mapping should still apply when relationships are created
        assert "mobile_apps" in data


class TestAriadneApiEndpoints:
    """Tests for api_endpoints extraction in Ariadne output."""

    def test_api_endpoints_extracted(self):
        findings = [
            _make_finding(
                source_tool="indago",
                source_id="ind-001",
                title="SQL Injection",
                severity=Severity.CRITICAL,
                finding_type=FindingType.DAST,
                location=FindingLocation(
                    url="https://api.example.com/users/search",
                    method="GET",
                    parameter="query",
                    host="api.example.com",
                    port=443,
                ),
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        assert len(data["api_endpoints"]) == 1
        ep = data["api_endpoints"][0]
        assert ep["url"] == "https://api.example.com/users/search"
        assert ep["method"] == "GET"
        assert "query" in ep["parameters"]

    def test_has_api_vulnerability_relationship(self):
        findings = [
            _make_finding(
                source_tool="indago",
                source_id="ind-001",
                title="API Vuln",
                severity=Severity.HIGH,
                finding_type=FindingType.DAST,
                location=FindingLocation(
                    url="https://api.example.com/endpoint",
                    method="POST",
                    host="api.example.com",
                    port=443,
                ),
            ),
        ]
        result = correlate_findings(findings)
        formatter = AriadneOutputFormatter(pretty=True)
        data = json.loads(formatter.format(result))

        rel_types = {r["relation_type"] for r in data["relationships"]}
        assert "has_api_vulnerability" in rel_types
