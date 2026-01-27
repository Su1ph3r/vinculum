"""Tests for SARIF output formatter."""

import json
from pathlib import Path

import pytest

from vinculum.correlation.engine import CorrelationResult, correlate_findings
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import CorrelationGroup, FindingLocation, UnifiedFinding
from vinculum.output.sarif_output import SARIFOutputFormatter, to_sarif


class TestSARIFOutputFormatter:
    """Test SARIF output formatting."""

    def _create_sample_finding(
        self,
        title: str = "Test XSS Vulnerability",
        severity: Severity = Severity.HIGH,
        cwe_ids: list[str] | None = None,
        cve_ids: list[str] | None = None,
        file_path: str | None = None,
        url: str | None = None,
    ) -> UnifiedFinding:
        """Create a sample finding for testing."""
        location = FindingLocation(
            file_path=file_path,
            url=url,
            line_start=10 if file_path else None,
            line_end=15 if file_path else None,
        )
        return UnifiedFinding(
            source_tool="test",
            source_id="test-001",
            title=title,
            description="Test description for the vulnerability.",
            severity=severity,
            confidence=Confidence.FIRM,
            cwe_ids=cwe_ids or ["CWE-79"],
            cve_ids=cve_ids or [],
            location=location,
            finding_type=FindingType.SAST if file_path else FindingType.DAST,
            fingerprint="abc123",
            remediation="Apply input validation.",
        )

    def _create_sample_result(self, findings: list[UnifiedFinding]) -> CorrelationResult:
        """Create a sample correlation result."""
        return correlate_findings(findings)

    def test_format_returns_valid_json(self):
        """Test that format returns valid JSON."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif_str = formatter.format(result)
        sarif = json.loads(sarif_str)

        assert sarif is not None
        assert "version" in sarif
        assert "runs" in sarif

    def test_sarif_version(self):
        """Test SARIF version is 2.1.0."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif

    def test_sarif_has_tool_info(self):
        """Test SARIF includes tool information."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))

        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "Vinculum"

    def test_sarif_result_has_rule_id(self):
        """Test SARIF results have rule IDs."""
        finding = self._create_sample_finding(cwe_ids=["CWE-79"])
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        results = sarif["runs"][0]["results"]

        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-79"

    def test_severity_mapping_critical(self):
        """Test critical severity maps to error level."""
        finding = self._create_sample_finding(severity=Severity.CRITICAL)
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        level = sarif["runs"][0]["results"][0]["level"]

        assert level == "error"

    def test_severity_mapping_high(self):
        """Test high severity maps to error level."""
        finding = self._create_sample_finding(severity=Severity.HIGH)
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        level = sarif["runs"][0]["results"][0]["level"]

        assert level == "error"

    def test_severity_mapping_medium(self):
        """Test medium severity maps to warning level."""
        finding = self._create_sample_finding(severity=Severity.MEDIUM)
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        level = sarif["runs"][0]["results"][0]["level"]

        assert level == "warning"

    def test_severity_mapping_low(self):
        """Test low severity maps to note level."""
        finding = self._create_sample_finding(severity=Severity.LOW)
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        level = sarif["runs"][0]["results"][0]["level"]

        assert level == "note"

    def test_severity_mapping_info(self):
        """Test info severity maps to none level."""
        finding = self._create_sample_finding(severity=Severity.INFO)
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        level = sarif["runs"][0]["results"][0]["level"]

        assert level == "none"

    def test_file_location_mapping(self):
        """Test file-based locations are properly mapped."""
        finding = self._create_sample_finding(file_path="/app/src/handler.py")
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        locations = sarif["runs"][0]["results"][0]["locations"]

        assert len(locations) >= 1
        physical = locations[0].get("physicalLocation", {})
        assert physical.get("artifactLocation", {}).get("uri") == "/app/src/handler.py"

    def test_url_location_mapping(self):
        """Test URL-based locations are properly mapped."""
        finding = self._create_sample_finding(url="https://example.com/api/users")
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        locations = sarif["runs"][0]["results"][0]["locations"]

        assert len(locations) >= 1
        # URL locations use logicalLocations
        logical = locations[0].get("logicalLocations", [])
        assert len(logical) >= 1
        assert "example.com" in logical[0].get("name", "")

    def test_fingerprint_included(self):
        """Test finding fingerprint is included in partialFingerprints."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        fingerprints = sarif["runs"][0]["results"][0]["partialFingerprints"]

        assert "vinculum/fingerprint/v1" in fingerprints
        assert fingerprints["vinculum/fingerprint/v1"] == "abc123"

    def test_properties_include_metadata(self):
        """Test properties include finding metadata."""
        finding = self._create_sample_finding(
            cve_ids=["CVE-2021-44228"],
            cwe_ids=["CWE-502"],
        )
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        properties = sarif["runs"][0]["results"][0]["properties"]

        assert properties["severity"] == "high"
        assert "cveIds" in properties
        assert "CVE-2021-44228" in properties["cveIds"]

    def test_invocation_includes_stats(self):
        """Test invocation includes correlation statistics."""
        findings = [
            self._create_sample_finding(title=f"Finding {i}")
            for i in range(3)
        ]
        result = self._create_sample_result(findings)
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        invocation = sarif["runs"][0]["invocations"][0]

        assert invocation["executionSuccessful"] is True
        assert "properties" in invocation
        assert invocation["properties"]["totalFindings"] == 3

    def test_to_sarif_convenience_function(self):
        """Test the to_sarif convenience function."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])

        sarif_str = to_sarif(result)
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"

    def test_pretty_print_option(self):
        """Test pretty print option."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])

        formatter_pretty = SARIFOutputFormatter(pretty=True)
        formatter_compact = SARIFOutputFormatter(pretty=False)

        pretty_output = formatter_pretty.format(result)
        compact_output = formatter_compact.format(result)

        # Pretty output should have more characters (indentation)
        assert len(pretty_output) > len(compact_output)
        # Both should be valid JSON (timestamps may differ slightly, so just check structure)
        pretty_data = json.loads(pretty_output)
        compact_data = json.loads(compact_output)
        assert pretty_data["version"] == compact_data["version"]
        assert len(pretty_data["runs"]) == len(compact_data["runs"])

    def test_write_creates_file(self, tmp_path):
        """Test write method creates a file."""
        finding = self._create_sample_finding()
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        output_path = tmp_path / "output.sarif"
        formatter.write(result, output_path)

        assert output_path.exists()
        with open(output_path) as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"

    def test_remediation_as_fix(self):
        """Test remediation is included as a fix suggestion."""
        finding = self._create_sample_finding()
        finding.remediation = "Apply proper input validation and output encoding."
        result = self._create_sample_result([finding])
        formatter = SARIFOutputFormatter()

        sarif = json.loads(formatter.format(result))
        fixes = sarif["runs"][0]["results"][0].get("fixes", [])

        assert len(fixes) >= 1
        assert "input validation" in fixes[0]["description"]["text"]
