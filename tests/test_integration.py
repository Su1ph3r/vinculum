"""Integration tests for the full SFCE pipeline."""

import json
from pathlib import Path

import pytest

from vinculum.correlation.engine import correlate_findings
from vinculum.models.enums import Severity
from vinculum.output.ariadne_output import AriadneOutputFormatter
from vinculum.output.json_output import JSONOutputFormatter
from vinculum.parsers.base import ParserRegistry
from vinculum.parsers.burp import BurpParser
from vinculum.parsers.nessus import NessusParser
from vinculum.parsers.reticustos import ReticustosParser
from vinculum.parsers.semgrep import SemgrepParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def setup_parsers():
    """Register parsers before each test."""
    ParserRegistry.clear()
    ParserRegistry.register(BurpParser())
    ParserRegistry.register(NessusParser())
    ParserRegistry.register(SemgrepParser())
    ParserRegistry.register(ReticustosParser())


class TestFullPipeline:
    """Integration tests for full ingestion-correlation-output pipeline."""

    def test_ingest_all_formats(self):
        """Test ingesting all three tool formats."""
        burp_findings = BurpParser().parse(FIXTURES_DIR / "burp_sample.xml")
        nessus_findings = NessusParser().parse(FIXTURES_DIR / "nessus_sample.nessus")
        semgrep_findings = SemgrepParser().parse(FIXTURES_DIR / "semgrep_sample.json")

        all_findings = burp_findings + nessus_findings + semgrep_findings

        assert len(burp_findings) > 0
        assert len(nessus_findings) > 0
        assert len(semgrep_findings) > 0
        assert len(all_findings) == len(burp_findings) + len(nessus_findings) + len(semgrep_findings)

    def test_correlate_mixed_findings(self):
        """Test correlation across different tool outputs."""
        burp_findings = BurpParser().parse(FIXTURES_DIR / "burp_sample.xml")
        nessus_findings = NessusParser().parse(FIXTURES_DIR / "nessus_sample.nessus")
        semgrep_findings = SemgrepParser().parse(FIXTURES_DIR / "semgrep_sample.json")

        all_findings = burp_findings + nessus_findings + semgrep_findings
        result = correlate_findings(all_findings)

        # Should have fewer unique issues than total findings (some dedup expected)
        assert result.unique_count <= result.original_count

        # Should have findings from all tools
        tools = result.by_tool()
        assert "burp" in tools
        assert "nessus" in tools
        assert "semgrep" in tools

    def test_json_output_valid(self):
        """Test that JSON output is valid and contains expected structure."""
        burp_findings = BurpParser().parse(FIXTURES_DIR / "burp_sample.xml")
        result = correlate_findings(burp_findings)

        formatter = JSONOutputFormatter(pretty=True)
        json_str = formatter.format(result)

        # Should be valid JSON
        data = json.loads(json_str)

        # Should have expected structure
        assert "metadata" in data
        assert "summary" in data
        assert "groups" in data

        # Summary should have stats
        assert "total_findings" in data["summary"]
        assert "unique_issues" in data["summary"]
        assert "by_severity" in data["summary"]
        assert "by_tool" in data["summary"]

        # Groups should have findings
        assert len(data["groups"]) > 0
        for group in data["groups"]:
            assert "correlation_id" in group
            assert "findings" in group
            assert len(group["findings"]) > 0

    def test_severity_filtering(self):
        """Test filtering findings by minimum severity."""
        nessus_findings = NessusParser().parse(FIXTURES_DIR / "nessus_sample.nessus")

        # Filter to high severity and above
        high_and_above = [
            f for f in nessus_findings
            if Severity(f.severity).numeric >= Severity.HIGH.numeric
        ]

        assert len(high_and_above) < len(nessus_findings)
        for finding in high_and_above:
            assert Severity(finding.severity).numeric >= Severity.HIGH.numeric

    def test_fingerprints_assigned(self):
        """Test that all findings get fingerprints after correlation."""
        semgrep_findings = SemgrepParser().parse(FIXTURES_DIR / "semgrep_sample.json")
        result = correlate_findings(semgrep_findings)

        for group in result.groups:
            for finding in group.findings:
                assert finding.fingerprint, "Finding should have a fingerprint"
                assert finding.correlation_id, "Finding should have a correlation_id"

    def test_correlation_ids_consistent(self):
        """Test that findings in same group have same correlation_id."""
        burp_findings = BurpParser().parse(FIXTURES_DIR / "burp_sample.xml")
        result = correlate_findings(burp_findings)

        for group in result.groups:
            correlation_ids = {f.correlation_id for f in group.findings}
            assert len(correlation_ids) == 1, "All findings in group should have same correlation_id"


class TestParserAutoDetection:
    """Test automatic parser detection from file contents."""

    def test_detect_burp_xml(self):
        parser = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "burp_sample.xml")
        assert parser is not None
        assert parser.tool_name == "burp"

    def test_detect_nessus(self):
        parser = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "nessus_sample.nessus")
        assert parser is not None
        assert parser.tool_name == "nessus"

    def test_detect_semgrep(self):
        parser = ParserRegistry.get_parser_for_file(FIXTURES_DIR / "semgrep_sample.json")
        assert parser is not None
        assert parser.tool_name == "semgrep"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_findings_list(self):
        """Test correlation with empty list."""
        result = correlate_findings([])
        assert result.unique_count == 0
        assert result.original_count == 0
        assert result.dedup_rate == 0.0

    def test_single_finding(self):
        """Test correlation with single finding."""
        from vinculum.models.finding import UnifiedFinding

        finding = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title="Test Finding",
        )
        result = correlate_findings([finding])

        assert result.unique_count == 1
        assert result.duplicate_count == 0

    def test_json_output_handles_special_chars(self):
        """Test JSON output handles special characters."""
        from vinculum.models.finding import UnifiedFinding

        finding = UnifiedFinding(
            source_tool="test",
            source_id="1",
            title='Test with "quotes" and <brackets>',
            description="Line1\nLine2\tTabbed",
        )
        result = correlate_findings([finding])

        formatter = JSONOutputFormatter()
        json_str = formatter.format(result)

        # Should be valid JSON
        data = json.loads(json_str)
        assert data is not None


class TestReticustosAriadneRoundTrip:
    """Integration test: Reticustos → Vinculum → Ariadne export round-trip."""

    def test_reticustos_to_ariadne_pipeline(self):
        """Parse Reticustos fixture, correlate, export as Ariadne format, validate structure."""
        # Step 1: Parse Reticustos export
        parser = ReticustosParser()
        findings = parser.parse(FIXTURES_DIR / "reticustos_sample.json")
        assert len(findings) > 0

        # Step 2: Correlate findings
        result = correlate_findings(findings)
        assert result.unique_count > 0

        # Step 3: Export as Ariadne format
        formatter = AriadneOutputFormatter(pretty=True)
        ariadne_json = formatter.format(result)

        # Step 4: Validate JSON structure
        data = json.loads(ariadne_json)

        # Top-level schema
        assert data["format"] == "vinculum-ariadne-export"
        assert data["format_version"] == "1.0"
        assert "metadata" in data
        assert "generated_at" in data["metadata"]

        # Hosts extracted from findings
        assert len(data["hosts"]) > 0
        for host in data["hosts"]:
            assert "ip" in host

        # Services extracted from findings
        assert len(data["services"]) > 0
        for service in data["services"]:
            assert "port" in service
            assert "protocol" in service
            assert "host_ip" in service

        # Vulnerabilities (findings with CVEs or non-info DAST/NETWORK)
        assert len(data["vulnerabilities"]) > 0
        for vuln in data["vulnerabilities"]:
            assert "title" in vuln
            assert "severity" in vuln
            assert "vinculum_metadata" in vuln
            meta = vuln["vinculum_metadata"]
            assert "correlation_id" in meta
            assert "fingerprint" in meta
            assert "source_tools" in meta

        # Misconfigurations (info-level without CVE)
        # Our fixture has info-level findings that should be misconfigs
        assert "misconfigurations" in data

        # Relationships
        assert len(data["relationships"]) > 0
        rel_types = {r["relation_type"] for r in data["relationships"]}
        assert "runs_on" in rel_types

        # Verify host IPs from the fixture appear in the output
        host_ips = {h["ip"] for h in data["hosts"]}
        assert "192.168.1.10" in host_ips
        assert "192.168.1.20" in host_ips

    def test_reticustos_to_ariadne_write_file(self, tmp_path):
        """Test full pipeline with file output."""
        parser = ReticustosParser()
        findings = parser.parse(FIXTURES_DIR / "reticustos_sample.json")
        result = correlate_findings(findings)

        output_path = tmp_path / "vinculum_ariadne_out.json"
        formatter = AriadneOutputFormatter(pretty=True)
        formatter.write(result, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["format"] == "vinculum-ariadne-export"
        assert len(data["vulnerabilities"]) + len(data["misconfigurations"]) > 0
