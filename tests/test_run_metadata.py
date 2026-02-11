"""Tests for pipeline run metadata (--run-id) support."""

import json

from vinculum.correlation.engine import CorrelationResult, correlate_findings
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import CorrelationGroup, FindingLocation, UnifiedFinding
from vinculum.output.ariadne_output import AriadneOutputFormatter
from vinculum.output.console_output import ConsoleOutputFormatter
from vinculum.output.json_output import JSONOutputFormatter
from vinculum.output.sarif_output import SARIFOutputFormatter


def _make_finding(**overrides) -> UnifiedFinding:
    defaults = {
        "source_tool": "test",
        "source_id": "t-001",
        "title": "Test Finding",
        "severity": Severity.HIGH,
        "confidence": Confidence.FIRM,
        "finding_type": FindingType.DAST,
        "location": FindingLocation(host="10.0.0.1", port=443),
    }
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


def _make_result(metadata=None) -> CorrelationResult:
    findings = [_make_finding()]
    return correlate_findings(findings, metadata=metadata)


class TestCorrelationResultMetadata:
    def test_metadata_defaults_to_empty_dict(self):
        result = _make_result()
        assert result.metadata == {}

    def test_metadata_stores_run_id(self):
        result = _make_result(metadata={"run_id": "run-123"})
        assert result.metadata["run_id"] == "run-123"

    def test_metadata_preserved_through_correlate_findings(self):
        findings = [_make_finding()]
        result = correlate_findings(findings, metadata={"run_id": "abc", "extra": 42})
        assert result.metadata["run_id"] == "abc"
        assert result.metadata["extra"] == 42

    def test_metadata_none_becomes_empty_dict(self):
        result = CorrelationResult(groups=[], original_count=0, metadata=None)
        assert result.metadata == {}


class TestJSONOutputRunId:
    def test_run_id_in_json_metadata(self):
        result = _make_result(metadata={"run_id": "run-456"})
        formatter = JSONOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        assert output["metadata"]["run_id"] == "run-456"

    def test_no_run_id_when_absent(self):
        result = _make_result()
        formatter = JSONOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        assert "run_id" not in output["metadata"]


class TestAriadneOutputRunId:
    def test_run_id_in_ariadne_metadata(self):
        result = _make_result(metadata={"run_id": "run-789"})
        formatter = AriadneOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        assert output["metadata"]["run_id"] == "run-789"

    def test_no_run_id_when_absent(self):
        result = _make_result()
        formatter = AriadneOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        assert "run_id" not in output["metadata"]


class TestSARIFOutputRunId:
    def test_run_id_in_sarif_invocation_properties(self):
        result = _make_result(metadata={"run_id": "run-sarif-001"})
        formatter = SARIFOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        invocation = output["runs"][0]["invocations"][0]
        assert invocation["properties"]["runId"] == "run-sarif-001"

    def test_no_run_id_when_absent(self):
        result = _make_result()
        formatter = SARIFOutputFormatter(pretty=True)
        output = json.loads(formatter.format(result))
        invocation = output["runs"][0]["invocations"][0]
        assert "runId" not in invocation["properties"]


class TestConsoleOutputRunId:
    def test_run_id_displayed_in_console(self, capsys):
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO())
        result = _make_result(metadata={"run_id": "run-console-001"})
        formatter = ConsoleOutputFormatter(console=console, verbose=False)
        # Should not raise
        formatter.print(result)
