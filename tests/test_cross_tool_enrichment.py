"""Tests for cross-tool enrichment, confidence boosting, and provenance chains."""

from vinculum.correlation.engine import CorrelationResult, correlate_findings
from vinculum.enrichment.cross_tool import CrossToolEnricher
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import CorrelationGroup, FindingLocation, UnifiedFinding


def _make_finding(**overrides) -> UnifiedFinding:
    defaults = {
        "source_tool": "test",
        "source_id": "t-001",
        "title": "Test Finding",
        "severity": Severity.HIGH,
        "confidence": Confidence.TENTATIVE,
        "finding_type": FindingType.DAST,
        "location": FindingLocation(host="10.0.0.1", port=443),
    }
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


def _make_group(findings: list[UnifiedFinding]) -> CorrelationGroup:
    group = CorrelationGroup()
    for f in findings:
        group.add_finding(f)
    return group


def _make_result(groups: list[CorrelationGroup]) -> CorrelationResult:
    total = sum(len(g.findings) for g in groups)
    return CorrelationResult(groups=groups, original_count=total)


class TestConfidenceBoosting:
    def test_multi_tool_boosts_to_certain(self):
        f1 = _make_finding(source_tool="indago", source_id="i-1", title="SQLi",
                           confidence=Confidence.TENTATIVE)
        f2 = _make_finding(source_tool="burp", source_id="b-1", title="SQLi",
                           confidence=Confidence.TENTATIVE)
        group = _make_group([f1, f2])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert f1.confidence == Confidence.CERTAIN
        assert f2.confidence == Confidence.CERTAIN

    def test_confirmed_by_populated(self):
        f1 = _make_finding(source_tool="indago", source_id="i-1", title="SQLi")
        f2 = _make_finding(source_tool="burp", source_id="b-1", title="SQLi")
        group = _make_group([f1, f2])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert "burp" in f1.confirmed_by
        assert "indago" in f2.confirmed_by

    def test_single_tool_no_boost(self):
        f1 = _make_finding(source_tool="indago", source_id="i-1",
                           confidence=Confidence.TENTATIVE)
        group = _make_group([f1])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert f1.confidence == Confidence.TENTATIVE
        assert f1.confirmed_by == []


class TestIndagoBurritoLink:
    def test_exploitation_confirmed_on_bypass(self):
        indago_f = _make_finding(
            source_tool="indago", source_id="i-1", title="SQLi",
            location=FindingLocation(
                url="https://api.example.com/search", parameter="q",
                host="api.example.com", port=443
            ),
        )
        burrito_f = _make_finding(
            source_tool="bypassburrito", source_id="bb-1", title="SQLi bypass",
            location=FindingLocation(
                url="https://api.example.com/search", parameter="q",
                host="api.example.com", port=443
            ),
            raw_data={"successful_bypass": {"found": True}},
        )
        group = _make_group([indago_f, burrito_f])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert indago_f.exploitation_confirmed is True
        assert "bypassburrito" in indago_f.confirmed_by

    def test_no_exploitation_on_failed_bypass(self):
        indago_f = _make_finding(
            source_tool="indago", source_id="i-1", title="SQLi",
            location=FindingLocation(
                url="https://api.example.com/search", parameter="q",
                host="api.example.com", port=443
            ),
        )
        burrito_f = _make_finding(
            source_tool="bypassburrito", source_id="bb-1", title="SQLi attempt",
            location=FindingLocation(
                url="https://api.example.com/search", parameter="q",
                host="api.example.com", port=443
            ),
            raw_data={"successful_bypass": {"found": False}},
        )
        group = _make_group([indago_f, burrito_f])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert indago_f.exploitation_confirmed is False


class TestIndagoReticustosLink:
    def test_service_info_enriched(self):
        retic_f = _make_finding(
            source_tool="reticustos", source_id="r-1", title="Port scan",
            location=FindingLocation(
                host="10.0.0.1", port=443, service="https"
            ),
        )
        indago_f = _make_finding(
            source_tool="indago", source_id="i-1", title="SQLi",
            location=FindingLocation(
                host="10.0.0.1", port=443
            ),
        )
        group = _make_group([retic_f, indago_f])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert indago_f.location.service == "https"


class TestCepheusNubicustosLink:
    def test_cloud_context_attached(self):
        cepheus_f = _make_finding(
            source_tool="cepheus", source_id="c-1", title="Container escape",
            finding_type=FindingType.CONTAINER,
            raw_data={"chain": {"container": {"container_id": "abc123"}}},
        )
        nubi_f = _make_finding(
            source_tool="nubicustos", source_id="n-1", title="Public S3",
            finding_type=FindingType.CLOUD,
            raw_data={
                "resource_id": "arn:aws:s3:::bucket",
                "resource_type": "s3_bucket",
                "cloud_provider": "aws",
                "region": "us-east-1",
            },
        )
        group = _make_group([cepheus_f, nubi_f])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert "cloud_context" in cepheus_f.raw_data
        ctx = cepheus_f.raw_data["cloud_context"]
        assert len(ctx) == 1
        assert ctx[0]["cloud_provider"] == "aws"


class TestProvenanceChain:
    def test_ordered_chain_built(self):
        f1 = _make_finding(source_tool="reticustos", source_id="r-1")
        f2 = _make_finding(source_tool="indago", source_id="i-1")
        f3 = _make_finding(source_tool="bypassburrito", source_id="bb-1")
        group = _make_group([f1, f2, f3])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        chain = group.provenance_chain
        assert len(chain) == 3
        assert chain[0] == {"tool": "reticustos", "role": "discovered"}
        assert chain[1] == {"tool": "indago", "role": "tested"}
        assert chain[2] == {"tool": "bypassburrito", "role": "bypass_confirmed"}

    def test_non_standard_tools_appended(self):
        f1 = _make_finding(source_tool="burp", source_id="b-1")
        f2 = _make_finding(source_tool="indago", source_id="i-1")
        group = _make_group([f1, f2])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        chain = group.provenance_chain
        tools = [c["tool"] for c in chain]
        assert "indago" in tools
        assert "burp" in tools
        # burp should be after standard tools
        indago_idx = tools.index("indago")
        burp_idx = tools.index("burp")
        assert burp_idx > indago_idx

    def test_single_tool_chain(self):
        f1 = _make_finding(source_tool="indago", source_id="i-1")
        group = _make_group([f1])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert group.provenance_chain == [{"tool": "indago", "role": "tested"}]

    def test_empty_group_no_chain(self):
        group = CorrelationGroup()
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        assert group.provenance_chain == []


class TestEnrichNoOp:
    def test_no_relevant_tools_is_noop(self):
        f1 = _make_finding(source_tool="semgrep", source_id="s-1",
                           confidence=Confidence.TENTATIVE)
        group = _make_group([f1])
        result = _make_result([group])

        CrossToolEnricher().enrich(result)

        # No cross-tool linking, no confidence boost (single tool)
        assert f1.confidence == Confidence.TENTATIVE
        assert f1.exploitation_confirmed is False
        assert f1.confirmed_by == []
