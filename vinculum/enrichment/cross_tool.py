"""Cross-tool enrichment, confidence boosting, and provenance chain building."""

from typing import Any

from vinculum.correlation.engine import CorrelationResult
from vinculum.models.enums import Confidence
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


# Ordered provenance stages: tool → role in the pipeline
PROVENANCE_ORDER = [
    ("reticustos", "discovered"),
    ("indago", "tested"),
    ("bypassburrito", "bypass_confirmed"),
    ("nubicustos", "cloud_context"),
    ("cepheus", "escape_analyzed"),
]


class CrossToolEnricher:
    """
    Enriches correlation results with cross-tool intelligence.

    Performs three passes:
    1. Link related findings across tools (Indago↔BypassBurrito, Indago↔Reticustos,
       Cepheus↔Nubicustos)
    2. Boost confidence when multiple tools confirm the same issue
    3. Build provenance chains showing the ordered tool pipeline per group
    """

    def enrich(self, result: CorrelationResult) -> CorrelationResult:
        """Run all enrichment passes on the correlation result."""
        for group in result.groups:
            self._link_cross_tool(group)
            self._boost_confidence(group)
            self._build_provenance_chain(group)
        return result

    def _link_cross_tool(self, group: CorrelationGroup) -> None:
        """Link findings across tool boundaries within a correlation group."""
        tools_in_group = {f.source_tool for f in group.findings}

        # Link Indago ↔ BypassBurrito: match by endpoint URL + parameter
        if "indago" in tools_in_group and "bypassburrito" in tools_in_group:
            self._link_indago_burrito(group)

        # Link Indago ↔ Reticustos: enrich with service/version info
        if "indago" in tools_in_group and "reticustos" in tools_in_group:
            self._link_indago_reticustos(group)

        # Link Cepheus ↔ Nubicustos: enrich container escapes with cloud context
        if "cepheus" in tools_in_group and "nubicustos" in tools_in_group:
            self._link_cepheus_nubicustos(group)

    def _link_indago_burrito(self, group: CorrelationGroup) -> None:
        """Match Indago and BypassBurrito findings by endpoint URL + parameter."""
        indago_findings = [f for f in group.findings if f.source_tool == "indago"]
        burrito_findings = [f for f in group.findings if f.source_tool == "bypassburrito"]

        # Index burrito findings by endpoint+parameter (keep all per key)
        burrito_index: dict[str, list[UnifiedFinding]] = {}
        for bf in burrito_findings:
            key = self._endpoint_key(bf)
            if key:
                burrito_index.setdefault(key, []).append(bf)

        for inf in indago_findings:
            key = self._endpoint_key(inf)
            if key and key in burrito_index:
                # Mark exploitation confirmed if any bypass was found
                for bf in burrito_index[key]:
                    if bf.raw_data.get("successful_bypass", {}).get("found", False):
                        inf.exploitation_confirmed = True
                        if "bypassburrito" not in inf.confirmed_by:
                            inf.confirmed_by.append("bypassburrito")
                        break

    def _link_indago_reticustos(self, group: CorrelationGroup) -> None:
        """Enrich Indago findings with Reticustos service/version info."""
        retic_findings = [f for f in group.findings if f.source_tool == "reticustos"]

        # Build host:port → service info index
        service_index: dict[str, dict[str, Any]] = {}
        for rf in retic_findings:
            loc = rf.location
            if loc.host and loc.port:
                key = f"{loc.host}:{loc.port}"
                service_index[key] = {
                    "service": loc.service,
                    "host": loc.host,
                    "port": loc.port,
                }

        # Enrich Indago findings
        for f in group.findings:
            if f.source_tool == "indago" and f.location.host and f.location.port:
                key = f"{f.location.host}:{f.location.port}"
                if key in service_index:
                    svc_info = service_index[key]
                    if svc_info.get("service") and not f.location.service:
                        f.location.service = svc_info["service"]

    def _link_cepheus_nubicustos(self, group: CorrelationGroup) -> None:
        """Enrich Cepheus container escapes with Nubicustos cloud resource context."""
        nubi_findings = [f for f in group.findings if f.source_tool == "nubicustos"]
        cepheus_findings = [f for f in group.findings if f.source_tool == "cepheus"]

        if not nubi_findings or not cepheus_findings:
            return

        # Collect cloud context from nubicustos
        cloud_context = []
        for nf in nubi_findings:
            cloud_context.append({
                "resource_id": nf.raw_data.get("resource_id"),
                "resource_type": nf.raw_data.get("resource_type"),
                "cloud_provider": nf.raw_data.get("cloud_provider"),
                "region": nf.raw_data.get("region"),
            })

        # Attach cloud context to cepheus findings
        for cf in cepheus_findings:
            if cloud_context:
                cf.raw_data["cloud_context"] = cloud_context

    def _boost_confidence(self, group: CorrelationGroup) -> None:
        """Boost confidence when multiple tools confirm the same issue."""
        tool_sources = {f.source_tool for f in group.findings}

        if len(tool_sources) < 2:
            return

        for finding in group.findings:
            # Boost to CERTAIN when 2+ tools confirm
            finding.confidence = Confidence.CERTAIN
            # Populate confirmed_by with other tools
            other_tools = tool_sources - {finding.source_tool}
            for tool in sorted(other_tools):
                if tool not in finding.confirmed_by:
                    finding.confirmed_by.append(tool)

    def _build_provenance_chain(self, group: CorrelationGroup) -> None:
        """Build an ordered provenance chain showing tool pipeline contribution."""
        tool_sources = {f.source_tool for f in group.findings}

        chain: list[dict[str, Any]] = []
        for tool, role in PROVENANCE_ORDER:
            if tool in tool_sources:
                chain.append({"tool": tool, "role": role})

        # Add any tools not in the standard order
        standard_tools = {t for t, _ in PROVENANCE_ORDER}
        for tool in sorted(tool_sources - standard_tools):
            chain.append({"tool": tool, "role": "detected"})

        group.provenance_chain = chain

    @staticmethod
    def _endpoint_key(finding: UnifiedFinding) -> str | None:
        """Generate endpoint key for matching: url+parameter."""
        loc = finding.location
        if loc.url:
            param = loc.parameter or ""
            return f"{loc.url}|{param}"
        return None
