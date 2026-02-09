"""Ariadne knowledge-graph output formatter for correlation results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vinculum import __version__
from vinculum.correlation.engine import CorrelationResult
from vinculum.models.enums import FindingType, Severity
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


class AriadneOutputFormatter:
    """
    Format correlation results for ingestion by Ariadne knowledge-graph builder.

    Produces a structured JSON document with hosts, services, vulnerabilities,
    misconfigurations, and relationships suitable for graph construction.
    """

    def __init__(self, pretty: bool = True, include_raw: bool = False):
        self.pretty = pretty
        self.include_raw = include_raw

    def format(self, result: CorrelationResult) -> str:
        """Format correlation result as Ariadne-compatible JSON string."""
        data = self._build_output(result)
        if self.pretty:
            return json.dumps(data, indent=2, default=self._json_serializer)
        return json.dumps(data, default=self._json_serializer)

    def write(self, result: CorrelationResult, output_path: Path) -> None:
        """Write correlation result to an Ariadne JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(self.format(result))

    def _build_output(self, result: CorrelationResult) -> dict[str, Any]:
        """Build the Ariadne export structure."""
        hosts: dict[str, dict[str, Any]] = {}
        services: dict[str, dict[str, Any]] = {}
        vulnerabilities: list[dict[str, Any]] = []
        misconfigurations: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        # Track service keys for relationship building
        service_keys_for_host: dict[str, list[str]] = {}

        for group in result.groups:
            if not group.primary_finding:
                continue

            primary = group.primary_finding

            # Extract hosts and services from all findings in the group
            for finding in group.findings:
                loc = finding.location
                host_ip = loc.host

                if host_ip and host_ip not in hosts:
                    hosts[host_ip] = {
                        "ip": host_ip,
                        "hostname": None,
                        "os": None,
                    }

                if host_ip and loc.port:
                    svc_key = f"{host_ip}:{loc.port}/{loc.protocol or 'tcp'}"
                    if svc_key not in services:
                        services[svc_key] = {
                            "port": loc.port,
                            "protocol": loc.protocol or "tcp",
                            "name": loc.service,
                            "product": None,
                            "version": None,
                            "host_ip": host_ip,
                        }
                        service_keys_for_host.setdefault(host_ip, []).append(svc_key)

            # Classify finding as vulnerability or misconfiguration
            is_vulnerability = self._is_vulnerability(primary)

            entry = self._build_finding_entry(primary, group)

            if is_vulnerability:
                vulnerabilities.append(entry)
            else:
                misconfigurations.append(entry)

        # Build relationships
        # Service → Host (runs_on)
        for host_ip, svc_keys in service_keys_for_host.items():
            for svc_key in svc_keys:
                relationships.append({
                    "source_type": "service",
                    "source_key": svc_key,
                    "target_type": "host",
                    "target_key": host_ip,
                    "relation_type": "runs_on",
                })

        # Finding → Host/Service relationships
        for group in result.groups:
            if not group.primary_finding:
                continue

            primary = group.primary_finding
            loc = primary.location
            host_ip = loc.host
            is_vuln = self._is_vulnerability(primary)
            finding_type_label = "vulnerability" if is_vuln else "misconfiguration"
            relation_type = "has_vulnerability" if is_vuln else "has_misconfiguration"
            finding_key = self._finding_key(primary, group)

            if host_ip and loc.port:
                svc_key = f"{host_ip}:{loc.port}/{loc.protocol or 'tcp'}"
                relationships.append({
                    "source_type": "service",
                    "source_key": svc_key,
                    "target_type": finding_type_label,
                    "target_key": finding_key,
                    "relation_type": relation_type,
                })
            elif host_ip:
                relationships.append({
                    "source_type": "host",
                    "source_key": host_ip,
                    "target_type": finding_type_label,
                    "target_key": finding_key,
                    "relation_type": relation_type,
                })

        return {
            "format": "vinculum-ariadne-export",
            "format_version": "1.0",
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "vinculum_version": __version__,
            },
            "hosts": list(hosts.values()),
            "services": list(services.values()),
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "relationships": relationships,
        }

    def _is_vulnerability(self, finding: UnifiedFinding) -> bool:
        """Determine if a finding is a vulnerability or misconfiguration."""
        # Findings with CVEs are vulnerabilities
        if finding.cve_ids:
            return True
        # DAST and NETWORK type findings are vulnerabilities (unless info-level without CVE)
        sev = Severity(finding.severity) if isinstance(finding.severity, str) else finding.severity
        finding_type = FindingType(finding.finding_type) if isinstance(finding.finding_type, str) else finding.finding_type
        if finding_type in (FindingType.DAST, FindingType.NETWORK) and sev != Severity.INFO:
            return True
        # Info-level without CVE → misconfiguration
        return False

    def _build_finding_entry(
        self, primary: UnifiedFinding, group: CorrelationGroup
    ) -> dict[str, Any]:
        """Build a vulnerability or misconfiguration entry."""
        loc = primary.location

        entry: dict[str, Any] = {
            "title": primary.title,
            "severity": str(primary.severity),
            "host_ip": loc.host,
            "port": loc.port,
            "protocol": loc.protocol or "tcp",
            "vinculum_metadata": {
                "correlation_id": group.correlation_id,
                "fingerprint": primary.fingerprint,
                "source_tools": list(group.tool_sources),
                "finding_count": len(group.findings),
                "epss_score": primary.epss_score,
                "epss_percentile": primary.epss_percentile,
            },
        }

        if primary.cve_ids:
            entry["cve_id"] = primary.cve_ids[0]
        if primary.cvss_score is not None:
            entry["cvss_score"] = primary.cvss_score

        if self._is_vulnerability(primary):
            # Vulnerability-specific fields
            pass
        else:
            # Misconfiguration-specific fields
            entry["check_id"] = primary.source_id
            entry["remediation"] = primary.remediation

        if primary.description:
            entry["description"] = primary.description

        if self.include_raw:
            entry["raw_data"] = primary.raw_data

        return entry

    def _finding_key(self, finding: UnifiedFinding, group: CorrelationGroup) -> str:
        """Generate a key for a finding in relationships."""
        if finding.cve_ids:
            host_ip = finding.location.host or "unknown"
            return f"{finding.cve_ids[0]}:{host_ip}"
        return group.correlation_id

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_ariadne(
    result: CorrelationResult, pretty: bool = True, include_raw: bool = False
) -> str:
    """Convenience function to format result as Ariadne export."""
    formatter = AriadneOutputFormatter(pretty=pretty, include_raw=include_raw)
    return formatter.format(result)
