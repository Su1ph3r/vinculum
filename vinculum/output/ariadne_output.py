"""Ariadne knowledge-graph output formatter for correlation results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vinculum import __version__
from vinculum.correlation.engine import CorrelationResult
from vinculum.models.enums import Confidence, FindingType, Severity
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

        # New v1.1 entity collections
        cloud_resources: dict[str, dict[str, Any]] = {}
        containers: dict[str, dict[str, Any]] = {}
        mobile_apps: dict[str, dict[str, Any]] = {}
        api_endpoints: dict[str, dict[str, Any]] = {}

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
                finding_type = FindingType(finding.finding_type) if isinstance(finding.finding_type, str) else finding.finding_type

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

                # Extract cloud resources from CLOUD findings
                if finding_type == FindingType.CLOUD:
                    self._extract_cloud_resource(finding, cloud_resources)

                # Extract containers from Cepheus findings
                if finding.source_tool == "cepheus" and finding_type == FindingType.CONTAINER:
                    self._extract_container(finding, containers)

                # Extract mobile apps from Mobilicustos findings
                if finding.source_tool == "mobilicustos":
                    self._extract_mobile_app(finding, mobile_apps)

                # Extract API endpoints from Indago findings
                if finding.source_tool == "indago" and finding_type == FindingType.DAST:
                    self._extract_api_endpoint(finding, api_endpoints)

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

        # Finding → Host/Service relationships + new entity relationships
        for group in result.groups:
            if not group.primary_finding:
                continue

            primary = group.primary_finding
            loc = primary.location
            host_ip = loc.host
            is_vuln = self._is_vulnerability(primary)
            finding_type_label = "vulnerability" if is_vuln else "misconfiguration"
            finding_key = self._finding_key(primary, group)

            # Determine relation type based on finding type
            relation_type = self._relation_type_for_finding(primary, is_vuln)

            # Confidence weights for this relationship
            rel_confidence = self._relationship_confidence(group)
            evidence = self._evidence_strength(group)
            confirmed = sorted(
                {t for f in group.findings for t in f.confirmed_by}
            )

            rel_extra = {
                "confidence": rel_confidence,
                "evidence_strength": evidence,
            }
            if confirmed:
                rel_extra["confirmed_by"] = confirmed

            if host_ip and loc.port:
                svc_key = f"{host_ip}:{loc.port}/{loc.protocol or 'tcp'}"
                relationships.append({
                    "source_type": "service",
                    "source_key": svc_key,
                    "target_type": finding_type_label,
                    "target_key": finding_key,
                    "relation_type": relation_type,
                    **rel_extra,
                })
            elif host_ip:
                relationships.append({
                    "source_type": "host",
                    "source_key": host_ip,
                    "target_type": finding_type_label,
                    "target_key": finding_key,
                    "relation_type": relation_type,
                    **rel_extra,
                })

        metadata: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "vinculum_version": __version__,
        }
        if result.metadata.get("run_id"):
            metadata["run_id"] = result.metadata["run_id"]

        return {
            "format": "vinculum-ariadne-export",
            "format_version": "1.1",
            "metadata": metadata,
            "hosts": list(hosts.values()),
            "services": list(services.values()),
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "cloud_resources": list(cloud_resources.values()),
            "containers": list(containers.values()),
            "mobile_apps": list(mobile_apps.values()),
            "api_endpoints": list(api_endpoints.values()),
            "relationships": relationships,
        }

    def _relationship_confidence(self, group: CorrelationGroup) -> str:
        """Determine relationship confidence based on tool sources and finding confidence."""
        tool_count = len(group.tool_sources)
        # Check if any finding has CERTAIN confidence
        has_certain = any(
            f.confidence in ("certain", Confidence.CERTAIN) for f in group.findings
        )
        if tool_count >= 2 or has_certain:
            return "certain"
        has_firm = any(
            f.confidence in ("firm", Confidence.FIRM) for f in group.findings
        )
        if has_firm:
            return "firm"
        return "tentative"

    def _evidence_strength(self, group: CorrelationGroup) -> float:
        """
        Calculate evidence strength as a 0.0-1.0 float.

        Components:
        - Multi-tool: +0.25 per tool, capped at 0.5
        - CVE presence: +0.2
        - Exploitation confirmed: +0.3
        """
        strength = 0.0

        # Multi-tool contribution
        tool_count = len(group.tool_sources)
        strength += min(tool_count * 0.25, 0.5)

        # CVE presence
        if group.all_cves:
            strength += 0.2

        # Exploitation confirmed
        if any(f.exploitation_confirmed for f in group.findings):
            strength += 0.3

        return round(min(strength, 1.0), 2)

    def _relation_type_for_finding(self, finding: UnifiedFinding, is_vuln: bool) -> str:
        """Determine the relationship type based on finding type."""
        finding_type = FindingType(finding.finding_type) if isinstance(finding.finding_type, str) else finding.finding_type

        if finding_type == FindingType.CLOUD:
            return "has_cloud_vulnerability"
        if finding_type == FindingType.CONTAINER and finding.source_tool == "cepheus":
            return "has_container_escape"
        if finding.source_tool == "mobilicustos":
            return "has_mobile_vulnerability"
        if finding.source_tool == "indago":
            return "has_api_vulnerability"
        if is_vuln:
            return "has_vulnerability"
        return "has_misconfiguration"

    def _extract_cloud_resource(
        self, finding: UnifiedFinding, cloud_resources: dict[str, dict[str, Any]]
    ) -> None:
        """Extract cloud resource entity from a CLOUD finding."""
        raw = finding.raw_data
        resource_id = raw.get("resource_id") or finding.location.host
        if not resource_id or resource_id in cloud_resources:
            return

        cloud_resources[resource_id] = {
            "resource_id": resource_id,
            "resource_type": raw.get("resource_type"),
            "resource_name": raw.get("resource_name"),
            "cloud_provider": raw.get("cloud_provider"),
            "region": raw.get("region"),
        }

    def _extract_container(
        self, finding: UnifiedFinding, containers: dict[str, dict[str, Any]]
    ) -> None:
        """Extract container entity from a Cepheus finding."""
        raw = finding.raw_data
        chain = raw.get("chain", {})
        container = chain.get("container", {})
        container_id = container.get("container_id")
        if not container_id or container_id in containers:
            return

        containers[container_id] = {
            "container_id": container_id,
            "hostname": container.get("hostname"),
            "runtime": container.get("runtime"),
            "namespace": container.get("namespace"),
            "image": container.get("image"),
        }

    def _extract_mobile_app(
        self, finding: UnifiedFinding, mobile_apps: dict[str, dict[str, Any]]
    ) -> None:
        """Extract mobile app entity from a Mobilicustos finding."""
        raw = finding.raw_data
        app_id = raw.get("app_id")
        if not app_id or app_id in mobile_apps:
            return

        # Extract app metadata from tags and raw_data
        platform = None
        package_name = None
        app_name = None
        for tag in finding.tags:
            if tag.startswith("platform:"):
                platform = tag.split(":", 1)[1]
            elif tag.startswith("package:"):
                package_name = tag.split(":", 1)[1]
            elif tag.startswith("app_name:"):
                app_name = tag.split(":", 1)[1]

        # Fall back to _app_info in raw_data
        app_info = raw.get("_app_info", {})
        if not app_name:
            app_name = app_info.get("app_name")

        mobile_apps[app_id] = {
            "app_id": app_id,
            "platform": platform,
            "package_name": package_name,
            "app_name": app_name,
        }

    def _extract_api_endpoint(
        self, finding: UnifiedFinding, api_endpoints: dict[str, dict[str, Any]]
    ) -> None:
        """Extract API endpoint entity from an Indago finding."""
        loc = finding.location
        url = loc.url
        if not url:
            return

        endpoint_key = f"{loc.method or 'GET'}:{url}"
        if endpoint_key in api_endpoints:
            return

        api_endpoints[endpoint_key] = {
            "url": url,
            "method": loc.method,
            "parameters": [loc.parameter] if loc.parameter else [],
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
