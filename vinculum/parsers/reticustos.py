"""Parser for Reticustos JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.reticustos")

# Tools that produce network-level findings
NETWORK_TOOLS = {"nmap", "masscan", "shodan"}
# Tools that produce DAST findings
DAST_TOOLS = {"nuclei", "nikto"}
# Tools that produce SSL/TLS findings
SSL_TOOLS = {"testssl"}


class ReticustosParser(BaseParser):
    """
    Parser for Reticustos orchestrator JSON export format.

    Reticustos orchestrates multiple scanners (Nmap, Nuclei, testssl, Nikto,
    Masscan, Shodan) and exports consolidated results with host/service context.
    """

    @property
    def tool_name(self) -> str:
        return "reticustos"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Reticustos export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return "export_metadata" in data and "findings" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Reticustos JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if "export_metadata" not in data or "findings" not in data:
            raise ParseError("Not a valid Reticustos export", file_path)

        # Build lookup dicts for host and service context
        hosts = {h["ip"]: h for h in data.get("hosts", [])}
        services = {}
        for svc in data.get("services", []):
            key = (svc["host_ip"], svc["port"], svc.get("protocol", "tcp"))
            services[key] = svc

        findings = []

        # Parse scanner findings
        for raw_finding in data.get("findings", []):
            if raw_finding.get("status") == "false_positive":
                logger.debug(f"Skipping false positive: {raw_finding.get('title')}")
                continue

            finding = self._parse_finding(raw_finding, hosts, services)
            if finding:
                findings.append(finding)

        # Parse SSL analyses into findings
        for ssl_analysis in data.get("ssl_analyses", []):
            ssl_findings = self._parse_ssl_analysis(ssl_analysis)
            findings.extend(ssl_findings)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_finding(
        self,
        raw: dict[str, Any],
        hosts: dict[str, dict],
        services: dict[tuple, dict],
    ) -> UnifiedFinding | None:
        """Parse a single Reticustos finding."""
        tool = raw.get("tool", "unknown")
        source_tool = f"reticustos:{tool}"

        # Map severity
        severity = self._map_severity(raw.get("severity", "info"))

        # Map confidence
        confidence = Confidence.from_string(raw.get("confidence", "tentative"))

        # Build location
        host_ip = raw.get("host_ip")
        port = raw.get("port")
        protocol = raw.get("protocol")
        hostname = raw.get("hostname")
        url = raw.get("url")

        # Enrich with service info
        service_name = None
        if host_ip and port:
            svc_key = (host_ip, port, protocol or "tcp")
            svc = services.get(svc_key)
            if svc:
                service_name = svc.get("name")

        location = FindingLocation(
            url=url,
            host=host_ip or hostname,
            port=port,
            protocol=protocol,
            service=service_name,
        )

        # Extract CVEs
        cve_ids = []
        if raw.get("cve_id"):
            cve_ids.append(raw["cve_id"])
        if raw.get("cve_ids"):
            cve_ids.extend(raw["cve_ids"])
        cve_ids = list(set(cve_ids))

        # Extract CWEs
        cwe_ids = []
        if raw.get("cwe_id"):
            cwe_ids.append(raw["cwe_id"])
        cwe_ids = list(set(cwe_ids))

        # Determine finding type
        finding_type = self._determine_finding_type(tool)

        # Build tags
        tags = list(raw.get("tags", []))

        # Add MITRE tags
        mitre = raw.get("mitre")
        if mitre:
            for tactic in mitre.get("tactics", []):
                tags.append(f"mitre:tactic:{tactic}")
            for technique in mitre.get("techniques", []):
                tags.append(f"mitre:technique:{technique}")

        # CVSS score
        cvss_score = raw.get("cvss_score")

        return UnifiedFinding(
            source_tool=source_tool,
            source_id=raw.get("id", ""),
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            location=location,
            finding_type=finding_type,
            evidence=raw.get("evidence"),
            remediation=raw.get("remediation"),
            references=raw.get("references", []),
            tags=tags,
            raw_data=raw,
        )

    def _parse_ssl_analysis(self, ssl: dict[str, Any]) -> list[UnifiedFinding]:
        """Parse SSL/TLS analysis into individual findings for actual issues."""
        findings = []
        host_ip = ssl.get("host_ip")
        port = ssl.get("port", 443)
        hostname = ssl.get("hostname")

        base_location = FindingLocation(
            host=host_ip or hostname,
            port=port,
            protocol="tcp",
            service="https",
        )

        # Check for expired certificate
        cert = ssl.get("certificate", {})
        if cert.get("expired"):
            days = cert.get("days_until_expiry", 0)
            findings.append(UnifiedFinding(
                source_tool="reticustos:testssl",
                source_id=f"ssl-expired-{host_ip}:{port}",
                title="SSL Certificate Expired",
                description=f"The SSL certificate for {hostname or host_ip} has expired ({abs(days)} days ago).",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                cwe_ids=["CWE-295"],
                location=base_location,
                finding_type=FindingType.OTHER,
                evidence=f"Subject: {cert.get('subject', 'N/A')}, Expired: {cert.get('not_after', 'N/A')}",
                remediation="Renew the SSL certificate immediately.",
                tags=["ssl", "certificate", "expired"],
                raw_data=ssl,
            ))

        # Check for weak protocols (TLSv1.0, TLSv1.1, SSLv3)
        protocols = ssl.get("protocols", {})
        weak_protocols = []
        if protocols.get("SSLv3"):
            weak_protocols.append("SSLv3")
        if protocols.get("TLSv1.0"):
            weak_protocols.append("TLSv1.0")
        if protocols.get("TLSv1.1"):
            weak_protocols.append("TLSv1.1")

        if weak_protocols:
            findings.append(UnifiedFinding(
                source_tool="reticustos:testssl",
                source_id=f"ssl-weak-proto-{host_ip}:{port}",
                title="Weak TLS/SSL Protocols Enabled",
                description=f"Weak protocols enabled: {', '.join(weak_protocols)}.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                cwe_ids=["CWE-326"],
                location=base_location,
                finding_type=FindingType.OTHER,
                evidence=f"Weak protocols: {', '.join(weak_protocols)}",
                remediation="Disable SSLv3, TLSv1.0, and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                tags=["ssl", "weak-protocol"],
                raw_data=ssl,
            ))

        # Check for known vulnerabilities
        vulns = ssl.get("vulnerabilities", {})
        vuln_map = {
            "heartbleed": {
                "title": "Heartbleed Vulnerability (CVE-2014-0160)",
                "description": "Server is vulnerable to the Heartbleed bug, allowing memory disclosure.",
                "severity": Severity.CRITICAL,
                "cve_ids": ["CVE-2014-0160"],
                "cwe_ids": ["CWE-119"],
                "remediation": "Update OpenSSL to a patched version and reissue certificates.",
            },
            "poodle": {
                "title": "POODLE Vulnerability (CVE-2014-3566)",
                "description": "Server is vulnerable to POODLE attack via SSLv3/CBC ciphers.",
                "severity": Severity.MEDIUM,
                "cve_ids": ["CVE-2014-3566"],
                "cwe_ids": ["CWE-310"],
                "remediation": "Disable SSLv3 and CBC-mode ciphers.",
            },
            "drown": {
                "title": "DROWN Attack Vulnerability (CVE-2016-0800)",
                "description": "Server is vulnerable to DROWN attack via SSLv2 support.",
                "severity": Severity.HIGH,
                "cve_ids": ["CVE-2016-0800"],
                "cwe_ids": ["CWE-310"],
                "remediation": "Disable SSLv2 on all servers sharing the same certificate.",
            },
        }

        for vuln_key, vuln_info in vuln_map.items():
            if vulns.get(vuln_key):
                findings.append(UnifiedFinding(
                    source_tool="reticustos:testssl",
                    source_id=f"ssl-{vuln_key}-{host_ip}:{port}",
                    title=vuln_info["title"],
                    description=vuln_info["description"],
                    severity=vuln_info["severity"],
                    confidence=Confidence.CERTAIN,
                    cve_ids=vuln_info.get("cve_ids", []),
                    cwe_ids=vuln_info.get("cwe_ids", []),
                    location=base_location,
                    finding_type=FindingType.OTHER,
                    remediation=vuln_info["remediation"],
                    tags=["ssl", vuln_key],
                    raw_data=ssl,
                ))

        return findings

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Reticustos severity string to unified Severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _determine_finding_type(self, tool: str) -> FindingType:
        """Determine finding type based on the originating scanner tool."""
        tool_lower = tool.lower()
        if tool_lower in NETWORK_TOOLS:
            return FindingType.NETWORK
        if tool_lower in DAST_TOOLS:
            return FindingType.DAST
        if tool_lower in SSL_TOOLS:
            return FindingType.OTHER
        return FindingType.OTHER
