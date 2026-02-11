"""Parser for Nmap XML scan output files."""

import re
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nmap")

# Regex pattern for extracting CVE IDs from script output
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


class NmapParser(BaseParser):
    """
    Parser for Nmap XML output format.

    Produces two types of findings:
    - Open port discoveries (INFO severity)
    - NSE script vulnerability detections (MEDIUM/HIGH severity)
    """

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is an Nmap XML export by looking for nmaprun tag."""
        if file_path.suffix.lower() != ".xml":
            return False
        try:
            with open(file_path, "rb") as f:
                header = f.read(2048).decode("utf-8", errors="ignore")
                return "nmaprun" in header and "scanner" in header
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nmap XML output file."""
        findings = []

        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            hosts = root.findall(".//host")
            skipped = 0
            total = len(hosts)

            for host in hosts:
                try:
                    host_addr = self._get_host_address(host)
                    hostnames = self._get_hostnames(host)

                    # Process ports
                    for port in host.findall(".//port"):
                        state_elem = port.find("state")
                        if state_elem is None:
                            continue
                        port_state = state_elem.get("state", "")
                        if port_state != "open":
                            continue

                        protocol = port.get("protocol", "tcp")
                        port_id = port.get("portid", "0")

                        # Extract service info
                        service_elem = port.find("service")
                        service_name = ""
                        service_product = ""
                        service_version = ""
                        if service_elem is not None:
                            service_name = service_elem.get("name", "")
                            service_product = service_elem.get("product", "")
                            service_version = service_elem.get("version", "")

                        service_info = service_product
                        if service_version:
                            service_info = f"{service_product} {service_version}".strip()

                        # Create open port finding
                        port_finding = self._create_port_finding(
                            host_addr,
                            hostnames,
                            port_id,
                            protocol,
                            service_name,
                            service_info,
                        )
                        findings.append(port_finding)

                        # Process NSE scripts on this port
                        for script in port.findall("script"):
                            script_finding = self._parse_script(
                                script, host_addr, hostnames, port_id, protocol, service_name
                            )
                            if script_finding:
                                findings.append(script_finding)

                    # Process host-level scripts
                    for hostscript in host.findall(".//hostscript"):
                        for script in hostscript.findall("script"):
                            script_finding = self._parse_script(
                                script, host_addr, hostnames, "0", "tcp", ""
                            )
                            if script_finding:
                                findings.append(script_finding)

                except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
                    logger.warning("Skipping malformed %s item: %s", self.tool_name, e)
                    skipped += 1
                    continue

            if skipped > 0:
                logger.error(
                    "Skipped %d of %d items in %s — possible schema change or parser bug",
                    skipped, total, file_path,
                )

            if total > 0 and skipped == total:
                raise ParseError(
                    f"All {total} items failed to parse — likely schema change or parser bug",
                    file_path,
                )

        except ET.ParseError as e:
            raise ParseError(f"Invalid XML: {e}", file_path)
        except ParseError:
            raise
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info("Parsed %d findings from %s", len(findings), file_path)
        return findings

    def _get_host_address(self, host: Element) -> str:
        """Extract the primary IP address from a host element."""
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4":
                return addr.get("addr", "")
        # Fallback to first address
        addr_elem = host.find("address")
        if addr_elem is not None:
            return addr_elem.get("addr", "")
        return "unknown"

    def _get_hostnames(self, host: Element) -> list[str]:
        """Extract hostnames from a host element."""
        names = []
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall("hostname"):
                name = hostname.get("name", "")
                if name:
                    names.append(name)
        return names

    def _create_port_finding(
        self,
        host_addr: str,
        hostnames: list[str],
        port_id: str,
        protocol: str,
        service_name: str,
        service_info: str,
    ) -> UnifiedFinding:
        """Create a finding for an open port."""
        service_display = service_name or "unknown"
        title = f"Open Port {port_id}/{protocol} ({service_display})"

        description = f"Port {port_id}/{protocol} is open on {host_addr}."
        if service_info:
            description += f" Service: {service_info}."
        if hostnames:
            description += f" Hostnames: {', '.join(hostnames)}."

        port_int = int(port_id) if port_id.isdigit() else None

        # Build tags
        tags = ["nmap"]
        if service_name:
            tags.append(service_name)

        location = FindingLocation(
            host=host_addr,
            port=port_int,
            protocol=protocol,
            service=service_name or None,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=f"port-{host_addr}-{port_id}-{protocol}",
            title=title,
            description=description,
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            location=location,
            finding_type=FindingType.NETWORK,
            tags=tags,
            raw_data={
                "host": host_addr,
                "hostnames": hostnames,
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "service_info": service_info,
            },
        )

    def _parse_script(
        self,
        script: Element,
        host_addr: str,
        hostnames: list[str],
        port_id: str,
        protocol: str,
        service_name: str,
    ) -> UnifiedFinding | None:
        """Parse an NSE script element for vulnerability information."""
        script_id = script.get("id", "")
        output = script.get("output", "")

        if not script_id or not output:
            return None

        # Skip scripts that report NOT VULNERABLE
        output_upper = output.upper()
        if "NOT VULNERABLE" in output_upper:
            return None

        # Only create findings for scripts that indicate issues
        is_vuln = (
            "VULNERABLE" in output_upper
            or "FOUND" in output_upper
            or "VULNERABLE" in script_id.upper()
        )
        if not is_vuln:
            return None

        # Extract CVE IDs from script output
        cve_ids = list(set(_CVE_PATTERN.findall(output)))

        # Severity: HIGH if CVEs present, MEDIUM otherwise
        severity = Severity.HIGH if cve_ids else Severity.MEDIUM

        title = f"NSE {script_id}: {host_addr}:{port_id}"
        description = output.strip()

        port_int = int(port_id) if port_id.isdigit() else None

        # Build tags
        tags = ["nmap", script_id]
        if service_name:
            tags.append(service_name)

        location = FindingLocation(
            host=host_addr,
            port=port_int,
            protocol=protocol,
            service=service_name or None,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=f"nse-{host_addr}-{port_id}-{script_id}",
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.FIRM,
            cve_ids=cve_ids,
            location=location,
            finding_type=FindingType.NETWORK,
            evidence=output,
            tags=tags,
            raw_data={
                "host": host_addr,
                "hostnames": hostnames,
                "port": port_id,
                "protocol": protocol,
                "script_id": script_id,
                "script_output": output,
            },
        )
