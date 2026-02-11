"""Parser for Nessus XML (.nessus) files."""

from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nessus")


class NessusParser(BaseParser):
    """Parser for Nessus .nessus XML format."""

    @property
    def tool_name(self) -> str:
        return "nessus"

    @property
    def supported_extensions(self) -> list[str]:
        return [".nessus", ".xml"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Nessus export by looking for signature."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "rb") as f:
                header = f.read(2048).decode("utf-8", errors="ignore")
                return "NessusClientData" in header or "<Policy>" in header
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nessus XML file."""
        findings = []
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            skipped = 0
            total = 0

            # Find all ReportHost elements
            for report_host in root.findall(".//ReportHost"):
                host_name = report_host.get("name", "unknown")
                host_properties = self._parse_host_properties(report_host)

                items = report_host.findall(".//ReportItem")
                total += len(items)

                # Process each ReportItem
                for item in items:
                    try:
                        finding = self._parse_report_item(item, host_name, host_properties)
                        if finding:
                            findings.append(finding)
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

        return findings

    def _parse_host_properties(self, report_host: Element) -> dict:
        """Extract host properties from HostProperties element."""
        properties = {}
        host_props = report_host.find("HostProperties")
        if host_props is not None:
            for tag in host_props.findall("tag"):
                name = tag.get("name", "")
                if name and tag.text:
                    properties[name] = tag.text
        return properties

    def _parse_report_item(
        self, item: Element, host_name: str, host_properties: dict
    ) -> UnifiedFinding | None:
        """Parse a single ReportItem element."""
        # Extract attributes
        port = item.get("port", "0")
        svc_name = item.get("svc_name", "")
        protocol = item.get("protocol", "tcp")
        plugin_id = item.get("pluginID", "0")
        plugin_name = item.get("pluginName", "Unknown")
        plugin_family = item.get("pluginFamily", "")

        # Skip informational items with severity 0 if they're just noise
        severity_val = item.get("severity", "0")

        # Extract detailed fields
        description = self._get_text(item, "description", "")
        solution = self._get_text(item, "solution", "")
        synopsis = self._get_text(item, "synopsis", "")
        plugin_output = self._get_text(item, "plugin_output", "")

        # CVE and vulnerability references
        cve_ids = [elem.text for elem in item.findall("cve") if elem.text]
        bid_ids = [elem.text for elem in item.findall("bid") if elem.text]
        xref_ids = [elem.text for elem in item.findall("xref") if elem.text]

        # CWE extraction
        cwe_ids = []
        for cwe_elem in item.findall("cwe"):
            if cwe_elem.text:
                cwe_ids.append(f"CWE-{cwe_elem.text}")

        # CVSS scores
        cvss_score = self._get_float(item, "cvss_base_score")
        cvss_vector = self._get_text(item, "cvss_vector", None)
        cvss3_score = self._get_float(item, "cvss3_base_score")
        cvss3_vector = self._get_text(item, "cvss3_vector", None)

        # Exploit availability
        exploit_available = self._get_text(item, "exploit_available", "").lower() == "true"
        exploitability_ease = self._get_text(item, "exploitability_ease", "")

        # Map Nessus severity to our severity
        severity = self._map_severity(severity_val)

        # Build description with synopsis
        full_description = synopsis
        if description:
            full_description = f"{synopsis}\n\n{description}" if synopsis else description

        # Evidence from plugin output
        evidence = plugin_output if plugin_output else None

        # References
        references = []
        for see_also in item.findall("see_also"):
            if see_also.text:
                references.extend(see_also.text.strip().split("\n"))

        location = FindingLocation(
            host=host_name,
            port=int(port) if port.isdigit() else None,
            protocol=protocol,
            service=svc_name if svc_name and svc_name != "general" else None,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=f"{plugin_id}:{host_name}:{port}",
            title=plugin_name,
            description=full_description,
            severity=severity,
            confidence=Confidence.CERTAIN,  # Nessus findings are generally high confidence
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss3_score=cvss3_score,
            cvss3_vector=cvss3_vector,
            location=location,
            finding_type=FindingType.NETWORK,
            evidence=evidence,
            remediation=solution if solution else None,
            references=references,
            exploit_available=exploit_available if exploit_available else None,
            raw_data={
                "plugin_id": plugin_id,
                "plugin_family": plugin_family,
                "exploitability_ease": exploitability_ease,
                "bid": bid_ids,
                "xref": xref_ids,
                "host_properties": host_properties,
            },
        )

    def _get_text(self, element: Element, tag: str, default: str | None = "") -> str | None:
        """Safely get text content from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    def _get_float(self, element: Element, tag: str) -> float | None:
        """Safely get float value from a child element."""
        text = self._get_text(element, tag, None)
        if text:
            try:
                return float(text)
            except ValueError:
                pass
        return None

    def _map_severity(self, nessus_severity: str) -> Severity:
        """Map Nessus severity (0-4) to our severity levels."""
        mapping = {
            "0": Severity.INFO,
            "1": Severity.LOW,
            "2": Severity.MEDIUM,
            "3": Severity.HIGH,
            "4": Severity.CRITICAL,
        }
        result = mapping.get(nessus_severity)
        if result is None:
            logger.warning("Unknown severity '%s', defaulting to MEDIUM", nessus_severity)
            return Severity.MEDIUM
        return result
