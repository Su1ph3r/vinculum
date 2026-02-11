"""Parser for OWASP ZAP XML report files."""

from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.zap")


class ZAPParser(BaseParser):
    """
    Parser for OWASP ZAP XML report format.

    Supports ZAP's standard XML export format (OWASPZAPReport).
    """

    @property
    def tool_name(self) -> str:
        return "zap"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is ZAP report by looking for OWASPZAPReport tag."""
        if file_path.suffix.lower() != ".xml":
            return False
        try:
            with open(file_path, "rb") as f:
                header = f.read(2048).decode("utf-8", errors="ignore")
                return "OWASPZAPReport" in header or "OWASP-ZAP" in header
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse ZAP XML report file."""
        findings = []

        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            skipped = 0
            total = 0

            # Iterate through sites
            for site in root.findall(".//site"):
                site_name = site.get("name", "")
                site_host = site.get("host", "")
                site_port = site.get("port", "")

                alerts = site.findall(".//alertitem")
                total += len(alerts)

                # Iterate through alerts
                for alert in alerts:
                    try:
                        finding = self._parse_alert(alert, site_name, site_host, site_port)
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

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_alert(
        self,
        alert: Element,
        site_name: str,
        site_host: str,
        site_port: str,
    ) -> UnifiedFinding | None:
        """Parse a single ZAP alert element."""
        plugin_id = self._get_text(alert, "pluginid", "")
        if not plugin_id:
            return None

        # Extract basic info
        name = self._get_text(alert, "name") or self._get_text(alert, "alert", "Unknown Alert")
        description = self._get_text(alert, "desc", "")
        solution = self._get_text(alert, "solution", "")
        reference = self._get_text(alert, "reference", "")
        other_info = self._get_text(alert, "otherinfo", "")

        # Map risk code to severity (ZAP uses 0-3)
        risk_code = self._get_text(alert, "riskcode", "0")
        severity = self._map_risk_code(risk_code)

        # Map confidence (ZAP uses 0-3)
        conf_code = self._get_text(alert, "confidence", "1")
        confidence = self._map_confidence(conf_code)

        # Extract CWE
        cwe_ids = []
        cwe_id = self._get_text(alert, "cweid", "")
        if cwe_id:
            cwe_ids.append(f"CWE-{cwe_id}")

        # Extract WASC ID for additional context
        wasc_id = self._get_text(alert, "wascid", "")

        # Collect all instances of this alert
        instances = []
        evidence_parts = []

        for instance in alert.findall(".//instance"):
            inst_data = {
                "uri": self._get_text(instance, "uri", ""),
                "method": self._get_text(instance, "method", ""),
                "param": self._get_text(instance, "param", ""),
                "attack": self._get_text(instance, "attack", ""),
                "evidence": self._get_text(instance, "evidence", ""),
            }
            instances.append(inst_data)

            # Build evidence from instance
            if inst_data["uri"]:
                evidence_parts.append(f"URL: {inst_data['uri']}")
            if inst_data["method"]:
                evidence_parts.append(f"Method: {inst_data['method']}")
            if inst_data["param"]:
                evidence_parts.append(f"Parameter: {inst_data['param']}")
            if inst_data["attack"]:
                evidence_parts.append(f"Attack: {inst_data['attack']}")
            if inst_data["evidence"]:
                evidence_parts.append(f"Evidence: {inst_data['evidence'][:500]}")
            evidence_parts.append("---")

        # Use first instance for location, or fall back to site
        first_instance = instances[0] if instances else {}
        url = first_instance.get("uri") or site_name
        method = first_instance.get("method") or None
        parameter = first_instance.get("param") or None

        # Build location
        location = FindingLocation(
            url=url or None,
            host=site_host or self._extract_host(url) or None,
            port=int(site_port) if site_port and site_port.isdigit() else None,
            method=method,
            parameter=parameter,
        )

        # Build source ID
        source_id = f"{plugin_id}:{url}:{parameter or 'none'}"

        # Build evidence string
        evidence = "\n".join(evidence_parts) if evidence_parts else None

        # Parse references
        references = []
        if reference:
            # ZAP often includes multiple URLs in reference field
            for line in reference.split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    references.append(line)
                elif line.startswith("<p>"):
                    # Handle HTML-wrapped references
                    import re
                    urls = re.findall(r'https?://[^\s<>"]+', line)
                    references.extend(urls)

        # Build tags
        tags = ["zap"]
        if wasc_id:
            tags.append(f"WASC-{wasc_id}")

        # Clean HTML from description
        description = self._clean_html(description)
        if other_info:
            description = f"{description}\n\nAdditional Info: {self._clean_html(other_info)}"

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=name,
            description=description,
            severity=severity,
            confidence=confidence,
            cwe_ids=cwe_ids,
            location=location,
            finding_type=FindingType.DAST,
            evidence=evidence,
            remediation=self._clean_html(solution) if solution else None,
            references=references[:10],  # Limit references
            tags=tags,
            raw_data={
                "plugin_id": plugin_id,
                "risk_code": risk_code,
                "confidence": conf_code,
                "wasc_id": wasc_id,
                "instance_count": len(instances),
            },
        )

    def _get_text(self, element: Element, tag: str, default: str = "") -> str:
        """Safely get text content from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text
        return default

    def _map_risk_code(self, risk_code: str) -> Severity:
        """Map ZAP risk code (0-3) to severity."""
        mapping = {
            "0": Severity.INFO,       # Informational
            "1": Severity.LOW,        # Low
            "2": Severity.MEDIUM,     # Medium
            "3": Severity.HIGH,       # High
        }
        result = mapping.get(risk_code)
        if result is None:
            logger.warning("Unknown risk code '%s', defaulting to MEDIUM", risk_code)
            return Severity.MEDIUM
        return result

    def _map_confidence(self, conf_code: str) -> Confidence:
        """Map ZAP confidence code (0-3) to confidence."""
        mapping = {
            "0": Confidence.TENTATIVE,  # False Positive
            "1": Confidence.TENTATIVE,  # Low
            "2": Confidence.FIRM,       # Medium
            "3": Confidence.CERTAIN,    # High
        }
        return mapping.get(conf_code, Confidence.TENTATIVE)

    def _extract_host(self, url: str) -> str | None:
        """Extract hostname from URL."""
        if not url:
            return None
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or None
        except Exception:
            return None

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        import re
        # Remove HTML tags
        clean = re.sub(r"<[^>]+>", "", text)
        # Normalize whitespace
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean
