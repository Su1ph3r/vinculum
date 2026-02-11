"""Parser for OWASP Dependency-Check XML and JSON report files."""

import json
import re
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.dependency_check")


class DependencyCheckParser(BaseParser):
    """
    Parser for OWASP Dependency-Check XML and JSON report formats.

    Supports both the XML report (default) and JSON report output from
    Dependency-Check, which identifies known vulnerabilities in project
    dependencies.
    """

    @property
    def tool_name(self) -> str:
        return "dependency-check"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml", ".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Dependency-Check report."""
        suffix = file_path.suffix.lower()
        if suffix not in self.supported_extensions:
            return False
        try:
            if suffix == ".xml":
                with open(file_path, "rb") as f:
                    header = f.read(2048).decode("utf-8", errors="ignore")
                    return "dependency-check" in header.lower()
            else:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    return "reportSchema" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Dependency-Check report file (XML or JSON)."""
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            return self._parse_json(file_path)
        return self._parse_xml(file_path)

    def _parse_xml(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Dependency-Check XML report."""
        findings = []
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            # Handle namespace: extract from root tag if present
            ns = ""
            tag = root.tag
            if tag.startswith("{"):
                ns = tag[: tag.index("}") + 1]

            skipped = 0
            total = 0

            for dependency in root.findall(f".//{ns}dependency"):
                file_name = self._get_text(dependency, f"{ns}fileName", "")
                file_path_str = self._get_text(dependency, f"{ns}filePath", "")

                vulns_container = dependency.find(f"{ns}vulnerabilities")
                if vulns_container is None:
                    continue

                vulns = vulns_container.findall(f"{ns}vulnerability")
                total += len(vulns)

                for vuln in vulns:
                    try:
                        finding = self._parse_xml_vulnerability(
                            vuln, ns, file_name, file_path_str
                        )
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

        logger.info("Parsed %d findings from %s", len(findings), file_path)
        return findings

    def _parse_xml_vulnerability(
        self,
        vuln: Element,
        ns: str,
        file_name: str,
        file_path_str: str,
    ) -> UnifiedFinding | None:
        """Parse a single vulnerability element from XML."""
        name = self._get_text(vuln, f"{ns}name", "")
        if not name:
            logger.warning("Skipping dependency-check XML vulnerability with empty name")
            return None

        description = self._get_text(vuln, f"{ns}description", "")

        # Extract CVSS scores
        cvss3_score = None
        cvss_score = None

        cvss_v3 = vuln.find(f"{ns}cvssV3")
        if cvss_v3 is not None:
            cvss3_score = self._get_float(cvss_v3, f"{ns}baseScore")

        cvss_v2 = vuln.find(f"{ns}cvssV2")
        if cvss_v2 is not None:
            cvss_score = self._get_float(cvss_v2, f"{ns}score")

        # Determine severity from CVSS score
        severity = self._severity_from_cvss(cvss3_score or cvss_score)

        # Extract CWEs
        cwe_ids = []
        cwes_elem = vuln.find(f"{ns}cwes")
        if cwes_elem is not None:
            for cwe_elem in cwes_elem.findall(f"{ns}cwe"):
                if cwe_elem.text:
                    cwe_text = cwe_elem.text.strip()
                    if not cwe_text.startswith("CWE-"):
                        cwe_text = f"CWE-{cwe_text}"
                    cwe_ids.append(cwe_text)

        # Extract CVE IDs
        cve_ids = []
        if re.match(r"CVE-\d{4}-\d{4,7}", name):
            cve_ids.append(name)

        # Extract references
        references = []
        refs_elem = vuln.find(f"{ns}references")
        if refs_elem is not None:
            for ref in refs_elem.findall(f"{ns}reference"):
                url = self._get_text(ref, f"{ns}url", "")
                if url:
                    references.append(url)

        # Build tags
        tags = ["dependency-check"]
        if file_name:
            tags.append(file_name)

        # Build remediation hint
        remediation = None
        if file_name:
            remediation = f"Upgrade {file_name} to a version that fixes {name}."

        location = FindingLocation(
            file_path=file_path_str or file_name or None,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=name,
            title=f"{name} in {file_name}" if file_name else name,
            description=description,
            severity=severity,
            confidence=Confidence.CERTAIN,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss3_score=cvss3_score,
            location=location,
            finding_type=FindingType.DEPENDENCY,
            remediation=remediation,
            references=references,
            tags=tags,
            raw_data={
                "dependency_file": file_name,
                "vulnerability_name": name,
            },
        )

    def _parse_json(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Dependency-Check JSON report."""
        findings = []
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            dependencies = data.get("dependencies", [])
            skipped = 0
            total = 0

            for dep in dependencies:
                file_name = dep.get("fileName", "")
                file_path_str = dep.get("filePath", "")
                vulnerabilities = dep.get("vulnerabilities", [])
                total += len(vulnerabilities)

                for vuln in vulnerabilities:
                    try:
                        finding = self._parse_json_vulnerability(
                            vuln, file_name, file_path_str
                        )
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

        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except ParseError:
            raise
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info("Parsed %d findings from %s", len(findings), file_path)
        return findings

    def _parse_json_vulnerability(
        self,
        vuln: dict[str, Any],
        file_name: str,
        file_path_str: str,
    ) -> UnifiedFinding | None:
        """Parse a single vulnerability dict from JSON."""
        name = vuln.get("name", "")
        if not name:
            logger.warning("Skipping dependency-check JSON vulnerability with empty name")
            return None

        description = vuln.get("description", "")

        # Extract CVSS scores
        cvss3_score = None
        cvss_score = None

        cvss_v3 = vuln.get("cvssV3")
        if isinstance(cvss_v3, dict):
            cvss3_score = cvss_v3.get("baseScore")

        cvss_v2 = vuln.get("cvssV2")
        if isinstance(cvss_v2, dict):
            cvss_score = cvss_v2.get("score")

        severity = self._severity_from_cvss(cvss3_score or cvss_score)

        # Extract CWEs
        cwe_ids = []
        for cwe in vuln.get("cwes", []):
            if isinstance(cwe, str):
                cwe_text = cwe.strip()
                if not cwe_text.startswith("CWE-"):
                    cwe_text = f"CWE-{cwe_text}"
                cwe_ids.append(cwe_text)

        # Extract CVE IDs
        cve_ids = []
        if re.match(r"CVE-\d{4}-\d{4,7}", name):
            cve_ids.append(name)

        # Extract references
        references = []
        for ref in vuln.get("references", []):
            if isinstance(ref, dict):
                url = ref.get("url", "")
                if url:
                    references.append(url)
            elif isinstance(ref, str):
                references.append(ref)

        # Build tags
        tags = ["dependency-check"]
        if file_name:
            tags.append(file_name)

        # Build remediation hint
        remediation = None
        if file_name:
            remediation = f"Upgrade {file_name} to a version that fixes {name}."

        location = FindingLocation(
            file_path=file_path_str or file_name or None,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=name,
            title=f"{name} in {file_name}" if file_name else name,
            description=description,
            severity=severity,
            confidence=Confidence.CERTAIN,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss3_score=cvss3_score,
            location=location,
            finding_type=FindingType.DEPENDENCY,
            remediation=remediation,
            references=references,
            tags=tags,
            raw_data={
                "dependency_file": file_name,
                "vulnerability_name": name,
            },
        )

    def _severity_from_cvss(self, score: float | None) -> Severity:
        """Map CVSS score to severity level."""
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def _get_text(self, element: Element, tag: str, default: str = "") -> str:
        """Safely get text content from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    def _get_float(self, element: Element, tag: str) -> float | None:
        """Safely get float value from a child element."""
        text = self._get_text(element, tag, "")
        if text:
            try:
                return float(text)
            except ValueError:
                logger.warning("Could not parse float value '%s' from tag '%s'", text, tag)
        return None
