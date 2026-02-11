"""Parser for Trivy JSON output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.trivy")


class TrivyParser(BaseParser):
    """
    Parser for Trivy vulnerability scanner JSON output.

    Supports container image, filesystem, and repository scans.
    """

    @property
    def tool_name(self) -> str:
        return "trivy"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is Trivy output by looking for Results key."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                # Trivy JSON has SchemaVersion and Results
                return "SchemaVersion" in data or "Results" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Trivy JSON output file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            artifact_name = data.get("ArtifactName", "")
            artifact_type = data.get("ArtifactType", "")

            skipped = 0
            total = 0

            for result in data.get("Results", []):
                target = result.get("Target", "")
                result_class = result.get("Class", "")
                result_type = result.get("Type", "")

                vulns = result.get("Vulnerabilities", [])
                misconfigs = result.get("Misconfigurations", [])
                total += len(vulns) + len(misconfigs)

                # Parse vulnerabilities
                for vuln in vulns:
                    try:
                        finding = self._parse_vulnerability(
                            vuln, artifact_name, target, result_class, result_type
                        )
                        if finding:
                            findings.append(finding)
                    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
                        logger.warning("Skipping malformed %s item: %s", self.tool_name, e)
                        skipped += 1
                        continue

                # Parse misconfigurations (if present)
                for misconfig in misconfigs:
                    try:
                        finding = self._parse_misconfiguration(
                            misconfig, artifact_name, target
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

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_vulnerability(
        self,
        vuln: dict[str, Any],
        artifact_name: str,
        target: str,
        result_class: str,
        result_type: str,
    ) -> UnifiedFinding | None:
        """Parse a single Trivy vulnerability."""
        vuln_id = vuln.get("VulnerabilityID", "")
        if not vuln_id:
            return None

        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")

        # Build title
        title = vuln.get("Title", "")
        if not title:
            title = f"{vuln_id} in {pkg_name}"

        # Build description
        description = vuln.get("Description", "")

        # Map severity
        severity = self._map_severity(vuln.get("Severity", "UNKNOWN"))

        # Extract CVE
        cve_ids = []
        if vuln_id.upper().startswith("CVE-"):
            cve_ids.append(vuln_id.upper())

        # Extract CWE
        cwe_ids = []
        for cwe in vuln.get("CweIDs", []):
            cwe_ids.append(self._normalize_cwe(cwe))

        # Extract CVSS scores
        cvss_score = None
        cvss3_score = None
        cvss_data = vuln.get("CVSS", {})

        # Try different CVSS sources
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss_data:
                v3_score = cvss_data[source].get("V3Score")
                v2_score = cvss_data[source].get("V2Score")
                if v3_score is not None:
                    cvss3_score = float(v3_score)
                if v2_score is not None:
                    cvss_score = float(v2_score)
                if cvss3_score or cvss_score:
                    break

        # Determine finding type
        finding_type = self._determine_finding_type(result_class, result_type)

        # Build location
        location = FindingLocation(
            file_path=target or artifact_name or None,
        )

        # Build source ID
        source_id = f"{vuln_id}:{target}:{pkg_name}"

        # Build remediation
        remediation = None
        if fixed_version:
            remediation = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}"
        elif vuln.get("PrimaryURL"):
            remediation = f"See {vuln.get('PrimaryURL')} for remediation guidance"

        # Extract references
        references = []
        if vuln.get("PrimaryURL"):
            references.append(vuln["PrimaryURL"])
        references.extend(vuln.get("References", []))

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.CERTAIN,  # Trivy has high confidence
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss3_score=cvss3_score,
            location=location,
            finding_type=finding_type,
            remediation=remediation,
            references=references[:10],  # Limit references
            tags=[result_type, result_class] if result_type else [],
            raw_data={
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "artifact_name": artifact_name,
                "target": target,
            },
        )

    def _parse_misconfiguration(
        self,
        misconfig: dict[str, Any],
        artifact_name: str,
        target: str,
    ) -> UnifiedFinding | None:
        """Parse a Trivy misconfiguration finding."""
        misconfig_id = misconfig.get("ID", "")
        if not misconfig_id:
            return None

        title = misconfig.get("Title", misconfig_id)
        description = misconfig.get("Description", "")
        message = misconfig.get("Message", "")

        if message and message not in description:
            description = f"{description}\n\n{message}".strip()

        severity = self._map_severity(misconfig.get("Severity", "UNKNOWN"))

        # Build location
        location = FindingLocation(
            file_path=target or artifact_name or None,
            line_start=misconfig.get("StartLine"),
            line_end=misconfig.get("EndLine"),
            code_snippet=misconfig.get("Code", {}).get("Lines", ""),
        )

        # Build source ID
        source_id = f"{misconfig_id}:{target}"

        # Extract references
        references = misconfig.get("References", [])

        # Build remediation
        remediation = misconfig.get("Resolution", "")

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.FIRM,
            location=location,
            finding_type=FindingType.SAST,  # Misconfigs are like SAST
            remediation=remediation if remediation else None,
            references=references[:10],
            tags=["misconfiguration", misconfig.get("Type", "")],
            raw_data=misconfig,
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Trivy severity to unified severity."""
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNKNOWN": Severity.INFO,
        }
        result = mapping.get(severity_str.upper())
        if result is None:
            logger.warning("Unknown severity '%s', defaulting to MEDIUM", severity_str)
            return Severity.MEDIUM
        return result

    def _determine_finding_type(self, result_class: str, result_type: str) -> FindingType:
        """Determine finding type based on Trivy result metadata."""
        result_class = result_class.lower()
        result_type = result_type.lower()

        if "os-pkgs" in result_class or "container" in result_type:
            return FindingType.CONTAINER
        if "lang-pkgs" in result_class:
            return FindingType.DEPENDENCY
        if "secret" in result_class:
            return FindingType.SECRET
        if "config" in result_class:
            return FindingType.CLOUD
        return FindingType.DEPENDENCY  # Default for vulnerability scans

    def _normalize_cwe(self, cwe: str) -> str:
        """Normalize CWE ID format."""
        cwe = str(cwe).upper().strip()
        if cwe.startswith("CWE-"):
            return cwe
        if cwe.isdigit():
            return f"CWE-{cwe}"
        return f"CWE-{cwe}"
