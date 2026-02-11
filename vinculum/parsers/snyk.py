"""Parser for Snyk JSON output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.snyk")


class SnykParser(BaseParser):
    """
    Parser for Snyk vulnerability scanner JSON output.

    Supports dependency (SCA) and code (SAST) scan results.
    """

    @property
    def tool_name(self) -> str:
        return "snyk"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is Snyk output by looking for vulnerabilities key."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return (
                    isinstance(data, dict)
                    and "vulnerabilities" in data
                    and ("packageManager" in data or "projectName" in data)
                )
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Snyk JSON output file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            package_manager = data.get("packageManager", "")
            language = data.get("language", "")

            for vuln in data.get("vulnerabilities", []):
                try:
                    finding = self._parse_vulnerability(vuln, package_manager, language)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.warning("Skipping malformed Snyk vulnerability: %s", e)
                    continue

        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_vulnerability(
        self,
        vuln: dict[str, Any],
        package_manager: str,
        language: str,
    ) -> UnifiedFinding | None:
        """Parse a single Snyk vulnerability."""
        vuln_id = vuln.get("id", "")
        if not vuln_id:
            return None

        title = vuln.get("title", vuln_id)
        description = vuln.get("description", "")
        severity = self._map_severity(vuln.get("severity", "low"))

        # Extract identifiers
        identifiers = vuln.get("identifiers", {})
        cve_ids = identifiers.get("CVE", [])
        cwe_ids = [self._normalize_cwe(c) for c in identifiers.get("CWE", [])]

        # CVSS data
        cvss_score = vuln.get("cvssScore")
        cvss3_vector = vuln.get("CVSSv3")
        cvss3_score = cvss_score if cvss3_vector else None

        # Determine finding type
        finding_type = self._determine_finding_type(vuln)

        # Build location from package path or file path
        from_path = vuln.get("from", [])
        file_path_str = vuln.get("filePath")
        location_path = None
        if file_path_str:
            location_path = file_path_str
        elif from_path:
            location_path = " > ".join(str(p) for p in from_path)

        location = FindingLocation(
            file_path=location_path,
        )

        # Build remediation from fixedIn versions
        fixed_in = vuln.get("fixedIn", [])
        remediation = None
        if fixed_in:
            pkg_name = vuln.get("packageName", vuln.get("name", "package"))
            versions_str = ", ".join(str(v) for v in fixed_in)
            remediation = f"Upgrade {pkg_name} to fixed version(s): {versions_str}"

        # Extract references
        references = []
        for ref in vuln.get("references", []):
            if isinstance(ref, dict) and "url" in ref:
                references.append(ref["url"])
            elif isinstance(ref, str):
                references.append(ref)

        # Build tags
        tags = []
        if package_manager:
            tags.append(package_manager)
        if language:
            tags.append(language)

        # Source ID
        source_id = vuln_id

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.CERTAIN,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss3_score=cvss3_score,
            cvss3_vector=cvss3_vector,
            location=location,
            finding_type=finding_type,
            remediation=remediation,
            references=references[:10],
            tags=tags,
            raw_data={
                "id": vuln_id,
                "packageName": vuln.get("packageName", ""),
                "version": vuln.get("version", ""),
                "from": from_path,
                "packageManager": package_manager,
            },
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Snyk severity to unified severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _determine_finding_type(self, vuln: dict[str, Any]) -> FindingType:
        """Determine finding type based on vulnerability data."""
        vuln_type = vuln.get("type", "")
        # If it's a code-level vuln with file context, treat as SAST
        if vuln_type == "vuln" and vuln.get("filePath"):
            return FindingType.SAST
        # Default for Snyk is dependency scanning
        return FindingType.DEPENDENCY

    def _normalize_cwe(self, cwe: str) -> str:
        """Normalize CWE ID format."""
        cwe = str(cwe).upper().strip()
        if cwe.startswith("CWE-"):
            return cwe
        if cwe.isdigit():
            return f"CWE-{cwe}"
        return f"CWE-{cwe}"
