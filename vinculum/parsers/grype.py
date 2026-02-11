"""Parser for Grype JSON output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.grype")

# OS package types that indicate container-level findings
_OS_PACKAGE_TYPES = {"deb", "rpm", "apk"}


class GrypeParser(BaseParser):
    """
    Parser for Grype vulnerability scanner JSON output.

    Supports container image and filesystem scans.
    """

    @property
    def tool_name(self) -> str:
        return "grype"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is Grype output by looking for matches key and descriptor."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return (
                    isinstance(data, dict)
                    and "matches" in data
                    and data.get("descriptor", {}).get("name") == "grype"
                )
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Grype JSON output file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            matches = data.get("matches", [])
            skipped = 0
            total = len(matches)

            for match in matches:
                try:
                    finding = self._parse_match(match)
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

    def _parse_match(self, match: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single Grype match."""
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vulnerability.get("id", "")
        if not vuln_id:
            logger.warning("Skipping Grype match with empty vulnerability id")
            return None

        artifact_name = artifact.get("name", "")
        artifact_version = artifact.get("version", "")
        artifact_type = artifact.get("type", "")
        artifact_language = artifact.get("language", "")

        # Build title
        title = f"{vuln_id} in {artifact_name} {artifact_version}".strip()

        # Description
        description = vulnerability.get("description", "")

        # Map severity
        severity = self._map_severity(vulnerability.get("severity", "Unknown"))

        # Extract CVE
        cve_ids = []
        if vuln_id.upper().startswith("CVE-"):
            cve_ids.append(vuln_id.upper())

        # Extract CVSS
        cvss3_score = None
        cvss3_vector = None
        cvss_list = vulnerability.get("cvss", [])
        if cvss_list:
            first_cvss = cvss_list[0]
            metrics = first_cvss.get("metrics", {})
            cvss3_score = metrics.get("baseScore")
            cvss3_vector = first_cvss.get("vector")

        # Determine finding type
        finding_type = self._determine_finding_type(artifact_type)

        # Build location from artifact locations
        locations = artifact.get("locations", [])
        location_path = None
        if locations:
            location_path = locations[0].get("path")

        location = FindingLocation(
            file_path=location_path,
        )

        # Build remediation from fix versions
        fix = vulnerability.get("fix", {})
        fix_versions = fix.get("versions", [])
        remediation = None
        if fix_versions:
            versions_str = ", ".join(str(v) for v in fix_versions)
            remediation = f"Upgrade {artifact_name} to fixed version(s): {versions_str}"
        elif fix.get("state") == "not-fixed":
            remediation = f"No fix available for {artifact_name}. Consider using an alternative package."

        # Extract references
        references = vulnerability.get("urls", [])

        # Build tags
        tags = []
        if artifact_type:
            tags.append(artifact_type)
        if artifact_language:
            tags.append(artifact_language)

        # Source ID combines vulnerability and artifact
        source_id = f"{vuln_id}:{artifact_name}"

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.CERTAIN,
            cve_ids=cve_ids,
            cvss3_score=float(cvss3_score) if cvss3_score is not None else None,
            cvss3_vector=cvss3_vector,
            location=location,
            finding_type=finding_type,
            remediation=remediation,
            references=references[:10],
            tags=tags,
            raw_data={
                "vulnerability_id": vuln_id,
                "artifact_name": artifact_name,
                "artifact_version": artifact_version,
                "artifact_type": artifact_type,
                "fix_state": fix.get("state", ""),
            },
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Grype severity to unified severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "negligible": Severity.INFO,
        }
        result = mapping.get(severity_str.lower())
        if result is None:
            logger.warning("Unknown severity '%s', defaulting to MEDIUM", severity_str)
            return Severity.MEDIUM
        return result

    def _determine_finding_type(self, artifact_type: str) -> FindingType:
        """Determine finding type based on artifact type."""
        if artifact_type.lower() in _OS_PACKAGE_TYPES:
            return FindingType.CONTAINER
        return FindingType.DEPENDENCY
