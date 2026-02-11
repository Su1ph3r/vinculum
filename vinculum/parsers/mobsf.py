"""Parser for MobSF JSON output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.mobsf")


class MobSFParser(BaseParser):
    """
    Parser for MobSF (Mobile Security Framework) JSON output.

    Supports Android and iOS scan results including code analysis,
    manifest analysis, binary analysis, and certificate analysis.
    """

    @property
    def tool_name(self) -> str:
        return "mobsf"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is MobSF output by looking for app_name and platform indicators."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return (
                    isinstance(data, dict)
                    and "app_name" in data
                    and ("android" in data or "ios" in data or "security_score" in data)
                )
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse MobSF JSON output file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            app_name = data.get("app_name", "")
            platform = self._detect_platform(data)

            # Parse code analysis findings
            code_analysis = data.get("code_analysis", {})
            if isinstance(code_analysis, dict):
                findings.extend(self._parse_code_analysis(code_analysis, app_name, platform))

            # Parse manifest analysis findings
            manifest_analysis = data.get("manifest_analysis", [])
            if isinstance(manifest_analysis, list):
                findings.extend(
                    self._parse_manifest_analysis(manifest_analysis, app_name, platform)
                )

            # Parse binary analysis findings
            binary_analysis = data.get("binary_analysis", [])
            if isinstance(binary_analysis, list):
                findings.extend(
                    self._parse_binary_analysis(binary_analysis, app_name, platform)
                )

            # Parse certificate analysis findings
            cert_analysis = data.get("certificate_analysis", {})
            if isinstance(cert_analysis, dict) and cert_analysis.get("certificate_findings"):
                findings.extend(
                    self._parse_certificate_analysis(cert_analysis, app_name, platform)
                )

        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_code_analysis(
        self,
        code_analysis: dict[str, Any],
        app_name: str,
        platform: str,
    ) -> list[UnifiedFinding]:
        """Parse code analysis section (dict of findings by category)."""
        findings = []

        for key, finding_data in code_analysis.items():
            try:
                if not isinstance(finding_data, dict):
                    continue

                metadata = finding_data.get("metadata", {})
                description = metadata.get("description", "") if isinstance(metadata, dict) else ""
                severity_str = metadata.get("severity", "info") if isinstance(metadata, dict) else "info"
                severity = self._map_severity(severity_str)

                # Extract file paths from finding data
                files = finding_data.get("files", {})
                if isinstance(files, dict):
                    file_paths = list(files.keys())
                elif isinstance(files, list):
                    file_paths = [f.get("file_path", "") for f in files if isinstance(f, dict)]
                else:
                    file_paths = []

                # Create a finding for each affected file, or one if no files
                if file_paths:
                    for fp in file_paths[:5]:  # Limit to avoid explosion
                        finding = UnifiedFinding(
                            source_tool=self.tool_name,
                            source_id=f"code_analysis:{key}:{fp}",
                            title=key.replace("_", " ").title(),
                            description=description,
                            severity=severity,
                            confidence=Confidence.FIRM,
                            location=FindingLocation(file_path=fp),
                            finding_type=FindingType.SAST,
                            tags=[platform, app_name, "code_analysis"],
                            raw_data={"section": "code_analysis", "key": key},
                        )
                        findings.append(finding)
                else:
                    finding = UnifiedFinding(
                        source_tool=self.tool_name,
                        source_id=f"code_analysis:{key}",
                        title=key.replace("_", " ").title(),
                        description=description,
                        severity=severity,
                        confidence=Confidence.FIRM,
                        finding_type=FindingType.SAST,
                        tags=[platform, app_name, "code_analysis"],
                        raw_data={"section": "code_analysis", "key": key},
                    )
                    findings.append(finding)

            except Exception as e:
                logger.warning("Skipping malformed code analysis finding '%s': %s", key, e)
                continue

        return findings

    def _parse_manifest_analysis(
        self,
        manifest_analysis: list[dict[str, Any]],
        app_name: str,
        platform: str,
    ) -> list[UnifiedFinding]:
        """Parse manifest analysis section (list of findings)."""
        findings = []

        for i, item in enumerate(manifest_analysis):
            try:
                if not isinstance(item, dict):
                    continue

                title = item.get("title", f"Manifest Finding #{i + 1}")
                description = item.get("description", "")
                severity_str = item.get("severity", "info")
                severity = self._map_severity(severity_str)

                finding = UnifiedFinding(
                    source_tool=self.tool_name,
                    source_id=f"manifest_analysis:{i}:{title}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    location=FindingLocation(
                        file_path=item.get("component", "AndroidManifest.xml"),
                    ),
                    finding_type=FindingType.SAST,
                    tags=[platform, app_name, "manifest_analysis"],
                    raw_data={"section": "manifest_analysis", "index": i},
                )
                findings.append(finding)

            except Exception as e:
                logger.warning("Skipping malformed manifest finding at index %d: %s", i, e)
                continue

        return findings

    def _parse_binary_analysis(
        self,
        binary_analysis: list[dict[str, Any]],
        app_name: str,
        platform: str,
    ) -> list[UnifiedFinding]:
        """Parse binary analysis section (list of findings)."""
        findings = []

        for i, item in enumerate(binary_analysis):
            try:
                if not isinstance(item, dict):
                    continue

                title = item.get("title", f"Binary Finding #{i + 1}")
                description = item.get("description", "")
                severity_str = item.get("severity", "info")
                severity = self._map_severity(severity_str)

                finding = UnifiedFinding(
                    source_tool=self.tool_name,
                    source_id=f"binary_analysis:{i}:{title}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=Confidence.TENTATIVE,
                    location=FindingLocation(
                        file_path=item.get("name", item.get("binary", "")),
                    ),
                    finding_type=FindingType.SAST,
                    tags=[platform, app_name, "binary_analysis"],
                    raw_data={"section": "binary_analysis", "index": i},
                )
                findings.append(finding)

            except Exception as e:
                logger.warning("Skipping malformed binary finding at index %d: %s", i, e)
                continue

        return findings

    def _parse_certificate_analysis(
        self,
        cert_analysis: dict[str, Any],
        app_name: str,
        platform: str,
    ) -> list[UnifiedFinding]:
        """Parse certificate analysis section."""
        findings = []
        cert_findings = cert_analysis.get("certificate_findings", [])

        for i, item in enumerate(cert_findings):
            try:
                if not isinstance(item, (dict, list)):
                    continue

                # Handle both list-of-lists and list-of-dicts formats
                if isinstance(item, list) and len(item) >= 2:
                    title = str(item[0])
                    description = str(item[1])
                    severity_str = str(item[2]) if len(item) > 2 else "info"
                elif isinstance(item, dict):
                    title = item.get("title", f"Certificate Finding #{i + 1}")
                    description = item.get("description", "")
                    severity_str = item.get("severity", "info")
                else:
                    continue

                severity = self._map_severity(severity_str)

                finding = UnifiedFinding(
                    source_tool=self.tool_name,
                    source_id=f"certificate_analysis:{i}:{title}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    finding_type=FindingType.SAST,
                    tags=[platform, app_name, "certificate_analysis"],
                    raw_data={"section": "certificate_analysis", "index": i},
                )
                findings.append(finding)

            except Exception as e:
                logger.warning("Skipping malformed certificate finding at index %d: %s", i, e)
                continue

        return findings

    def _map_severity(self, severity_str: str) -> Severity:
        """Map MobSF severity to unified severity."""
        mapping = {
            "high": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "info": Severity.LOW,
            "secure": Severity.INFO,
            "good": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _detect_platform(self, data: dict[str, Any]) -> str:
        """Detect the platform from MobSF data."""
        if "android" in data or data.get("package_name"):
            return "android"
        if "ios" in data or data.get("bundle_id"):
            return "ios"
        return "mobile"
