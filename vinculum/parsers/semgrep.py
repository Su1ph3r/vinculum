"""Parser for Semgrep JSON output files."""

import json
from pathlib import Path

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.semgrep")


class SemgrepParser(BaseParser):
    """Parser for Semgrep JSON output format."""

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Semgrep JSON output."""
        if file_path.suffix.lower() != ".json":
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                # Semgrep JSON has 'results' array and optionally 'version'
                return isinstance(data, dict) and "results" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Semgrep JSON output file."""
        findings = []
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            results = data.get("results", [])
            skipped = 0
            total = len(results)

            for result in results:
                try:
                    finding = self._parse_result(result)
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

        return findings

    def _parse_result(self, result: dict) -> UnifiedFinding | None:
        """Parse a single Semgrep result."""
        check_id = result.get("check_id", "unknown")
        path = result.get("path", "")

        # Location info
        start = result.get("start", {})
        end = result.get("end", {})
        line_start = start.get("line")
        line_end = end.get("line")
        col_start = start.get("col")
        col_end = end.get("col")

        # Extra metadata
        extra = result.get("extra", {})
        message = extra.get("message", "")
        severity_text = extra.get("severity", "WARNING")
        metadata = extra.get("metadata", {})
        fix = extra.get("fix")
        lines = extra.get("lines", "")

        # Extract references from metadata
        cwe_ids = self._extract_cwes(metadata)
        references = metadata.get("references", [])
        if isinstance(references, str):
            references = [references]

        # OWASP references
        owasp = metadata.get("owasp", [])
        if isinstance(owasp, str):
            owasp = [owasp]

        # Confidence from metadata
        confidence_text = metadata.get("confidence", "MEDIUM")

        # Determine finding type from category or technology
        category = metadata.get("category", "")
        finding_type = self._determine_finding_type(category, metadata)

        # Map severity
        severity = self._map_severity(severity_text)
        confidence = self._map_confidence(confidence_text)

        # Build description
        description = message
        if owasp:
            description += f"\n\nOWASP: {', '.join(owasp)}"

        location = FindingLocation(
            file_path=path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=lines if lines else None,
        )

        # Build remediation from fix suggestion
        remediation = None
        if fix:
            remediation = f"Suggested fix:\n{fix}"

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=f"{check_id}:{path}:{line_start}",
            title=self._format_title(check_id),
            description=description,
            severity=severity,
            confidence=confidence,
            cwe_ids=cwe_ids,
            location=location,
            finding_type=finding_type,
            evidence=lines if lines else None,
            remediation=remediation,
            references=references,
            tags=self._extract_tags(metadata),
            raw_data={
                "check_id": check_id,
                "metadata": metadata,
                "col_start": col_start,
                "col_end": col_end,
            },
        )

    def _extract_cwes(self, metadata: dict) -> list[str]:
        """Extract CWE IDs from metadata."""
        cwe_ids = []
        cwe_data = metadata.get("cwe", [])
        if isinstance(cwe_data, str):
            cwe_data = [cwe_data]

        for cwe in cwe_data:
            if isinstance(cwe, str):
                # Handle formats like "CWE-79" or just "79"
                if cwe.upper().startswith("CWE-"):
                    cwe_ids.append(cwe.upper())
                elif cwe.isdigit():
                    cwe_ids.append(f"CWE-{cwe}")
                else:
                    # Try to extract CWE number from string
                    import re

                    match = re.search(r"CWE[:\-]?\s*(\d+)", cwe, re.I)
                    if match:
                        cwe_ids.append(f"CWE-{match.group(1)}")

        return list(set(cwe_ids))

    def _extract_tags(self, metadata: dict) -> list[str]:
        """Extract tags from metadata."""
        tags = []
        for key in ["category", "subcategory", "technology", "likelihood", "impact"]:
            value = metadata.get(key)
            if value:
                if isinstance(value, list):
                    tags.extend(value)
                else:
                    tags.append(str(value))
        return tags

    def _determine_finding_type(self, category: str, metadata: dict) -> FindingType:
        """Determine finding type from Semgrep metadata."""
        category_lower = category.lower()
        technology = str(metadata.get("technology", "")).lower()

        if "secret" in category_lower or "credential" in category_lower:
            return FindingType.SECRET
        if "supply-chain" in category_lower or "dependency" in category_lower:
            return FindingType.DEPENDENCY
        if "docker" in technology or "container" in technology:
            return FindingType.CONTAINER

        # Default to SAST for code analysis
        return FindingType.SAST

    def _format_title(self, check_id: str) -> str:
        """Format check_id into a readable title."""
        # Remove common prefixes
        title = check_id
        for prefix in ["semgrep.", "rules.", "generic.", "audit."]:
            if title.lower().startswith(prefix):
                title = title[len(prefix) :]

        # Replace separators with spaces and capitalize
        title = title.replace("-", " ").replace("_", " ").replace(".", " - ")

        # Capitalize first letter of each word, but preserve acronyms
        words = []
        for word in title.split():
            if word.isupper() and len(word) > 1:
                words.append(word)  # Keep acronyms
            else:
                words.append(word.capitalize())

        return " ".join(words)

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity to our severity levels."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
            "INVENTORY": Severity.INFO,
        }
        result = mapping.get(semgrep_severity.upper())
        if result is None:
            logger.warning("Unknown severity '%s', defaulting to MEDIUM", semgrep_severity)
            return Severity.MEDIUM
        return result

    def _map_confidence(self, confidence: str) -> Confidence:
        """Map Semgrep confidence to our confidence levels."""
        mapping = {
            "HIGH": Confidence.CERTAIN,
            "MEDIUM": Confidence.FIRM,
            "LOW": Confidence.TENTATIVE,
        }
        return mapping.get(confidence.upper(), Confidence.FIRM)
