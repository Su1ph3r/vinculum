"""Parser for Nuclei JSONL output files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nuclei")


class NucleiParser(BaseParser):
    """
    Parser for Nuclei scanner JSONL output format.

    Nuclei outputs one JSON object per line (JSONL format).
    """

    @property
    def tool_name(self) -> str:
        return "nuclei"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json", ".jsonl"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is Nuclei output by looking for template-id in first line."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False
                data = json.loads(first_line)
                return "template-id" in data and "info" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nuclei JSONL output file."""
        findings = []
        line_number = 0

        try:
            with open(file_path, "r") as f:
                for line in f:
                    line_number += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        result = json.loads(line)
                        finding = self._parse_result(result)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Skipping invalid JSON on line {line_number}: {e}"
                        )
                        continue

        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_result(self, result: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single Nuclei result object."""
        template_id = result.get("template-id", "unknown")
        info = result.get("info", {})

        # Extract basic info
        name = info.get("name", template_id)
        description = info.get("description", "")
        severity = self._map_severity(info.get("severity", "info"))

        # Extract host/URL info
        host = result.get("host", "")
        matched_at = result.get("matched-at", host)
        ip = result.get("ip", "")

        # Extract CVEs and CWEs
        cve_ids = self._extract_cves(result)
        cwe_ids = self._extract_cwes(result)

        # Extract CVSS if available
        cvss_score = None
        cvss_metrics = info.get("classification", {}).get("cvss-metrics", "")
        cvss_score_str = info.get("classification", {}).get("cvss-score")
        if cvss_score_str:
            try:
                cvss_score = float(cvss_score_str)
            except (ValueError, TypeError):
                pass

        # Build location
        location = FindingLocation(
            url=matched_at or host or None,
            host=ip or self._extract_host(host) or None,
        )

        # Build source ID
        source_id = f"{template_id}:{host}"

        # Extract evidence
        evidence_parts = []
        if result.get("request"):
            evidence_parts.append(f"REQUEST:\n{result['request'][:2000]}")
        if result.get("response"):
            evidence_parts.append(f"RESPONSE:\n{result['response'][:2000]}")
        if result.get("extracted-results"):
            extracted = result["extracted-results"]
            if isinstance(extracted, list):
                evidence_parts.append(f"EXTRACTED:\n{', '.join(str(e) for e in extracted)}")
            else:
                evidence_parts.append(f"EXTRACTED:\n{extracted}")
        evidence = "\n\n".join(evidence_parts) if evidence_parts else None

        # Extract references
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        # Extract tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Determine confidence based on matcher info
        matcher_name = result.get("matcher-name", "")
        confidence = Confidence.FIRM  # Nuclei matches are generally reliable
        if "fuzzy" in matcher_name.lower() or "heuristic" in matcher_name.lower():
            confidence = Confidence.TENTATIVE

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=source_id,
            title=name,
            description=description,
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            location=location,
            finding_type=FindingType.DAST,
            evidence=evidence,
            references=references,
            tags=tags,
            raw_data=result,
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Nuclei severity to unified severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "unknown": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _extract_cves(self, result: dict[str, Any]) -> list[str]:
        """Extract CVE IDs from Nuclei result."""
        cves = []
        info = result.get("info", {})

        # Check classification
        classification = info.get("classification", {})
        if classification.get("cve-id"):
            cve = classification["cve-id"]
            if isinstance(cve, list):
                cves.extend(cve)
            else:
                cves.append(cve)

        # Check template-id for CVE patterns
        template_id = result.get("template-id", "")
        if template_id.upper().startswith("CVE-"):
            cves.append(template_id.upper())

        # Check tags for CVE patterns
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                cves.append(tag.upper())

        return list(set(cves))

    def _extract_cwes(self, result: dict[str, Any]) -> list[str]:
        """Extract CWE IDs from Nuclei result."""
        cwes = []
        info = result.get("info", {})
        classification = info.get("classification", {})

        cwe_id = classification.get("cwe-id")
        if cwe_id:
            if isinstance(cwe_id, list):
                for cwe in cwe_id:
                    cwes.append(self._normalize_cwe(cwe))
            else:
                cwes.append(self._normalize_cwe(cwe_id))

        return list(set(cwes))

    def _normalize_cwe(self, cwe: str) -> str:
        """Normalize CWE ID format."""
        cwe = str(cwe).upper().strip()
        if cwe.startswith("CWE-"):
            return cwe
        if cwe.isdigit():
            return f"CWE-{cwe}"
        return f"CWE-{cwe}"

    def _extract_host(self, url: str) -> str | None:
        """Extract hostname from URL."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return parsed.netloc or None
        except Exception:
            return None
