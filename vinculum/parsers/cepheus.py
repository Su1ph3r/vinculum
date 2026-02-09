"""Parser for Cepheus container escape analysis JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.cepheus")

# Reliability to confidence mapping
RELIABILITY_CONFIDENCE = {
    "high": Confidence.CERTAIN,
    "medium": Confidence.FIRM,
    "low": Confidence.TENTATIVE,
}


class CepheusParser(BaseParser):
    """
    Parser for Cepheus container escape analysis JSON export format.

    Cepheus analyzes container environments for escape chains — sequences
    of techniques that could allow container breakout. It also assesses
    overall container security posture.
    """

    @property
    def tool_name(self) -> str:
        return "cepheus"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Cepheus export by looking for signature keys."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return "chains" in data and "posture" in data
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Cepheus JSON export file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if "chains" not in data or "posture" not in data:
            raise ParseError("Not a valid Cepheus export", file_path)

        posture = data.get("posture", {})
        remediations = {
            r["technique"]: r["description"]
            for r in data.get("remediations", [])
            if "technique" in r and "description" in r
        }

        findings = []
        emitted_technique_cves: set[str] = set()

        for chain in data.get("chains", []):
            # One finding per escape chain
            chain_finding = self._parse_chain(chain, posture, remediations)
            if chain_finding:
                findings.append(chain_finding)

            # Standalone findings for techniques with CVEs (deduplicated across chains)
            for step in chain.get("steps", []):
                technique = step.get("technique", "unknown")
                for cve in step.get("cves", []):
                    key = f"{technique}-{cve}"
                    if key in emitted_technique_cves:
                        continue
                    emitted_technique_cves.add(key)
                    technique_finding = self._parse_technique_cve(step, cve, posture)
                    if technique_finding:
                        findings.append(technique_finding)

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def _parse_chain(
        self,
        chain: dict[str, Any],
        posture: dict[str, Any],
        remediations: dict[str, str],
    ) -> UnifiedFinding | None:
        """Parse a container escape chain into a single finding."""
        steps = chain.get("steps", [])
        if not steps:
            return None

        # Build chain title from step names
        step_names = [s.get("technique", "unknown") for s in steps]
        title = "Container Escape: " + " → ".join(step_names)

        severity = Severity.from_string(chain.get("severity", "high"))
        cvss_score = chain.get("composite_score")

        # Collect all CVEs from all steps
        cve_ids = []
        for step in steps:
            cve_ids.extend(step.get("cves", []))
        cve_ids = list(set(cve_ids))

        # Build tags from MITRE ATT&CK IDs
        tags = []
        for step in steps:
            for attack_id in step.get("mitre_attack", []):
                tags.append(f"mitre:{attack_id}")

        # Map reliability to confidence (use lowest reliability in chain)
        reliability_order = {"high": 2, "medium": 1, "low": 0}
        min_reliability = "high"
        for step in steps:
            step_rel = step.get("reliability", "low")
            if reliability_order.get(step_rel, 0) < reliability_order.get(min_reliability, 2):
                min_reliability = step_rel
        confidence = RELIABILITY_CONFIDENCE.get(min_reliability, Confidence.TENTATIVE)

        # Build remediation from matching techniques
        remediation_parts = []
        for step_name in step_names:
            if step_name in remediations:
                remediation_parts.append(f"- {step_name}: {remediations[step_name]}")
        remediation = "\n".join(remediation_parts) if remediation_parts else None

        # Build location from container info
        container = chain.get("container", {})
        location = FindingLocation(
            host=container.get("hostname") or container.get("container_id"),
        )

        # Description from chain
        description = chain.get("description", f"Container escape chain with {len(steps)} steps.")

        return UnifiedFinding(
            source_tool="cepheus",
            source_id=chain.get("chain_id", ""),
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            location=location,
            finding_type=FindingType.CONTAINER,
            remediation=remediation,
            tags=tags,
            raw_data={"chain": chain, "posture": posture},
        )

    def _parse_technique_cve(
        self,
        step: dict[str, Any],
        cve: str,
        posture: dict[str, Any],
    ) -> UnifiedFinding | None:
        """Parse a standalone finding for a technique with a CVE."""
        technique = step.get("technique", "unknown")
        title = f"Container Vulnerability: {technique} ({cve})"

        severity = Severity.from_string(step.get("severity", "medium"))
        reliability = step.get("reliability", "low")
        confidence = RELIABILITY_CONFIDENCE.get(reliability, Confidence.TENTATIVE)

        tags = [f"mitre:{aid}" for aid in step.get("mitre_attack", [])]

        return UnifiedFinding(
            source_tool="cepheus",
            source_id=f"{technique}-{cve}",
            title=title,
            description=step.get("description", ""),
            severity=severity,
            confidence=confidence,
            cve_ids=[cve],
            finding_type=FindingType.CONTAINER,
            tags=tags,
            raw_data={"step": step, "posture": posture},
        )
