"""Parser for Cepheus container escape analysis JSON export files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.cepheus")


def _reliability_to_confidence(value: Any) -> Confidence:
    """Map Cepheus reliability score (float 0.0-1.0) to a Confidence bucket."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return Confidence.TENTATIVE
    if score >= 0.85:
        return Confidence.CERTAIN
    if score >= 0.6:
        return Confidence.FIRM
    return Confidence.TENTATIVE


class CepheusParser(BaseParser):
    """Parser for Cepheus container escape analysis JSON export format.

    Cepheus analyzes container environments for escape chains -- sequences
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

        findings: list[UnifiedFinding] = []
        emitted_technique_cves: set[str] = set()

        for chain in data.get("chains", []):
            chain_finding = self._parse_chain(chain, posture, remediations)
            if chain_finding:
                findings.append(chain_finding)

            for step in chain.get("steps", []):
                technique = step.get("technique") or {}
                technique_id = technique.get("id", "unknown")
                cve = technique.get("cve")
                if not cve:
                    continue
                key = f"{technique_id}-{cve}"
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

        techniques = [s.get("technique") or {} for s in steps]
        step_names = [t.get("name") or t.get("id") or "unknown" for t in techniques]
        title = "Container Escape: " + " -> ".join(step_names)

        severity = Severity.from_string(chain.get("severity", "high"))
        cvss_score = chain.get("composite_score")

        cve_ids: list[str] = []
        for t in techniques:
            cve = t.get("cve")
            if cve:
                cve_ids.append(cve)
        cve_ids = list(dict.fromkeys(cve_ids))

        tags: list[str] = []
        for t in techniques:
            for attack_id in t.get("mitre_attack", []) or []:
                tags.append(f"mitre:{attack_id}")

        # Lowest per-step reliability drives chain confidence.
        reliabilities = [t.get("reliability", 0.0) for t in techniques]
        try:
            min_reliability = min(float(r) for r in reliabilities) if reliabilities else 0.0
        except (TypeError, ValueError):
            min_reliability = 0.0
        confidence = _reliability_to_confidence(min_reliability)

        # Remediation keyed by technique id (matches data.remediations.technique).
        remediation_parts: list[str] = []
        for t in techniques:
            tid = t.get("id")
            if tid and tid in remediations:
                remediation_parts.append(f"- {tid}: {remediations[tid]}")
        remediation = "\n".join(remediation_parts) if remediation_parts else None

        # Container info comes from posture (chain has no container field).
        location = FindingLocation(
            host=posture.get("hostname"),
        )

        description = chain.get("description", f"Container escape chain with {len(steps)} steps.")

        return UnifiedFinding(
            source_tool="cepheus",
            source_id=chain.get("id", ""),
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
        technique = step.get("technique") or {}
        technique_id = technique.get("id", "unknown")
        technique_name = technique.get("name") or technique_id

        title = f"Container Vulnerability: {technique_name} ({cve})"

        severity = Severity.from_string(technique.get("severity", "medium"))
        confidence = _reliability_to_confidence(technique.get("reliability"))
        tags = [f"mitre:{aid}" for aid in (technique.get("mitre_attack", []) or [])]

        return UnifiedFinding(
            source_tool="cepheus",
            source_id=f"{technique_id}-{cve}",
            title=title,
            description=technique.get("description", ""),
            severity=severity,
            confidence=confidence,
            cve_ids=[cve],
            location=FindingLocation(host=posture.get("hostname")),
            finding_type=FindingType.CONTAINER,
            tags=tags,
            raw_data={"step": step, "posture": posture},
        )
