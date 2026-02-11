"""Parser for Ariadne attack path report JSON files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.ariadne_report")

# Node type to FindingType mapping
NODE_TYPE_FINDING_MAP: dict[str, FindingType] = {
    "entry_point": FindingType.DAST,
    "vulnerability": FindingType.DAST,
    "service": FindingType.NETWORK,
    "host": FindingType.NETWORK,
    "container": FindingType.CONTAINER,
    "asset": FindingType.OTHER,
    "cloud_resource": FindingType.CLOUD,
}


class AriadneReportParser(BaseParser):
    """
    Parser for Ariadne attack path report format (ariadne-report).

    Parses attack path analysis reports that map multi-step attack chains
    through infrastructure, producing a finding per attack path with severity
    derived from the highest-severity node in the path.
    """

    @property
    def tool_name(self) -> str:
        return "ariadne:report"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Detect by the 'format': 'ariadne-report' key."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return data.get("format") == "ariadne-report"
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Ariadne attack path report JSON file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if data.get("format") != "ariadne-report":
            raise ParseError(
                "Not a valid Ariadne report (missing format key)", file_path
            )

        attack_paths = data.get("attack_paths", [])
        if not attack_paths:
            return []

        findings: list[UnifiedFinding] = []
        skipped = 0
        total = len(attack_paths)

        for path in attack_paths:
            try:
                finding = self._parse_attack_path(path)
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

        logger.info(f"Parsed {len(findings)} attack paths from {file_path}")
        return findings

    def _parse_attack_path(self, path: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single attack path into a UnifiedFinding."""
        path_id = path.get("id", "")
        title = path.get("title", "")
        description = path.get("description", "")
        nodes = path.get("nodes", [])

        if not title:
            logger.warning(f"Skipping attack path with missing title: {path_id}")
            return None

        # Determine severity from the highest-severity node
        severity = self._highest_node_severity(nodes)

        # Map confidence
        confidence = Confidence.from_string(path.get("confidence", "tentative"))

        # Determine finding type from node types
        finding_type = self._determine_finding_type(nodes)

        # Extract all CVEs and CWEs from nodes
        cve_ids: list[str] = []
        cwe_ids: list[str] = []
        for node in nodes:
            cve_ids.extend(node.get("cve_ids", []))
            cwe_ids.extend(node.get("cwe_ids", []))
        cve_ids = list(set(cve_ids))
        cwe_ids = list(set(cwe_ids))

        # Build location from the first node with host info
        location = self._build_location(nodes)

        # Build tags
        tags: list[str] = []
        for technique in path.get("mitre_techniques", []):
            tags.append(f"mitre:technique:{technique}")
        tags.append(f"path_nodes:{len(nodes)}")
        tags.append(f"path_edges:{len(path.get('edges', []))}")

        # Add node type tags
        node_types = set()
        for node in nodes:
            node_type = node.get("type", "")
            if node_type:
                node_types.add(node_type)
        for nt in sorted(node_types):
            tags.append(f"node_type:{nt}")

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=path_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            location=location,
            finding_type=finding_type,
            evidence=path.get("playbook"),
            tags=tags,
            raw_data=path,
        )

    def _highest_node_severity(self, nodes: list[dict[str, Any]]) -> Severity:
        """Return the highest severity found across all nodes."""
        max_severity = Severity.INFO
        for node in nodes:
            node_severity = Severity.from_string(node.get("severity", "info"))
            if node_severity.numeric > max_severity.numeric:
                max_severity = node_severity
        return max_severity

    def _determine_finding_type(self, nodes: list[dict[str, Any]]) -> FindingType:
        """Determine finding type based on node types in the path."""
        type_counts: dict[FindingType, int] = {}
        for node in nodes:
            node_type = node.get("type", "")
            finding_type = NODE_TYPE_FINDING_MAP.get(node_type, FindingType.OTHER)
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

        if not type_counts:
            return FindingType.OTHER

        # Return the most common finding type (excluding OTHER if alternatives exist)
        non_other = {k: v for k, v in type_counts.items() if k != FindingType.OTHER}
        if non_other:
            return max(non_other, key=non_other.get)  # type: ignore[arg-type]
        return FindingType.OTHER

    def _build_location(self, nodes: list[dict[str, Any]]) -> FindingLocation:
        """Build a FindingLocation from the first node with host information."""
        for node in nodes:
            host = node.get("host")
            if host:
                return FindingLocation(
                    host=host,
                    port=node.get("port"),
                )
        return FindingLocation()
