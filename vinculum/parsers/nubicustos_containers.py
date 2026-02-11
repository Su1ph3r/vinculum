"""Parser for Nubicustos container inventory export JSON files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nubicustos_containers")


class NubicustosContainersParser(BaseParser):
    """
    Parser for Nubicustos container inventory export format (nubicustos-containers).

    Parses container inventory data from Kubernetes clusters and container
    runtimes, producing informational findings for each discovered container.
    """

    @property
    def tool_name(self) -> str:
        return "nubicustos:containers"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Detect by the 'format': 'nubicustos-containers' key."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return data.get("format") == "nubicustos-containers"
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nubicustos container inventory JSON file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if data.get("format") != "nubicustos-containers":
            raise ParseError(
                "Not a valid Nubicustos containers export (missing format key)",
                file_path,
            )

        containers = data.get("containers", [])
        if not containers:
            return []

        findings: list[UnifiedFinding] = []

        for container in containers:
            finding = self._parse_container(container)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} containers from {file_path}")
        return findings

    def _parse_container(self, container: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single container entry into a UnifiedFinding."""
        try:
            container_id = container.get("id", "")
            name = container.get("name", "")
            image = container.get("image", "")

            if not name and not image:
                logger.warning(
                    f"Skipping container with missing name and image: {container_id}"
                )
                return None

            host_ip = container.get("host_ip")
            node = container.get("node", "")
            namespace = container.get("namespace", "")
            runtime = container.get("runtime", "")
            privileged = container.get("privileged", False)
            ports = container.get("ports", [])
            status = container.get("status", "")
            labels = container.get("labels", {})

            # Use host_ip if available, fall back to node
            host = host_ip or node

            location = FindingLocation(
                host=host,
            )

            # Build tags from container metadata
            tags: list[str] = []
            if image:
                tags.append(f"image:{image}")
            if namespace:
                tags.append(f"namespace:{namespace}")
            if runtime:
                tags.append(f"runtime:{runtime}")
            if privileged:
                tags.append("privileged")
            if status:
                tags.append(f"status:{status}")
            if node:
                tags.append(f"node:{node}")

            # Add port tags
            for port_entry in ports:
                container_port = port_entry.get("container_port")
                port_protocol = port_entry.get("protocol", "TCP")
                if container_port is not None:
                    tags.append(f"port:{container_port}/{port_protocol}")

            # Add label tags
            for key, value in labels.items():
                tags.append(f"label:{key}={value}")

            title = f"Container inventory: {name} ({image})"
            description = (
                f"Container '{name}' running image {image} "
                f"in namespace {namespace or 'default'} on node {node or 'unknown'}"
            )
            if privileged:
                description += " [PRIVILEGED]"

            return UnifiedFinding(
                source_tool=self.tool_name,
                source_id=container_id,
                title=title,
                description=description,
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                location=location,
                finding_type=FindingType.CONTAINER,
                tags=tags,
                raw_data=container,
            )
        except Exception as e:
            logger.warning(f"Skipping malformed container: {e}")
            return None
