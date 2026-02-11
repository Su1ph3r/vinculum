"""Parser for Reticustos endpoint inventory export JSON files."""

import json
from pathlib import Path
from typing import Any

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.reticustos_endpoints")


class ReticustosEndpointsParser(BaseParser):
    """
    Parser for Reticustos endpoint inventory export format (reticustos-endpoints).

    Parses discovered API endpoints and web resources from Reticustos crawl,
    brute-force, and OpenAPI-based endpoint discovery scans.
    """

    @property
    def tool_name(self) -> str:
        return "reticustos:endpoints"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def supports_file(self, file_path: Path) -> bool:
        """Detect by the 'format': 'reticustos-endpoints' key."""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                return data.get("format") == "reticustos-endpoints"
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Reticustos endpoint inventory JSON file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to read file: {e}", file_path)

        if data.get("format") != "reticustos-endpoints":
            raise ParseError(
                "Not a valid Reticustos endpoints export (missing format key)",
                file_path,
            )

        endpoints = data.get("endpoints", [])
        if not endpoints:
            return []

        findings: list[UnifiedFinding] = []

        for endpoint in endpoints:
            finding = self._parse_endpoint(endpoint)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} endpoints from {file_path}")
        return findings

    def _parse_endpoint(self, endpoint: dict[str, Any]) -> UnifiedFinding | None:
        """Parse a single endpoint entry into a UnifiedFinding."""
        try:
            endpoint_id = endpoint.get("id", "")
            url = endpoint.get("url", "")
            method = endpoint.get("method", "")
            host = endpoint.get("host", "")

            if not url:
                logger.warning(f"Skipping endpoint with missing url: {endpoint_id}")
                return None

            port = endpoint.get("port")
            protocol = endpoint.get("protocol")
            content_type = endpoint.get("content_type", "")
            discovered_by = endpoint.get("discovered_by", "")
            status_code = endpoint.get("status_code")
            authenticated = endpoint.get("authenticated", False)
            parameters = endpoint.get("parameters", [])

            location = FindingLocation(
                url=url,
                method=method,
                host=host,
                port=port,
                protocol=protocol,
            )

            # Build tags from endpoint metadata
            tags: list[str] = []
            if discovered_by:
                tags.append(f"discovered_by:{discovered_by}")
            if content_type:
                tags.append(f"content_type:{content_type}")
            if authenticated:
                tags.append("authenticated")
            if parameters:
                for param in parameters:
                    tags.append(f"param:{param}")
            if status_code is not None:
                tags.append(f"status:{status_code}")

            title = f"Discovered endpoint: {method} {url}"
            description = (
                f"Endpoint discovered via {discovered_by or 'unknown'}: "
                f"{method} {url} (status {status_code})"
            )

            return UnifiedFinding(
                source_tool=self.tool_name,
                source_id=endpoint_id,
                title=title,
                description=description,
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                location=location,
                finding_type=FindingType.DAST,
                tags=tags,
                raw_data=endpoint,
            )
        except Exception as e:
            logger.warning(f"Skipping malformed endpoint: {e}")
            return None
