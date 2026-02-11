"""Parser for Nikto XML scan output files."""

from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.logging import get_logger
from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError

logger = get_logger("parsers.nikto")

# Keywords for severity heuristic classification
_HIGH_KEYWORDS = [
    "remote code execution",
    "command injection",
    "sql injection",
    "rce",
    "arbitrary code",
    "shell injection",
]
_MEDIUM_KEYWORDS = [
    "cross-site scripting",
    "xss",
    "directory traversal",
    "file inclusion",
    "path traversal",
    "local file inclusion",
    "remote file inclusion",
    "open redirect",
]
_LOW_KEYWORDS = [
    "information disclosure",
    "version disclosure",
    "header",
    "server leaks",
    "directory indexing",
    "directory listing",
]


class NiktoParser(BaseParser):
    """
    Parser for Nikto web scanner XML output format.

    Nikto is a web server scanner that tests for dangerous files/CGIs,
    outdated server software, and other problems.
    """

    @property
    def tool_name(self) -> str:
        return "nikto"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Nikto XML export by looking for signature."""
        if file_path.suffix.lower() != ".xml":
            return False
        try:
            with open(file_path, "rb") as f:
                header = f.read(2048).decode("utf-8", errors="ignore")
                return "niktoscan" in header.lower()
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Nikto XML output file."""
        findings = []

        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            for scan_details in root.findall(".//scandetails"):
                target_ip = scan_details.get("targetip", "")
                target_hostname = scan_details.get("targethostname", "")
                target_port = scan_details.get("targetport", "")
                target_banner = scan_details.get("targetbanner", "")

                for item in scan_details.findall("item"):
                    try:
                        finding = self._parse_item(
                            item,
                            target_ip,
                            target_hostname,
                            target_port,
                            target_banner,
                        )
                        if finding:
                            findings.append(finding)
                    except Exception as e:
                        item_id = item.get("id", "unknown")
                        logger.warning(
                            "Skipping malformed Nikto item %s: %s", item_id, e
                        )
                        continue

        except ET.ParseError as e:
            raise ParseError(f"Invalid XML: {e}", file_path)
        except ParseError:
            raise
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        logger.info("Parsed %d findings from %s", len(findings), file_path)
        return findings

    def _parse_item(
        self,
        item: Element,
        target_ip: str,
        target_hostname: str,
        target_port: str,
        target_banner: str,
    ) -> UnifiedFinding | None:
        """Parse a single Nikto item element."""
        item_id = item.get("id", "")
        osvdb_id = item.get("osvdbid", "0")
        osvdb_link = item.get("osvdblink", "")
        method = item.get("method", "")

        description = self._get_text(item, "description", "")
        uri = self._get_text(item, "uri", "")
        name_link = self._get_text(item, "namelink", "")
        ip_link = self._get_text(item, "iplink", "")

        if not description and not item_id:
            return None

        # Determine URL for location
        url = name_link or ip_link or None
        if not url and (target_hostname or target_ip) and target_port:
            host = target_hostname or target_ip
            url = f"https://{host}:{target_port}{uri}" if uri else f"https://{host}:{target_port}/"

        # Determine severity from description keywords
        has_osvdb = osvdb_id and osvdb_id != "0"
        severity = self._classify_severity(description, has_osvdb)

        # Build references
        references = []
        if osvdb_link:
            references.append(osvdb_link)

        # Build tags
        tags = ["nikto"]
        if has_osvdb:
            tags.append(f"osvdb:{osvdb_id}")

        # Extract host and port from target info
        host = target_hostname or target_ip or None
        port = int(target_port) if target_port and target_port.isdigit() else None

        location = FindingLocation(
            url=url,
            method=method or None,
            host=host,
            port=port,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=item_id,
            title=description[:120] if description else f"Nikto Finding {item_id}",
            description=description,
            severity=severity,
            confidence=Confidence.FIRM,
            location=location,
            finding_type=FindingType.DAST,
            references=references,
            tags=tags,
            raw_data={
                "item_id": item_id,
                "osvdb_id": osvdb_id,
                "uri": uri,
                "method": method,
                "target_banner": target_banner,
            },
        )

    def _classify_severity(self, description: str, has_osvdb: bool) -> Severity:
        """Classify severity based on description keywords and OSVDB presence."""
        desc_lower = description.lower()

        base_severity = Severity.LOW

        for keyword in _HIGH_KEYWORDS:
            if keyword in desc_lower:
                base_severity = Severity.HIGH
                break

        if base_severity == Severity.LOW:
            for keyword in _MEDIUM_KEYWORDS:
                if keyword in desc_lower:
                    base_severity = Severity.MEDIUM
                    break

        # Bump severity by one level if OSVDB reference exists
        if has_osvdb:
            bump_map = {
                Severity.LOW: Severity.MEDIUM,
                Severity.MEDIUM: Severity.HIGH,
                Severity.HIGH: Severity.CRITICAL,
                Severity.CRITICAL: Severity.CRITICAL,
            }
            base_severity = bump_map.get(base_severity, base_severity)

        return base_severity

    def _get_text(self, element: Element, tag: str, default: str = "") -> str:
        """Safely get text content from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
