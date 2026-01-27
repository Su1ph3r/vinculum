"""Parser for Burp Suite XML export files."""

import base64
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.parsers.base import BaseParser, ParseError


class BurpParser(BaseParser):
    """Parser for Burp Suite XML export format."""

    @property
    def tool_name(self) -> str:
        return "burp"

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def supports_file(self, file_path: Path) -> bool:
        """Check if file is a Burp XML export by looking for signature."""
        if file_path.suffix.lower() != ".xml":
            return False
        try:
            # Read first few KB to check for Burp signature
            with open(file_path, "rb") as f:
                header = f.read(2048).decode("utf-8", errors="ignore")
                return "<issues" in header or "burp" in header.lower()
        except Exception:
            return False

    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """Parse Burp Suite XML export file."""
        findings = []
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            for issue in root.findall(".//issue"):
                finding = self._parse_issue(issue)
                if finding:
                    findings.append(finding)

        except ET.ParseError as e:
            raise ParseError(f"Invalid XML: {e}", file_path)
        except Exception as e:
            raise ParseError(f"Failed to parse: {e}", file_path)

        return findings

    def _parse_issue(self, issue: Element) -> UnifiedFinding | None:
        """Parse a single Burp issue element."""
        # Extract basic fields
        serial_number = self._get_text(issue, "serialNumber", "unknown")
        issue_type = self._get_text(issue, "type", "")
        name = self._get_text(issue, "name", "Unknown Issue")
        host = self._get_text(issue, "host", "")
        path = self._get_text(issue, "path", "")
        location_text = self._get_text(issue, "location", "")

        # Build URL
        url = ""
        if host:
            url = host
            if path:
                url = f"{host.rstrip('/')}/{path.lstrip('/')}"

        # Extract severity and confidence
        severity_text = self._get_text(issue, "severity", "Information")
        confidence_text = self._get_text(issue, "confidence", "Tentative")

        # Extract descriptions
        issue_background = self._get_text(issue, "issueBackground", "")
        issue_detail = self._get_text(issue, "issueDetail", "")
        remediation_background = self._get_text(issue, "remediationBackground", "")
        remediation_detail = self._get_text(issue, "remediationDetail", "")

        description = issue_detail or issue_background
        remediation = remediation_detail or remediation_background

        # Extract request/response as evidence
        evidence_parts = []
        for req_resp in issue.findall(".//requestresponse"):
            request = self._get_text(req_resp, "request", "")
            response = self._get_text(req_resp, "response", "")

            # Handle base64 encoded content
            req_elem = req_resp.find("request")
            if req_elem is not None and req_elem.get("base64") == "true" and request:
                try:
                    request = base64.b64decode(request).decode("utf-8", errors="replace")
                except Exception:
                    pass

            resp_elem = req_resp.find("response")
            if resp_elem is not None and resp_elem.get("base64") == "true" and response:
                try:
                    response = base64.b64decode(response).decode("utf-8", errors="replace")
                except Exception:
                    pass

            if request:
                evidence_parts.append(f"REQUEST:\n{request[:2000]}")
            if response:
                evidence_parts.append(f"RESPONSE:\n{response[:2000]}")

        evidence = "\n\n".join(evidence_parts) if evidence_parts else None

        # Extract CWE if present in vulnerability classifications
        cwe_ids = []
        for classification in issue.findall(".//vulnerabilityClassifications"):
            text = classification.text or ""
            if "CWE-" in text:
                cwes = re.findall(r"CWE-(\d+)", text)
                cwe_ids.extend([f"CWE-{cwe}" for cwe in cwes])

        # Parse HTTP method from location
        method = None
        parameter = None
        if location_text:
            # Location often contains method and parameter info
            if " " in location_text:
                parts = location_text.split()
                if parts[0] in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                    method = parts[0]
            # Try to extract parameter
            if "parameter" in location_text.lower():
                param_match = re.search(r"parameter\s+['\"]?(\w+)['\"]?", location_text, re.I)
                if param_match:
                    parameter = param_match.group(1)

        location = FindingLocation(
            url=url or None,
            host=self._extract_host(host) if host else None,
            method=method,
            parameter=parameter,
        )

        return UnifiedFinding(
            source_tool=self.tool_name,
            source_id=f"{issue_type}:{serial_number}",
            title=name,
            description=self._clean_html(description),
            severity=Severity.from_string(severity_text),
            confidence=Confidence.from_string(confidence_text),
            cwe_ids=list(set(cwe_ids)),
            location=location,
            finding_type=FindingType.DAST,
            evidence=evidence,
            remediation=self._clean_html(remediation) if remediation else None,
            raw_data={
                "serial_number": serial_number,
                "issue_type": issue_type,
                "location": location_text,
            },
        )

    def _get_text(self, element: Element, tag: str, default: str = "") -> str:
        """Safely get text content from a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text
        return default

    def _extract_host(self, url: str) -> str | None:
        """Extract hostname from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            return None

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        # Remove HTML tags
        clean = re.sub(r"<[^>]+>", "", text)
        # Normalize whitespace
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean
