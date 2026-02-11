"""Unified finding model for security findings from any tool."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from vinculum.models.enums import Confidence, FindingType, Severity


class FindingLocation(BaseModel):
    """Location where a finding was detected."""

    # For DAST/web findings
    url: str | None = None
    method: str | None = None  # HTTP method
    parameter: str | None = None  # Vulnerable parameter

    # For SAST/code findings
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None

    # For network findings
    host: str | None = None
    port: int | None = None
    protocol: str | None = None  # tcp, udp
    service: str | None = None  # ssh, http, etc.

    def normalized_key(self) -> str:
        """Return a normalized string key for this location."""
        parts = []
        if self.host:
            parts.append(f"host:{self.host}")
        if self.port:
            parts.append(f"port:{self.port}")
        if self.url:
            parts.append(f"url:{self.url}")
        if self.file_path:
            parts.append(f"file:{self.file_path}")
        if self.line_start:
            parts.append(f"line:{self.line_start}")
        return "|".join(sorted(parts)) if parts else "unknown"


class UnifiedFinding(BaseModel):
    """Unified representation of a security finding from any tool."""

    # Identity
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_tool: str  # "burp", "nessus", "semgrep", etc.
    source_id: str  # Original ID from the tool

    # Classification
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE

    # Vulnerability References
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss3_score: float | None = None
    cvss3_vector: str | None = None

    # Location
    location: FindingLocation = Field(default_factory=FindingLocation)

    # Context
    finding_type: FindingType = FindingType.OTHER
    evidence: str | None = None  # Request/response, code snippet, etc.
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)

    # Correlation
    fingerprint: str = ""  # Hash for deduplication
    correlation_id: str | None = None  # Links related findings across tools

    # Enrichment
    epss_score: float | None = None
    epss_percentile: float | None = None
    exploit_available: bool | None = None

    # Cross-tool enrichment
    exploitation_confirmed: bool = False
    confirmed_by: list[str] = Field(default_factory=list)

    # Metadata
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)

    def short_description(self, max_length: int = 100) -> str:
        """Return a truncated description for display."""
        if len(self.description) <= max_length:
            return self.description
        return self.description[: max_length - 3] + "..."

    def severity_icon(self) -> str:
        """Return an icon for the severity level."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return icons.get(Severity(self.severity), "⚪")


class CorrelationGroup(BaseModel):
    """A group of correlated findings that represent the same issue."""

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    findings: list[UnifiedFinding] = Field(default_factory=list)
    primary_finding: UnifiedFinding | None = None  # Representative finding
    provenance_chain: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity in the group."""
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: Severity(f.severity).numeric).severity

    @property
    def all_cves(self) -> set[str]:
        """Return all unique CVEs across findings."""
        cves = set()
        for finding in self.findings:
            cves.update(finding.cve_ids)
        return cves

    @property
    def tool_sources(self) -> set[str]:
        """Return all tools that detected this issue."""
        return {f.source_tool for f in self.findings}

    def add_finding(self, finding: UnifiedFinding) -> None:
        """Add a finding to this group."""
        finding.correlation_id = self.correlation_id
        self.findings.append(finding)
        # Update primary finding if this one is higher severity
        if self.primary_finding is None or Severity(finding.severity).numeric > Severity(
            self.primary_finding.severity
        ).numeric:
            self.primary_finding = finding
