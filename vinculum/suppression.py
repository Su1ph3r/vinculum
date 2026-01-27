"""Finding suppression rules for Vinculum."""

import fnmatch
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from vinculum.logging import get_logger
from vinculum.models.finding import UnifiedFinding

logger = get_logger("suppression")


class SuppressionRule(BaseModel):
    """A rule for suppressing findings."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique identifier for this rule")
    reason: str = Field(..., description="Reason for suppression")
    fingerprint: str | None = Field(None, description="Exact fingerprint to match")
    title_pattern: str | None = Field(None, description="Glob pattern to match title")
    title_regex: str | None = Field(None, description="Regex pattern to match title")
    cwe_ids: list[str] | None = Field(None, description="CWE IDs to suppress")
    cve_ids: list[str] | None = Field(None, description="CVE IDs to suppress")
    source_tool: str | None = Field(None, description="Source tool name to match")
    severity: list[str] | None = Field(None, description="Severity levels to suppress")
    expires: datetime | None = Field(None, description="Expiration date for the rule")

    def is_expired(self) -> bool:
        """Check if this rule has expired."""
        if self.expires is None:
            return False
        return datetime.now() > self.expires

    def matches(self, finding: UnifiedFinding) -> bool:
        """
        Check if a finding matches this suppression rule.

        A finding matches if ALL specified criteria match (AND logic).
        At least one criterion must be specified for a match.

        Args:
            finding: The finding to check

        Returns:
            True if the finding matches this rule
        """
        if self.is_expired():
            return False

        # Track which criteria were specified and matched
        criteria_specified = False
        all_matched = True

        # Check fingerprint
        if self.fingerprint is not None:
            criteria_specified = True
            if finding.fingerprint != self.fingerprint:
                all_matched = False

        # Check title pattern (glob)
        if self.title_pattern is not None:
            criteria_specified = True
            if not fnmatch.fnmatch(finding.title.lower(), self.title_pattern.lower()):
                all_matched = False

        # Check title regex
        if self.title_regex is not None:
            criteria_specified = True
            try:
                if not re.search(self.title_regex, finding.title, re.IGNORECASE):
                    all_matched = False
            except re.error:
                logger.warning(f"Invalid regex in suppression rule {self.id}: {self.title_regex}")
                all_matched = False

        # Check CWE IDs (any match)
        if self.cwe_ids is not None:
            criteria_specified = True
            finding_cwes = set(finding.cwe_ids) if finding.cwe_ids else set()
            rule_cwes = set(self.cwe_ids)
            if not finding_cwes & rule_cwes:
                all_matched = False

        # Check CVE IDs (any match)
        if self.cve_ids is not None:
            criteria_specified = True
            finding_cves = set(finding.cve_ids) if finding.cve_ids else set()
            rule_cves = set(self.cve_ids)
            if not finding_cves & rule_cves:
                all_matched = False

        # Check source tool
        if self.source_tool is not None:
            criteria_specified = True
            if finding.source_tool.lower() != self.source_tool.lower():
                all_matched = False

        # Check severity
        if self.severity is not None:
            criteria_specified = True
            severity_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            if severity_str.lower() not in [s.lower() for s in self.severity]:
                all_matched = False

        # Must have at least one criterion specified to match
        return criteria_specified and all_matched


class SuppressionResult(BaseModel):
    """Result of applying suppression rules."""

    model_config = ConfigDict(extra="ignore")

    kept: list[UnifiedFinding] = Field(default_factory=list)
    suppressed: list[tuple[UnifiedFinding, SuppressionRule]] = Field(default_factory=list)

    @property
    def kept_count(self) -> int:
        """Number of findings kept."""
        return len(self.kept)

    @property
    def suppressed_count(self) -> int:
        """Number of findings suppressed."""
        return len(self.suppressed)


class SuppressionManager:
    """Manager for finding suppression rules."""

    def __init__(self, rules: list[SuppressionRule] | None = None):
        """
        Initialize suppression manager.

        Args:
            rules: List of suppression rules
        """
        self.rules = rules or []
        self._active_rules: list[SuppressionRule] = []
        self._refresh_active_rules()

    def _refresh_active_rules(self) -> None:
        """Refresh the list of active (non-expired) rules."""
        self._active_rules = [r for r in self.rules if not r.is_expired()]
        expired_count = len(self.rules) - len(self._active_rules)
        if expired_count > 0:
            logger.info(f"Skipped {expired_count} expired suppression rule(s)")

    def add_rule(self, rule: SuppressionRule) -> None:
        """Add a suppression rule."""
        self.rules.append(rule)
        self._refresh_active_rules()

    def add_rules(self, rules: list[SuppressionRule]) -> None:
        """Add multiple suppression rules."""
        self.rules.extend(rules)
        self._refresh_active_rules()

    @classmethod
    def from_config(cls, suppression_dicts: list[dict]) -> "SuppressionManager":
        """
        Create a SuppressionManager from configuration dictionaries.

        Args:
            suppression_dicts: List of suppression rule dictionaries

        Returns:
            SuppressionManager instance
        """
        rules = []
        for data in suppression_dicts:
            try:
                # Handle expires field conversion
                if "expires" in data and isinstance(data["expires"], str):
                    data["expires"] = datetime.fromisoformat(data["expires"])
                rules.append(SuppressionRule(**data))
            except Exception as e:
                logger.warning(f"Skipping invalid suppression rule: {e}")
        return cls(rules=rules)

    def filter_findings(
        self, findings: list[UnifiedFinding]
    ) -> SuppressionResult:
        """
        Filter findings by applying suppression rules.

        Args:
            findings: List of findings to filter

        Returns:
            SuppressionResult containing kept and suppressed findings
        """
        result = SuppressionResult()

        for finding in findings:
            matched_rule = None

            for rule in self._active_rules:
                if rule.matches(finding):
                    matched_rule = rule
                    break

            if matched_rule:
                result.suppressed.append((finding, matched_rule))
                logger.debug(
                    f"Suppressed finding '{finding.title}' by rule '{matched_rule.id}'"
                )
            else:
                result.kept.append(finding)

        if result.suppressed_count > 0:
            logger.info(
                f"Suppressed {result.suppressed_count} finding(s), "
                f"kept {result.kept_count} finding(s)"
            )

        return result
