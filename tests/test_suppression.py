"""Tests for finding suppression rules."""

from datetime import datetime, timedelta

import pytest

from vinculum.models.enums import Confidence, FindingType, Severity
from vinculum.models.finding import FindingLocation, UnifiedFinding
from vinculum.suppression import SuppressionManager, SuppressionResult, SuppressionRule


class TestSuppressionRule:
    """Tests for SuppressionRule model."""

    def _create_finding(
        self,
        title: str = "Test XSS Vulnerability",
        fingerprint: str = "abc123",
        cwe_ids: list[str] | None = None,
        cve_ids: list[str] | None = None,
        source_tool: str = "burp",
        severity: Severity = Severity.HIGH,
    ) -> UnifiedFinding:
        """Create a sample finding for testing."""
        return UnifiedFinding(
            source_tool=source_tool,
            source_id="test-001",
            title=title,
            description="Test description",
            severity=severity,
            confidence=Confidence.FIRM,
            cwe_ids=cwe_ids or ["CWE-79"],
            cve_ids=cve_ids or [],
            location=FindingLocation(url="https://example.com/test"),
            finding_type=FindingType.DAST,
            fingerprint=fingerprint,
        )

    def test_match_by_fingerprint(self):
        """Test matching by fingerprint."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            fingerprint="abc123",
        )
        finding = self._create_finding(fingerprint="abc123")
        assert rule.matches(finding) is True

        finding2 = self._create_finding(fingerprint="xyz789")
        assert rule.matches(finding2) is False

    def test_match_by_title_pattern(self):
        """Test matching by title glob pattern."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            title_pattern="*XSS*",
        )
        finding = self._create_finding(title="Test XSS Vulnerability")
        assert rule.matches(finding) is True

        finding2 = self._create_finding(title="SQL Injection")
        assert rule.matches(finding2) is False

    def test_match_by_title_regex(self):
        """Test matching by title regex."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            title_regex=r"XSS|Cross.Site.Scripting",
        )
        finding = self._create_finding(title="Reflected XSS in search")
        assert rule.matches(finding) is True

        finding2 = self._create_finding(title="Cross Site Scripting Detected")
        assert rule.matches(finding2) is True

        finding3 = self._create_finding(title="SQL Injection")
        assert rule.matches(finding3) is False

    def test_match_by_cwe_ids(self):
        """Test matching by CWE IDs."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            cwe_ids=["CWE-79", "CWE-80"],
        )
        finding = self._create_finding(cwe_ids=["CWE-79"])
        assert rule.matches(finding) is True

        finding2 = self._create_finding(cwe_ids=["CWE-89"])
        assert rule.matches(finding2) is False

    def test_match_by_cve_ids(self):
        """Test matching by CVE IDs."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            cve_ids=["CVE-2021-44228"],
        )
        finding = self._create_finding(cve_ids=["CVE-2021-44228", "CVE-2021-45046"])
        assert rule.matches(finding) is True

        finding2 = self._create_finding(cve_ids=["CVE-2023-12345"])
        assert rule.matches(finding2) is False

    def test_match_by_source_tool(self):
        """Test matching by source tool."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            source_tool="burp",
        )
        finding = self._create_finding(source_tool="burp")
        assert rule.matches(finding) is True

        finding2 = self._create_finding(source_tool="zap")
        assert rule.matches(finding2) is False

    def test_match_by_severity(self):
        """Test matching by severity."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            severity=["info", "low"],
        )
        finding = self._create_finding(severity=Severity.INFO)
        assert rule.matches(finding) is True

        finding2 = self._create_finding(severity=Severity.LOW)
        assert rule.matches(finding2) is True

        finding3 = self._create_finding(severity=Severity.HIGH)
        assert rule.matches(finding3) is False

    def test_match_multiple_criteria_and_logic(self):
        """Test that multiple criteria use AND logic."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            source_tool="burp",
            cwe_ids=["CWE-79"],
        )
        # Both criteria match
        finding = self._create_finding(source_tool="burp", cwe_ids=["CWE-79"])
        assert rule.matches(finding) is True

        # Only one criterion matches
        finding2 = self._create_finding(source_tool="zap", cwe_ids=["CWE-79"])
        assert rule.matches(finding2) is False

        finding3 = self._create_finding(source_tool="burp", cwe_ids=["CWE-89"])
        assert rule.matches(finding3) is False

    def test_expired_rule_does_not_match(self):
        """Test that expired rules do not match."""
        past_date = datetime.now() - timedelta(days=1)
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            fingerprint="abc123",
            expires=past_date,
        )
        finding = self._create_finding(fingerprint="abc123")
        assert rule.matches(finding) is False
        assert rule.is_expired() is True

    def test_future_expiration_matches(self):
        """Test that rules with future expiration still match."""
        future_date = datetime.now() + timedelta(days=30)
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            fingerprint="abc123",
            expires=future_date,
        )
        finding = self._create_finding(fingerprint="abc123")
        assert rule.matches(finding) is True
        assert rule.is_expired() is False

    def test_no_criteria_does_not_match(self):
        """Test that rules with no criteria do not match anything."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
        )
        finding = self._create_finding()
        assert rule.matches(finding) is False

    def test_case_insensitive_title_pattern(self):
        """Test that title pattern matching is case-insensitive."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            title_pattern="*xss*",
        )
        finding = self._create_finding(title="XSS Vulnerability")
        assert rule.matches(finding) is True

    def test_case_insensitive_source_tool(self):
        """Test that source tool matching is case-insensitive."""
        rule = SuppressionRule(
            id="test-1",
            reason="Test",
            source_tool="BURP",
        )
        finding = self._create_finding(source_tool="burp")
        assert rule.matches(finding) is True


class TestSuppressionManager:
    """Tests for SuppressionManager."""

    def _create_finding(
        self,
        title: str = "Test Vulnerability",
        fingerprint: str = "abc123",
        cwe_ids: list[str] | None = None,
        severity: Severity = Severity.HIGH,
    ) -> UnifiedFinding:
        """Create a sample finding for testing."""
        return UnifiedFinding(
            source_tool="test",
            source_id="test-001",
            title=title,
            description="Test description",
            severity=severity,
            confidence=Confidence.FIRM,
            cwe_ids=cwe_ids or ["CWE-79"],
            cve_ids=[],
            location=FindingLocation(url="https://example.com/test"),
            finding_type=FindingType.DAST,
            fingerprint=fingerprint,
        )

    def test_filter_findings_suppresses_matched(self):
        """Test that filter_findings suppresses matched findings."""
        manager = SuppressionManager(
            rules=[
                SuppressionRule(
                    id="suppress-xss",
                    reason="False positive",
                    title_pattern="*XSS*",
                )
            ]
        )

        findings = [
            self._create_finding(title="XSS Vulnerability"),
            self._create_finding(title="SQL Injection"),
        ]

        result = manager.filter_findings(findings)

        assert result.kept_count == 1
        assert result.suppressed_count == 1
        assert result.kept[0].title == "SQL Injection"
        assert result.suppressed[0][0].title == "XSS Vulnerability"
        assert result.suppressed[0][1].id == "suppress-xss"

    def test_filter_findings_with_no_rules(self):
        """Test filter_findings with no rules keeps all findings."""
        manager = SuppressionManager()

        findings = [
            self._create_finding(title="Finding 1"),
            self._create_finding(title="Finding 2"),
        ]

        result = manager.filter_findings(findings)

        assert result.kept_count == 2
        assert result.suppressed_count == 0

    def test_filter_findings_with_multiple_rules(self):
        """Test filter_findings with multiple rules."""
        manager = SuppressionManager(
            rules=[
                SuppressionRule(
                    id="suppress-xss",
                    reason="False positive",
                    cwe_ids=["CWE-79"],
                ),
                SuppressionRule(
                    id="suppress-sqli",
                    reason="Accepted risk",
                    cwe_ids=["CWE-89"],
                ),
            ]
        )

        findings = [
            self._create_finding(title="XSS", cwe_ids=["CWE-79"]),
            self._create_finding(title="SQLi", cwe_ids=["CWE-89"]),
            self._create_finding(title="XXE", cwe_ids=["CWE-611"]),
        ]

        result = manager.filter_findings(findings)

        assert result.kept_count == 1
        assert result.suppressed_count == 2
        assert result.kept[0].title == "XXE"

    def test_from_config(self):
        """Test creating SuppressionManager from config dictionaries."""
        config = [
            {
                "id": "supp-1",
                "reason": "Test reason",
                "fingerprint": "abc123",
            },
            {
                "id": "supp-2",
                "reason": "Another reason",
                "cwe_ids": ["CWE-79"],
            },
        ]

        manager = SuppressionManager.from_config(config)

        assert len(manager.rules) == 2
        assert manager.rules[0].id == "supp-1"
        assert manager.rules[1].cwe_ids == ["CWE-79"]

    def test_from_config_with_expires_string(self):
        """Test creating SuppressionManager with ISO date string expires."""
        future_date = (datetime.now() + timedelta(days=30)).isoformat()
        config = [
            {
                "id": "supp-1",
                "reason": "Test",
                "fingerprint": "abc123",
                "expires": future_date,
            },
        ]

        manager = SuppressionManager.from_config(config)

        assert len(manager.rules) == 1
        assert manager.rules[0].expires is not None
        assert not manager.rules[0].is_expired()

    def test_from_config_skips_invalid_rules(self):
        """Test that from_config skips invalid rule configurations."""
        config = [
            {
                "id": "valid",
                "reason": "Test",
                "fingerprint": "abc123",
            },
            {
                # Missing required 'id' field
                "reason": "Invalid",
            },
        ]

        manager = SuppressionManager.from_config(config)

        assert len(manager.rules) == 1
        assert manager.rules[0].id == "valid"

    def test_add_rule(self):
        """Test adding a rule to the manager."""
        manager = SuppressionManager()
        rule = SuppressionRule(
            id="test",
            reason="Test",
            fingerprint="abc123",
        )

        manager.add_rule(rule)

        assert len(manager.rules) == 1
        assert manager.rules[0].id == "test"

    def test_add_rules(self):
        """Test adding multiple rules to the manager."""
        manager = SuppressionManager()
        rules = [
            SuppressionRule(id="test-1", reason="Test 1", fingerprint="abc"),
            SuppressionRule(id="test-2", reason="Test 2", fingerprint="xyz"),
        ]

        manager.add_rules(rules)

        assert len(manager.rules) == 2

    def test_expired_rules_not_active(self):
        """Test that expired rules are not in active rules."""
        past_date = datetime.now() - timedelta(days=1)
        future_date = datetime.now() + timedelta(days=30)

        manager = SuppressionManager(
            rules=[
                SuppressionRule(
                    id="expired",
                    reason="Old rule",
                    fingerprint="abc",
                    expires=past_date,
                ),
                SuppressionRule(
                    id="active",
                    reason="New rule",
                    fingerprint="xyz",
                    expires=future_date,
                ),
            ]
        )

        assert len(manager.rules) == 2
        assert len(manager._active_rules) == 1
        assert manager._active_rules[0].id == "active"


class TestSuppressionResult:
    """Tests for SuppressionResult model."""

    def _create_finding(self, title: str = "Test") -> UnifiedFinding:
        """Create a sample finding."""
        return UnifiedFinding(
            source_tool="test",
            source_id="test-001",
            title=title,
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            cwe_ids=["CWE-79"],
            cve_ids=[],
            location=FindingLocation(url="https://example.com"),
            finding_type=FindingType.DAST,
            fingerprint="abc123",
        )

    def test_counts(self):
        """Test result counts."""
        finding1 = self._create_finding("Finding 1")
        finding2 = self._create_finding("Finding 2")
        rule = SuppressionRule(id="test", reason="Test", fingerprint="abc")

        result = SuppressionResult(
            kept=[finding1],
            suppressed=[(finding2, rule)],
        )

        assert result.kept_count == 1
        assert result.suppressed_count == 1

    def test_empty_result(self):
        """Test empty result."""
        result = SuppressionResult()

        assert result.kept_count == 0
        assert result.suppressed_count == 0
