"""Tests for configuration management."""

from pathlib import Path

import pytest

from vinculum.config import (
    AIConfig,
    CorrelationConfig,
    LoggingConfig,
    OutputConfig,
    VinculumConfig,
    load_config,
    merge_cli_with_config,
)


class TestVinculumConfig:
    """Tests for VinculumConfig model."""

    def test_default_config(self):
        """Test default configuration values."""
        config = VinculumConfig()

        assert config.ai.provider is None
        assert config.output.format == "console"
        assert config.correlation.min_severity == "info"
        assert config.logging.level == "info"
        assert config.suppressions == []

    def test_config_with_values(self):
        """Test configuration with explicit values."""
        config = VinculumConfig(
            ai=AIConfig(provider="claude", model="claude-3-haiku-20240307"),
            output=OutputConfig(format="json", pretty=True),
            correlation=CorrelationConfig(min_severity="high", enrich_epss=True),
            logging=LoggingConfig(level="debug"),
        )

        assert config.ai.provider == "claude"
        assert config.ai.model == "claude-3-haiku-20240307"
        assert config.output.format == "json"
        assert config.correlation.min_severity == "high"
        assert config.correlation.enrich_epss is True
        assert config.logging.level == "debug"

    def test_config_ignores_extra_fields(self):
        """Test that extra fields are ignored."""
        config = VinculumConfig(
            ai=AIConfig(provider="claude", unknown_field="ignored"),
        )
        assert config.ai.provider == "claude"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_default_when_no_file(self, tmp_path, monkeypatch):
        """Test loading default config when no file exists."""
        monkeypatch.chdir(tmp_path)
        config = load_config()

        assert config.output.format == "console"
        assert config.correlation.min_severity == "info"

    def test_load_from_explicit_path(self, tmp_path):
        """Test loading config from explicit path."""
        config_file = tmp_path / "custom.yaml"
        config_file.write_text(
            """
ai:
  provider: openai
  model: gpt-4
output:
  format: json
correlation:
  min_severity: high
"""
        )

        config = load_config(config_file)

        assert config.ai.provider == "openai"
        assert config.ai.model == "gpt-4"
        assert config.output.format == "json"
        assert config.correlation.min_severity == "high"

    def test_load_from_current_directory(self, tmp_path, monkeypatch):
        """Test loading config from current directory."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "vinculum.yaml"
        config_file.write_text(
            """
output:
  format: sarif
"""
        )

        config = load_config()

        assert config.output.format == "sarif"

    def test_load_from_dotfile(self, tmp_path, monkeypatch):
        """Test loading config from .vinculum.yaml."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".vinculum.yaml"
        config_file.write_text(
            """
logging:
  level: debug
"""
        )

        config = load_config()

        assert config.logging.level == "debug"

    def test_load_with_suppressions(self, tmp_path):
        """Test loading config with suppressions list."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
suppressions:
  - id: supp-001
    reason: False positive
    fingerprint: abc123
  - id: supp-002
    reason: Accepted risk
    cve_ids:
      - CVE-2021-44228
"""
        )

        config = load_config(config_file)

        assert len(config.suppressions) == 2
        assert config.suppressions[0]["id"] == "supp-001"
        assert config.suppressions[1]["cve_ids"] == ["CVE-2021-44228"]

    def test_load_empty_file(self, tmp_path):
        """Test loading empty config file."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        config = load_config(config_file)

        # Should return default config
        assert config.output.format == "console"

    def test_load_partial_config(self, tmp_path):
        """Test loading config with only some sections."""
        config_file = tmp_path / "partial.yaml"
        config_file.write_text(
            """
ai:
  provider: ollama
  base_url: http://localhost:11434
"""
        )

        config = load_config(config_file)

        assert config.ai.provider == "ollama"
        assert config.ai.base_url == "http://localhost:11434"
        # Other sections should have defaults
        assert config.output.format == "console"
        assert config.correlation.min_severity == "info"


class TestMergeCliWithConfig:
    """Tests for merge_cli_with_config function."""

    def test_cli_overrides_config(self):
        """Test that CLI options override config values."""
        config = VinculumConfig(
            output=OutputConfig(format="console"),
            correlation=CorrelationConfig(min_severity="info"),
        )

        merged = merge_cli_with_config(
            config,
            output_format="json",
            min_severity="high",
        )

        assert merged.output.format == "json"
        assert merged.correlation.min_severity == "high"

    def test_none_preserves_config(self):
        """Test that None values preserve config values."""
        config = VinculumConfig(
            ai=AIConfig(provider="claude", model="claude-3-haiku"),
            output=OutputConfig(format="json"),
        )

        merged = merge_cli_with_config(
            config,
            output_format=None,  # Should preserve "json"
            ai_provider=None,  # Should preserve "claude"
        )

        assert merged.output.format == "json"
        assert merged.ai.provider == "claude"
        assert merged.ai.model == "claude-3-haiku"

    def test_merge_all_options(self):
        """Test merging all CLI options."""
        config = VinculumConfig()

        merged = merge_cli_with_config(
            config,
            output_format="sarif",
            output_path="/tmp/results.sarif",
            min_severity="critical",
            ai_provider="openai",
            ai_model="gpt-4",
            ai_base_url="https://api.openai.com",
            enrich_epss=True,
            include_raw=True,
            log_level="debug",
        )

        assert merged.output.format == "sarif"
        assert merged.output.path == "/tmp/results.sarif"
        assert merged.correlation.min_severity == "critical"
        assert merged.ai.provider == "openai"
        assert merged.ai.model == "gpt-4"
        assert merged.ai.base_url == "https://api.openai.com"
        assert merged.correlation.enrich_epss is True
        assert merged.output.include_raw is True
        assert merged.logging.level == "debug"

    def test_merge_preserves_suppressions(self):
        """Test that merge preserves suppressions list."""
        config = VinculumConfig(
            suppressions=[{"id": "test", "reason": "Testing"}]
        )

        merged = merge_cli_with_config(
            config,
            output_format="json",
        )

        assert len(merged.suppressions) == 1
        assert merged.suppressions[0]["id"] == "test"


class TestAIConfig:
    """Tests for AIConfig model."""

    def test_all_providers(self):
        """Test all valid AI providers."""
        for provider in ["claude", "openai", "ollama", "lmstudio"]:
            config = AIConfig(provider=provider)
            assert config.provider == provider

    def test_with_base_url(self):
        """Test AI config with base URL."""
        config = AIConfig(
            provider="ollama",
            model="llama2",
            base_url="http://localhost:11434",
        )

        assert config.provider == "ollama"
        assert config.model == "llama2"
        assert config.base_url == "http://localhost:11434"


class TestOutputConfig:
    """Tests for OutputConfig model."""

    def test_all_formats(self):
        """Test all valid output formats."""
        for fmt in ["json", "console", "sarif"]:
            config = OutputConfig(format=fmt)
            assert config.format == fmt

    def test_default_values(self):
        """Test default output config values."""
        config = OutputConfig()

        assert config.format == "console"
        assert config.path is None
        assert config.pretty is True
        assert config.include_raw is False


class TestLoggingConfig:
    """Tests for LoggingConfig model."""

    def test_all_levels(self):
        """Test all valid log levels."""
        for level in ["debug", "info", "warning", "error"]:
            config = LoggingConfig(level=level)
            assert config.level == level

    def test_all_formats(self):
        """Test all valid log formats."""
        for fmt in ["simple", "detailed"]:
            config = LoggingConfig(format=fmt)
            assert config.format == fmt
