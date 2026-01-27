"""Configuration management for Vinculum."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class AIConfig(BaseModel):
    """AI provider configuration."""

    model_config = ConfigDict(extra="ignore")

    provider: Literal["claude", "openai", "ollama", "lmstudio"] | None = None
    model: str | None = None
    base_url: str | None = None


class OutputConfig(BaseModel):
    """Output configuration."""

    model_config = ConfigDict(extra="ignore")

    format: Literal["json", "console", "sarif"] = "console"
    path: str | None = None
    pretty: bool = True
    include_raw: bool = False


class CorrelationConfig(BaseModel):
    """Correlation engine configuration."""

    model_config = ConfigDict(extra="ignore")

    min_severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    enrich_epss: bool = False


class LoggingConfig(BaseModel):
    """Logging configuration."""

    model_config = ConfigDict(extra="ignore")

    level: Literal["debug", "info", "warning", "error"] = "info"
    file: str | None = None
    format: Literal["simple", "detailed"] = "simple"


class VinculumConfig(BaseModel):
    """Main Vinculum configuration."""

    model_config = ConfigDict(extra="ignore")

    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    suppressions: list[dict] = Field(default_factory=list)


def load_config(config_path: Path | None = None) -> VinculumConfig:
    """
    Load configuration from file.

    Search order:
    1. Explicit path if provided
    2. ./vinculum.yaml in current directory
    3. ~/.vinculum/config.yaml in home directory
    4. Default empty config

    Args:
        config_path: Optional explicit path to config file

    Returns:
        VinculumConfig instance with loaded or default values
    """
    search_paths: list[Path] = []

    if config_path:
        search_paths.append(Path(config_path))
    else:
        # Check current directory
        search_paths.append(Path.cwd() / "vinculum.yaml")
        search_paths.append(Path.cwd() / "vinculum.yml")
        search_paths.append(Path.cwd() / ".vinculum.yaml")
        search_paths.append(Path.cwd() / ".vinculum.yml")
        # Check home directory
        home_config_dir = Path.home() / ".vinculum"
        search_paths.append(home_config_dir / "config.yaml")
        search_paths.append(home_config_dir / "config.yml")

    for path in search_paths:
        if path.exists() and path.is_file():
            return _load_config_from_file(path)

    # Return default config if no file found
    return VinculumConfig()


def _load_config_from_file(path: Path) -> VinculumConfig:
    """Load configuration from a specific file."""
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    return VinculumConfig(**data)


def merge_cli_with_config(
    config: VinculumConfig,
    *,
    output_format: str | None = None,
    output_path: str | None = None,
    min_severity: str | None = None,
    ai_provider: str | None = None,
    ai_model: str | None = None,
    ai_base_url: str | None = None,
    enrich_epss: bool | None = None,
    include_raw: bool | None = None,
    log_level: str | None = None,
) -> VinculumConfig:
    """
    Merge CLI options with config file settings.

    CLI options take precedence over config file values.

    Args:
        config: Base configuration from file
        **kwargs: CLI options (None means use config value)

    Returns:
        Merged configuration
    """
    # Create a mutable copy of config data
    data = config.model_dump()

    # Override with CLI values if provided
    if output_format is not None:
        data["output"]["format"] = output_format
    if output_path is not None:
        data["output"]["path"] = output_path
    if min_severity is not None:
        data["correlation"]["min_severity"] = min_severity
    if ai_provider is not None:
        data["ai"]["provider"] = ai_provider
    if ai_model is not None:
        data["ai"]["model"] = ai_model
    if ai_base_url is not None:
        data["ai"]["base_url"] = ai_base_url
    if enrich_epss is not None:
        data["correlation"]["enrich_epss"] = enrich_epss
    if include_raw is not None:
        data["output"]["include_raw"] = include_raw
    if log_level is not None:
        data["logging"]["level"] = log_level

    return VinculumConfig(**data)
