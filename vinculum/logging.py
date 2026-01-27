"""Logging infrastructure for Vinculum."""

import logging
import sys
from typing import Literal

LogLevel = Literal["debug", "info", "warning", "error"]

_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

_configured = False


def setup_logging(
    level: LogLevel = "info",
    log_file: str | None = None,
    format_style: Literal["simple", "detailed"] = "simple",
) -> None:
    """
    Configure vinculum logging.

    Args:
        level: Log level (debug, info, warning, error)
        log_file: Optional file path to write logs to
        format_style: 'simple' for minimal output, 'detailed' for full context
    """
    global _configured

    if format_style == "detailed":
        fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    else:
        fmt = "%(levelname)s: %(message)s"

    log_level = _LOG_LEVELS.get(level, logging.INFO)

    # Configure root vinculum logger
    logger = logging.getLogger("vinculum")
    logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler - only show warnings and above by default
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a vinculum module.

    Args:
        name: Module name (e.g., 'parsers.burp', 'correlation.engine')

    Returns:
        Logger instance for vinculum.{name}
    """
    return logging.getLogger(f"vinculum.{name}")


def is_configured() -> bool:
    """Check if logging has been configured."""
    return _configured
