"""Vinculum - Bind and correlate security findings across tools."""

__version__ = "0.2.0"
__title__ = "Vinculum"

# Public API exports
from vinculum.correlation import (
    CorrelationEngine,
    CorrelationResult,
    correlate_findings,
    generate_fingerprint,
)
from vinculum.models import (
    Confidence,
    CorrelationGroup,
    FindingLocation,
    FindingType,
    Severity,
    UnifiedFinding,
)
from vinculum.parsers import BaseParser, ParseError, ParserRegistry

__all__ = [
    # Version info
    "__version__",
    "__title__",
    # Models
    "UnifiedFinding",
    "FindingLocation",
    "CorrelationGroup",
    "Severity",
    "Confidence",
    "FindingType",
    # Parsers
    "BaseParser",
    "ParseError",
    "ParserRegistry",
    # Correlation
    "CorrelationEngine",
    "CorrelationResult",
    "correlate_findings",
    "generate_fingerprint",
]
