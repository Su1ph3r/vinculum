"""Vinculum - Bind and correlate security findings across tools."""

__version__ = "0.4.0"
__title__ = "Vinculum"

# Public API exports
from vinculum.correlation import (
    CorrelationEngine,
    CorrelationResult,
    correlate_findings,
    generate_fingerprint,
)
from vinculum.enrichment.cross_tool import CrossToolEnricher
from vinculum.models import (
    Confidence,
    CorrelationGroup,
    FindingLocation,
    FindingType,
    Severity,
    UnifiedFinding,
)
from vinculum.output.burrito_output import BurritoOutputFormatter
from vinculum.parsers import BaseParser, ParseError, ParserRegistry
from vinculum.parsers.ariadne import AriadneParser

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
    "AriadneParser",
    # Correlation
    "CorrelationEngine",
    "CorrelationResult",
    "correlate_findings",
    "generate_fingerprint",
    # Enrichment
    "CrossToolEnricher",
    # Output
    "BurritoOutputFormatter",
]
