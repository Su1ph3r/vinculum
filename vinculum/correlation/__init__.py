"""Correlation and deduplication engine."""

from vinculum.correlation.engine import CorrelationEngine, CorrelationResult, correlate_findings
from vinculum.correlation.fingerprint import are_similar_findings, generate_fingerprint

__all__ = [
    "CorrelationEngine",
    "CorrelationResult",
    "correlate_findings",
    "generate_fingerprint",
    "are_similar_findings",
]
