"""Enumerations for security finding classifications."""

from enum import Enum


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity, with fuzzy matching."""
        normalized = value.lower().strip()
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "4": cls.CRITICAL,
            "high": cls.HIGH,
            "3": cls.HIGH,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "2": cls.MEDIUM,
            "low": cls.LOW,
            "1": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "information": cls.INFO,
            "none": cls.INFO,
            "0": cls.INFO,
        }
        return mapping.get(normalized, cls.INFO)

    @property
    def numeric(self) -> int:
        """Return numeric severity for sorting (higher = more severe)."""
        return {
            self.CRITICAL: 4,
            self.HIGH: 3,
            self.MEDIUM: 2,
            self.LOW: 1,
            self.INFO: 0,
        }[self]


class Confidence(str, Enum):
    """Confidence levels for findings."""

    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"

    @classmethod
    def from_string(cls, value: str) -> "Confidence":
        """Convert string to Confidence."""
        normalized = value.lower().strip()
        mapping = {
            "certain": cls.CERTAIN,
            "confirmed": cls.CERTAIN,
            "high": cls.CERTAIN,
            "firm": cls.FIRM,
            "medium": cls.FIRM,
            "tentative": cls.TENTATIVE,
            "low": cls.TENTATIVE,
        }
        return mapping.get(normalized, cls.TENTATIVE)


class FindingType(str, Enum):
    """Type of security finding based on detection method."""

    SAST = "sast"  # Static Application Security Testing (code analysis)
    DAST = "dast"  # Dynamic Application Security Testing (web scanning)
    NETWORK = "network"  # Network vulnerability scanning
    CONTAINER = "container"  # Container security scanning
    SECRET = "secret"  # Secret/credential detection
    DEPENDENCY = "dependency"  # Dependency/SCA scanning
    CLOUD = "cloud"  # Cloud misconfiguration
    OTHER = "other"
