"""Abstract base class for security tool parsers."""

from abc import ABC, abstractmethod
from pathlib import Path

from vinculum.models.finding import UnifiedFinding


class BaseParser(ABC):
    """Abstract base class that all tool parsers must implement."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the tool this parser handles."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """Return list of file extensions this parser can handle."""
        ...

    @abstractmethod
    def parse(self, file_path: Path) -> list[UnifiedFinding]:
        """
        Parse a file and return a list of unified findings.

        Args:
            file_path: Path to the file to parse

        Returns:
            List of UnifiedFinding objects

        Raises:
            ParseError: If the file cannot be parsed
        """
        ...

    def supports_file(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.

        Default implementation checks file extension.
        Override for more sophisticated detection.
        """
        return file_path.suffix.lower() in self.supported_extensions

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} tool={self.tool_name}>"


class ParseError(Exception):
    """Raised when a parser encounters an error."""

    def __init__(self, message: str, file_path: Path | None = None):
        self.file_path = file_path
        super().__init__(f"{file_path}: {message}" if file_path else message)


class ParserRegistry:
    """Registry of available parsers."""

    _parsers: list[BaseParser] = []

    @classmethod
    def register(cls, parser: BaseParser) -> None:
        """Register a parser idempotently (skip if already registered)."""
        if not any(p.tool_name == parser.tool_name for p in cls._parsers):
            cls._parsers.append(parser)

    @classmethod
    def get_parser_for_file(cls, file_path: Path) -> BaseParser | None:
        """Find a parser that can handle the given file."""
        for parser in cls._parsers:
            if parser.supports_file(file_path):
                return parser
        return None

    @classmethod
    def get_all_parsers(cls) -> list[BaseParser]:
        """Return all registered parsers."""
        return cls._parsers.copy()

    @classmethod
    def clear(cls) -> None:
        """Clear all registered parsers (useful for testing)."""
        cls._parsers = []
