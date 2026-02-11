"""Abstract base class for security tool parsers."""

import importlib.util
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from vinculum.models.finding import UnifiedFinding

logger = logging.getLogger(__name__)


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

    @classmethod
    def load_plugins(cls, directories: list[Path]) -> int:
        """
        Dynamically load parser plugins from directories.

        Scans each directory for .py files, imports them, and registers
        any classes that are subclasses of BaseParser.

        Args:
            directories: List of directories to scan for plugin .py files

        Returns:
            Number of parsers successfully loaded
        """
        loaded = 0
        for directory in directories:
            if not directory.is_dir():
                continue
            for py_file in sorted(directory.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                module_name = f"vinculum_plugin_{py_file.stem}"
                if module_name in sys.modules:
                    continue
                try:
                    spec = importlib.util.spec_from_file_location(module_name, py_file)
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)

                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, BaseParser)
                            and attr is not BaseParser
                        ):
                            instance = attr()
                            count_before = len(cls._parsers)
                            cls.register(instance)
                            if len(cls._parsers) > count_before:
                                loaded += 1
                except Exception as e:
                    sys.modules.pop(module_name, None)
                    logger.warning("Failed to load plugin %s: %s", py_file, e)
                    continue
        return loaded
