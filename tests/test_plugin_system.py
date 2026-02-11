"""Tests for custom parser plugin system (--parser-dir)."""

import textwrap
from pathlib import Path

import pytest

from vinculum.parsers.base import BaseParser, ParserRegistry


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure clean registry for each test."""
    original = ParserRegistry._parsers.copy()
    yield
    ParserRegistry._parsers = original


class TestLoadPlugins:
    def test_loads_parser_from_directory(self, tmp_path):
        plugin_file = tmp_path / "custom_parser.py"
        plugin_file.write_text(textwrap.dedent("""\
            from pathlib import Path
            from vinculum.parsers.base import BaseParser
            from vinculum.models.finding import UnifiedFinding

            class CustomTestParser(BaseParser):
                @property
                def tool_name(self) -> str:
                    return "custom_test"

                @property
                def supported_extensions(self) -> list[str]:
                    return [".custom"]

                def parse(self, file_path: Path) -> list[UnifiedFinding]:
                    return []
        """))

        loaded = ParserRegistry.load_plugins([tmp_path])
        assert loaded == 1
        names = [p.tool_name for p in ParserRegistry.get_all_parsers()]
        assert "custom_test" in names

    def test_skips_files_starting_with_underscore(self, tmp_path):
        plugin_file = tmp_path / "_internal.py"
        plugin_file.write_text(textwrap.dedent("""\
            from pathlib import Path
            from vinculum.parsers.base import BaseParser
            from vinculum.models.finding import UnifiedFinding

            class HiddenParser(BaseParser):
                @property
                def tool_name(self) -> str:
                    return "hidden"

                @property
                def supported_extensions(self) -> list[str]:
                    return [".hidden"]

                def parse(self, file_path: Path) -> list[UnifiedFinding]:
                    return []
        """))

        loaded = ParserRegistry.load_plugins([tmp_path])
        assert loaded == 0

    def test_skips_nonexistent_directories(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist"
        loaded = ParserRegistry.load_plugins([nonexistent])
        assert loaded == 0

    def test_skips_files_with_syntax_errors(self, tmp_path):
        bad_file = tmp_path / "bad_parser.py"
        bad_file.write_text("this is not valid python !!!")

        loaded = ParserRegistry.load_plugins([tmp_path])
        assert loaded == 0

    def test_idempotent_loading(self, tmp_path):
        plugin_file = tmp_path / "idempotent_parser.py"
        plugin_file.write_text(textwrap.dedent("""\
            from pathlib import Path
            from vinculum.parsers.base import BaseParser
            from vinculum.models.finding import UnifiedFinding

            class IdempotentParser(BaseParser):
                @property
                def tool_name(self) -> str:
                    return "idempotent_test"

                @property
                def supported_extensions(self) -> list[str]:
                    return [".idem"]

                def parse(self, file_path: Path) -> list[UnifiedFinding]:
                    return []
        """))

        ParserRegistry.load_plugins([tmp_path])
        count_after_first = len(ParserRegistry.get_all_parsers())
        ParserRegistry.load_plugins([tmp_path])
        count_after_second = len(ParserRegistry.get_all_parsers())
        assert count_after_first == count_after_second

    def test_loads_from_multiple_directories(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()

        (dir_a / "parser_a.py").write_text(textwrap.dedent("""\
            from pathlib import Path
            from vinculum.parsers.base import BaseParser
            from vinculum.models.finding import UnifiedFinding

            class ParserA(BaseParser):
                @property
                def tool_name(self) -> str:
                    return "plugin_a"

                @property
                def supported_extensions(self) -> list[str]:
                    return [".pa"]

                def parse(self, file_path: Path) -> list[UnifiedFinding]:
                    return []
        """))

        (dir_b / "parser_b.py").write_text(textwrap.dedent("""\
            from pathlib import Path
            from vinculum.parsers.base import BaseParser
            from vinculum.models.finding import UnifiedFinding

            class ParserB(BaseParser):
                @property
                def tool_name(self) -> str:
                    return "plugin_b"

                @property
                def supported_extensions(self) -> list[str]:
                    return [".pb"]

                def parse(self, file_path: Path) -> list[UnifiedFinding]:
                    return []
        """))

        loaded = ParserRegistry.load_plugins([dir_a, dir_b])
        assert loaded == 2

    def test_ignores_non_parser_classes(self, tmp_path):
        plugin_file = tmp_path / "not_a_parser.py"
        plugin_file.write_text(textwrap.dedent("""\
            class NotAParser:
                pass

            class AlsoNotAParser:
                tool_name = "nope"
        """))

        loaded = ParserRegistry.load_plugins([tmp_path])
        assert loaded == 0
