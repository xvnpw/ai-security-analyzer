import ai_security_analyzer.utils as utils
import pytest
import hashlib


class TestFormatFilename:
    """Tests for format_filename function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("normal_filename", "normal_filename"),
            ("test.md", "test_md"),
            ("file with spaces.md", "file_with_spaces_md"),
            ("FILE_WITH_CAPS", "file_with_caps"),
            ("file(with)parentheses.md", "file_with_parentheses_md"),
            ("file[with]brackets.md", "file_with_brackets_md"),
            ("file.with.dots.md", "file_with_dots_md"),
            ("file`with`backticks.md", "file_with_backticks_md"),
            ("file,with,commas.md", "file_with_commas_md"),
            # Test long filename
            ("a" * 120, "a" * 100 + "_" + hashlib.md5(("a" * 120).encode(), usedforsecurity=False).hexdigest()[:8]),
            # Test pathvalidate sanitization
            ("file<with>invalid:chars*.md", "filewithinvalidchars_md"),
            ("  filename with leading and trailing spaces  ", "filename_with_leading_and_trailing_spaces"),
        ],
    )
    def test_format_filename_various_cases(self, filename: str, expected: str):
        """Tests format_filename with various inputs including special characters and long names."""
        formatted_filename = utils.format_filename(filename)
        assert formatted_filename == expected

    def test_format_filename_markdown_safety(self):
        """Tests that format_filename output is safe for markdown links."""
        test_cases = [
            "file(1).md",
            "test [file].md",
            "complex [file] (with) dots.md",
            "file`with`backticks.md",
            "file,with,commas.md",
        ]

        for filename in test_cases:
            formatted = utils.format_filename(filename)
            assert all(c not in formatted for c in "[]().`,"), f"Markdown unsafe characters found in: {formatted}"
            assert " " not in formatted, f"Spaces found in: {formatted}"
            assert formatted.islower(), f"Not lowercase: {formatted}"

    def test_format_filename_long_filename_md5_stability(self):
        """Tests that the MD5 hash part of long filenames is stable."""
        long_filename = "a" * 150
        formatted1 = utils.format_filename(long_filename)
        formatted2 = utils.format_filename(long_filename)
        assert formatted1 == formatted2, "MD5 hash part is not stable across calls"

    def test_format_filename_length_truncation(self):
        """Tests that long filenames are truncated to the correct length."""
        long_filename = "a" * 150
        formatted = utils.format_filename(long_filename)
        assert (
            len(formatted) == 100 + 1 + 8
        ), "Filename length is not as expected after truncation and hash"  # 100 chars + _ + 8 hash chars


class TestCleanMarkdown:
    """Tests for clean_markdown function."""

    @pytest.mark.parametrize(
        "markdown_input, expected_output",
        [
            ("```markdown\nThis is markdown content\n```", "This is markdown content"),
            ("```\nThis is code block\n```", "This is code block"),
            ("No code block", "No code block"),
            ("  \n```markdown\nContent with whitespace\n```\n  ", "Content with whitespace"),
            ("  \n```\nCode with whitespace\n```\n  ", "Code with whitespace"),
            ("```markdown\n```", ""),  # Empty markdown block
            ("```\n```", ""),  # Empty code block
            ("```markdown\nContent\n", "Content"),  # Missing closing backticks for markdown
            ("```\nContent\n", "Content"),  # Missing closing backticks for code
            ("Content\n```", "Content"),  # Missing opening backticks
            ("", ""),  # Empty string
            ("   ", ""),  # String with only whitespace
        ],
    )
    def test_clean_markdown_various_cases(self, markdown_input: str, expected_output: str):
        """Tests clean_markdown with various markdown inputs."""
        assert utils.clean_markdown(markdown_input) == expected_output
