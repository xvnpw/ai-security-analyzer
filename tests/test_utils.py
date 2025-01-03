import ai_security_analyzer.utils as utils
import pytest
import hashlib


# Test format_filename
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
        # Test long filename
        ("a" * 120, "a" * 100 + "_" + hashlib.md5(("a" * 120).encode(), usedforsecurity=False).hexdigest()[:8]),
    ],
)
def test_format_filename_specific_cases(filename: str, expected: str):
    formatted_filename = utils.format_filename(filename)
    assert formatted_filename == expected


def test_format_filename_markdown_safety():
    # Test that the output is safe to use in markdown links
    test_cases = [
        "file(1).md",
        "test [file].md",
        "complex [file] (with) dots.md",
    ]

    for filename in test_cases:
        formatted = utils.format_filename(filename)
        assert all(c not in formatted for c in "[]().")  # No markdown special characters
        assert " " not in formatted  # No spaces
        assert formatted.islower()  # All lowercase
