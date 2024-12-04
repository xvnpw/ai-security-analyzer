import argparse
import os
from pathlib import Path
from typing import List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI


def get_changed_folders() -> List[str]:
    """Get list of changed folders from GITHUB_OUTPUT environment variable.

    Returns:
        List[str]: List of folder names that were changed
    """
    changed_files = os.getenv("CHANGED_FILES", "")
    if not changed_files:
        return []

    # Convert file paths to folder names
    changed_folders = {
        Path(file_path).parts[2]  # parts[2] is the folder name after fabric_patterns
        for file_path in changed_files.splitlines()
        if len(Path(file_path).parts) >= 3
    }

    return list(changed_folders)


def scan_folders(root_path: str | Path, process_all: bool = False) -> List[Tuple[str, str]]:
    """
    Scan folders for patterns.

    Args:
        root_path: Path to the root directory
        process_all: If True, process all folders regardless of CHANGED_FILES

    Returns:
        List[Tuple[str, str]]: List of tuples containing (pattern_name, pattern_content)
    """
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Path {root_path} does not exist")

    patterns = []
    changed_folders = None if process_all else get_changed_folders()

    # Early return if no changes detected and not processing all
    if changed_folders is not None and not changed_folders:
        print("No changed folders found")
        return patterns

    # Iterate through all subdirectories
    for folder in root.iterdir():  # for debug islice
        if not folder.is_dir():
            continue

        # Skip if not in changed folders (unless processing all)
        if changed_folders is not None and folder.name not in changed_folders:
            continue

        system_file = folder / "system.md"
        if not system_file.exists():
            print(f"\nWarning: No system.md file found in folder: {folder.name}")
            continue

        try:
            content = system_file.read_text(encoding="utf-8")
            patterns.append((folder.name, content))
        except Exception as e:
            print(f"\nError reading file in folder {folder.name}: {str(e)}")

    return patterns


def create_tool_code(pattern_name: str, pattern_content: str, output_file) -> None:
    """
    Create tool code using LLM and write to output file.

    Args:
        pattern_name: Name of the pattern
        pattern_content: Content of the pattern
        output_file: File object to write the output to
    """
    SYSTEM_PROMPT = """You are a helpful assistant tasked with creating python functions that will be used as fabric tools for LLM. I will give you PROMPT NAME and PROMPT CONTENT. You will create me well formatted python function.

    FORMATTING

    def function_name(self, input: str) -> str:
        \"""Tool description

        Args:
            input: input text
        \"""
    return self.invoke_llm(input, "prompt_name")

    - replace function_name with value of PROMPT_NAME
    - prompt_name replace with value of PROMPT_NAME
    - description of tool must contains information that tool is "fabric pattern"
    """

    llm = ChatOpenAI(model="gpt-4o")
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(
            content=f"PROMPT NAME: {pattern_name}\n\nPROMPT CONTENT: {pattern_content}\n\nTOOL DESCRIPTION:\n"
        ),
    ]

    response = llm.invoke(messages)
    if response.content:
        # Remove code block markers if present
        content = response.content.replace("```python", "").replace("```", "")
        output_file.write(f"{content}\n")


def convert_to_method(patterns: List[Tuple[str, str]]) -> str:
    """
    Convert patterns to a method definition.

    Args:
        patterns: List of (pattern_name, pattern_content) tuples

    Returns:
        str: Method definition as string
    """
    method_lines = [
        "def get_fabric_tools(self) -> list:",
        "    return [",
        *[f"        self.{pattern_name}" for pattern_name, _ in patterns],
        "    ]",
    ]
    return "\n".join(method_lines)


def convert_to_test(patterns: List[Tuple[str, str]]) -> str:
    """
    Convert patterns to a test definition.

    Args:
        patterns: List of (pattern_name, pattern_content) tuples

    Returns:
        str: Test definition as string
    """
    test_lines = [
        "@pytest.mark.parametrize(",
        '    "pattern_name",',
        "    [",
        *[f'        "{pattern_name}"' for pattern_name, _ in patterns],
        "    ],",
        ")",
    ]
    return "\n".join(test_lines)


def main():
    parser = argparse.ArgumentParser(description="Process fabric patterns.")
    parser.add_argument(
        "--process-all",
        action="store_true",
        help="Process all patterns regardless of CHANGED_FILES",
    )
    args = parser.parse_args()

    folder_path = "prompts/fabric_patterns"
    try:
        patterns = scan_folders(folder_path, process_all=args.process_all)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1

    if not patterns:
        print("No patterns found or no changes detected.")
        return 0

    pattern_type = "all" if args.process_all else "changed"
    print(f"\nProcessing {len(patterns)} {pattern_type} patterns:")

    with open("fabric_tools.txt", "w", encoding="utf-8") as f:
        for pattern_name, pattern_content in patterns:
            print(f"- {pattern_name}...")
            create_tool_code(pattern_name, pattern_content, f)

        f.write(convert_to_method(patterns) + "\n")
        f.write(convert_to_test(patterns))

    return 0


if __name__ == "__main__":
    exit(main())
