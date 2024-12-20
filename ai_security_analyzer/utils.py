import os
import platform
from shutil import which
from typing import Union
from langchain_core.messages import BaseMessage


def get_total_tokens(message: BaseMessage) -> int:
    return message.usage_metadata.get("total_tokens", 0)  # type: ignore


def get_response_content(message: BaseMessage) -> str:
    """
    Extract content from a BaseMessage, handling both string and list content types.
    Returns the content if it's a string, or the last element if it's a list.

    Args:
        message: BaseMessage object containing the response content

    Returns:
        str: The message content or the last element if content is a list
    """
    content = message.content
    if isinstance(content, str):
        return content
    elif isinstance(content, list):
        return str(content[-1])
    return str(content)  # Fallback case for other types


def find_node_binary() -> Union[str | None]:
    """
    Locate the Node.js binary in a cross-platform manner.
    Returns the full path to the Node.js binary or None if not found.
    """
    # Use 'which' to check if 'node' is in PATH
    node_path = which("node")
    if node_path:
        return node_path

    # Additional search for non-standard locations based on OS
    system = platform.system()
    if system == "Windows":
        # Default Node.js installation path on Windows
        possible_paths = [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe",
        ]
    elif system == "Darwin":  # macOS
        # Common paths on macOS
        possible_paths = [
            "/usr/local/bin/node",
            "/opt/homebrew/bin/node",  # Homebrew on ARM macs
        ]
    elif system == "Linux":
        # Common paths on Linux
        possible_paths = [
            "/usr/bin/node",
            "/usr/local/bin/node",
        ]
    else:
        possible_paths = []

    # Check all possible paths
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path

    # If all else fails, return None
    return None
