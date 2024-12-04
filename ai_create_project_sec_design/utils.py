import os
import platform
from shutil import which
from typing import Union


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
