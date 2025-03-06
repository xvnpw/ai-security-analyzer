from langchain_core.messages import BaseMessage, AIMessage
from pathvalidate import sanitize_filename
import hashlib
from typing import Any


def clean_markdown(markdown: str) -> str:
    markdown = markdown.strip()

    if markdown.startswith("```markdown"):
        markdown = markdown[11:]
    elif markdown.startswith("```"):
        markdown = markdown[3:]

    if markdown.endswith("```"):
        markdown = markdown[:-3]

    markdown = markdown.strip()

    return markdown


def convert_to_ai_message(message: BaseMessage) -> AIMessage:
    content = message.content

    if isinstance(content, list):
        content = str(content[-1])

    return AIMessage(content=content)


def get_total_tokens(message: BaseMessage) -> int:
    if message and hasattr(message, "usage_metadata") and message.usage_metadata:
        return message.usage_metadata.get("total_tokens", 0)  # type: ignore
    return 0


def get_response_content(message: BaseMessage) -> Any:
    content = message.content
    if isinstance(content, str):
        return content
    elif isinstance(content, list):
        last_element = content[-1]
        if isinstance(last_element, str):
            return last_element
        elif isinstance(last_element, dict):
            return last_element["text"]
        else:
            return str(last_element)
    return str(content)  # Fallback case for other types


def format_filename(filename: str) -> str:
    """
    Format a filename to be safe for markdown links and filesystem usage.
    Converts to lowercase, replaces spaces with underscores, and handles special characters.
    For long filenames, truncates and adds an MD5 hash.
    """
    # First sanitize using pathvalidate
    sanitized = sanitize_filename(filename)

    # Replace problematic characters for markdown links
    replacements = {
        " ": "_",
        "[": "_",
        "]": "_",
        "(": "_",
        ")": "_",
        ".": "_",
        "`": "_",
        ",": "_",
    }

    # Apply all replacements and convert to lowercase
    for char, replacement in replacements.items():
        sanitized = sanitized.replace(char, replacement)
    sanitized = sanitized.lower()

    # Handle long filenames
    if len(sanitized) > 100:
        md5_hash = hashlib.md5(filename.encode(), usedforsecurity=False).hexdigest()[:8]
        sanitized = f"{sanitized[:100]}_{md5_hash}"

    return sanitized
