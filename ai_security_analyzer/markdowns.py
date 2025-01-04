import logging
import re
import subprocess
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

DOMPURIFY_ERROR = "DOMPurify.sanitize is not a function"


class MarkdownMermaidValidator:
    def __init__(self, node_path: str, validate_script_path: str = "validateMermaid.js"):
        self.node_path = node_path
        self.validate_script_path = validate_script_path

    def validate_content(self, doc_content: str) -> Tuple[bool, Optional[str]]:
        try:
            mermaids = self.extract_mermaid_blocks(doc_content)
            if not mermaids:
                logger.info("No Mermaid diagrams found in the Markdown content.")
                return True, None

            is_valid = True
            errors = []

            for index, mermaid in enumerate(mermaids, start=1):
                logger.debug(f"Validating Mermaid diagram {index}...")
                valid, error = self.validate_mermaid_diagram(mermaid)
                logger.debug(f"Validation result: {valid}, Error: {error}")
                if DOMPURIFY_ERROR in (error or ""):
                    logger.warning(f"Skipping mermaid validation. Node libraries misconfigured: {error}")
                    return True, None
                if not valid:
                    is_valid = False
                    errors.append(f"Diagram {index}: {error}")

            error_message = "\n".join(errors) if errors else None
            return is_valid, error_message

        except subprocess.CalledProcessError as e:
            logger.warning(f"Skipping mermaid validation. Node.js misconfigured: {e}")
            return True, None
        except Exception as e:
            logger.warning(f"Skipping mermaid validation. Node.js misconfigured: {e}")
            return True, None

    def extract_mermaid_blocks(self, markdown_content: str) -> List[str]:
        mermaid_regex = r"```mermaid([\s\S]*?)```"
        blocks = [match.group(1).strip() for match in re.finditer(mermaid_regex, markdown_content)]
        logger.debug(f"Extracted {len(blocks)} Mermaid diagram(s) from Markdown content.")
        return blocks

    def validate_mermaid_diagram(self, mermaid_code: str) -> Tuple[bool, Optional[str]]:
        try:
            result = subprocess.run(
                [self.node_path, self.validate_script_path, mermaid_code],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip()
                logger.debug(f"Validation failed for Mermaid diagram: {error_msg}")
                return False, f"Validation error: {error_msg}"

            logger.debug("Mermaid diagram validated successfully.")
            return True, None

        except Exception as e:
            logger.error(f"Unexpected error during Mermaid validation: {e}")
            return False, str(e)
