import logging
from typing import List, Optional, Set

from langchain_core.documents import Document
from tiktoken import Encoding


logger = logging.getLogger(__name__)


class DocumentProcessor:
    """Handles document processing operations"""

    def __init__(self, tokenizer: Encoding):
        self.tokenizer = tokenizer

    def get_docs_batch(self, documents: List[Document], context_window: int) -> List[Document]:
        """Get a batch of documents that fits within the context window"""
        batch = []
        current_size = 0

        logger.debug(f"Fitting documents into context window of: {context_window}")

        for doc in documents:
            doc_tokens = len(self.tokenizer.encode(doc.page_content))
            if current_size + doc_tokens > context_window:
                break
            batch.append(doc)
            current_size += doc_tokens

        return batch

    def format_docs_for_prompt(self, documents: List[Document]) -> str:
        """Format documents for inclusion in the prompt"""
        formatted_docs = []
        for doc in documents:
            formatted_docs.append(
                f"File: {doc.metadata.get('source', 'Unknown')}\n" f"Content:\n{doc.page_content}\n" f"{'=' * 80}"
            )
        return "\n".join(formatted_docs)


class DocumentFilter:
    """Handles document filtering and sorting operations"""

    @staticmethod
    def sort_and_filter_docs(documents: List[Document], keywords: Optional[Set[str]]) -> List[Document]:
        """Sort and filter documents based on criteria"""
        keywords = keywords or set()

        def is_readme(doc: Document) -> bool:
            return "README.md" in doc.metadata.get("source", "")

        def is_md_file(doc: Document) -> bool:
            return str(doc.metadata.get("source", "")).lower().endswith(".md")

        def contains_keywords(doc: Document) -> bool:
            content = doc.page_content.lower()
            return any(keyword.lower() in content for keyword in keywords)

        filtered_docs = (
            [doc for doc in documents if is_readme(doc) or contains_keywords(doc)] if keywords else documents
        )

        return sorted(filtered_docs, key=lambda doc: (not is_readme(doc), not is_md_file(doc)))
