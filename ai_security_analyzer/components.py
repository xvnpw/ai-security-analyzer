import logging

from langchain_text_splitters import CharacterTextSplitter
from tiktoken import Encoding

from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class DocumentProcessingMixin:
    def __init__(
        self,
        text_splitter: CharacterTextSplitter,
        tokenizer: Encoding,
        doc_processor: DocumentProcessor,
        doc_filter: DocumentFilter,
    ):
        self.text_splitter = text_splitter
        self.tokenizer = tokenizer
        self.doc_processor = doc_processor
        self.doc_filter = doc_filter


class MarkdownValidationMixin:
    def __init__(self, markdown_validator: MarkdownMermaidValidator, max_editor_turns_count: int):
        self.markdown_validator = markdown_validator
        self.max_editor_turns_count = max_editor_turns_count
