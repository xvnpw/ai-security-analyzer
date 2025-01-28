import logging

from langchain_text_splitters import CharacterTextSplitter
from tiktoken import Encoding

from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor

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


class DeepAnalysisMixin:
    def __init__(self, deep_analysis_prompt_template: str, format_prompt_template: str):
        self.deep_analysis_prompt_template = deep_analysis_prompt_template
        self.format_prompt_template = format_prompt_template
