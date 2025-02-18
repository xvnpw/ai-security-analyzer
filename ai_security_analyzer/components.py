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


class VulnerabilitiesWorkflowMixin:
    def __init__(
        self,
        included_classes_of_vulnerabilities: str,
        excluded_classes_of_vulnerabilities: str,
        vulnerabilities_severity_threshold: str,
        vulnerabilities_threat_actor: str,
    ):
        self.included_classes_of_vulnerabilities = included_classes_of_vulnerabilities
        self.excluded_classes_of_vulnerabilities = excluded_classes_of_vulnerabilities
        self.vulnerabilities_severity_threshold = vulnerabilities_severity_threshold
        self.vulnerabilities_threat_actor = vulnerabilities_threat_actor
