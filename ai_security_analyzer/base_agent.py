import logging
from abc import ABC, abstractmethod
from enum import Enum

import tiktoken
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph.state import CompiledStateGraph

from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class AgentType(Enum):
    DIR = "dir"
    DRY_RUN_DIR = "dry-run-dir"
    GITHUB = "github"
    FILE = "file"


class BaseAgent(ABC):

    def __init__(
        self,
        llm_provider: LLMProvider,
        text_splitter: CharacterTextSplitter,
        tokenizer: tiktoken.Encoding,
        max_editor_turns_count: int,
        markdown_validator: MarkdownMermaidValidator,
        doc_processor: DocumentProcessor,
        doc_filter: DocumentFilter,
        agent_prompt: str,
        doc_type_prompt: str,
    ):
        self.llm_provider = llm_provider
        self.text_splitter = text_splitter
        self.tokenizer = tokenizer
        self.markdown_validator = markdown_validator
        self.max_editor_turns_count = max_editor_turns_count
        self.doc_processor = doc_processor
        self.doc_filter = doc_filter
        self.agent_prompt = agent_prompt
        self.doc_type_prompt = doc_type_prompt

    @abstractmethod
    def build_graph(self) -> CompiledStateGraph:
        """Build and return the agent's graph"""
        pass
