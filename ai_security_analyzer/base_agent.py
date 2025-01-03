import logging
from abc import ABC, abstractmethod
from enum import Enum

import tiktoken
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph.state import CompiledStateGraph

from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.config import AppConfig

logger = logging.getLogger(__name__)


class AgentType(Enum):
    DIR = "dir"
    DRY_RUN_DIR = "dry-run-dir"
    GITHUB = "github"
    GITHUB_DEEP_TM = "github-deep-tm"
    FILE = "file"
    GITHUB_DEEP_AS = "github-deep-as"
    GITHUB_DEEP_AT = "github-deep-at"
    GITHUB_DEEP_SD = "github-deep-sd"

    @staticmethod
    def create(config: AppConfig) -> "AgentType":
        if config.deep_analysis and config.agent_prompt_type == "threat-modeling":
            return AgentType.GITHUB_DEEP_TM
        elif config.deep_analysis and config.agent_prompt_type == "attack-surface":
            return AgentType.GITHUB_DEEP_AS
        elif config.deep_analysis and config.agent_prompt_type == "attack-tree":
            return AgentType.GITHUB_DEEP_AT
        elif config.deep_analysis and config.agent_prompt_type == "sec-design":
            return AgentType.GITHUB_DEEP_SD
        else:
            return AgentType(f"dry-run-{config.mode}") if config.dry_run else AgentType(config.mode)


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
