import logging
from typing import Type

import tiktoken
from langchain_text_splitters import CharacterTextSplitter

from ai_create_project_sec_design.agents import CreateProjectSecurityDesignAgent
from ai_create_project_sec_design.base_agent import BaseAgent
from ai_create_project_sec_design.config import AppConfig
from ai_create_project_sec_design.documents import DocumentFilter, DocumentProcessor
from ai_create_project_sec_design.dry_run import DryRunAgent
from ai_create_project_sec_design.llms import LLMProvider
from ai_create_project_sec_design.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class AgentBuilder:
    def __init__(self, llm_provider: LLMProvider, config: AppConfig) -> None:
        self.llm_provider = llm_provider
        self.config = config

        self._agents: dict[str, Type[BaseAgent]] = {
            "run": CreateProjectSecurityDesignAgent,
            "dry-run": DryRunAgent,
        }
        self._agent_type = "dry-run" if config.dry_run else "run"

    def build(self) -> BaseAgent:
        agent_class = self._agents.get(self._agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {self._agent_type}")

        agent_model = self.llm_provider.create_agent_llm()
        agent_model_config = agent_model.model_config

        logger.debug(
            f"Configured document splitter for chunk={agent_model_config.documents_chunk_size} and overlap={agent_model_config.documents_chunk_overlap}"
        )

        text_splitter = CharacterTextSplitter.from_tiktoken_encoder(
            chunk_size=agent_model_config.documents_chunk_size, chunk_overlap=agent_model_config.documents_chunk_overlap
        )

        tokenizer = tiktoken.encoding_for_model(agent_model_config.tokenizer_model_name)

        markdown_validator = MarkdownMermaidValidator(self.config.node_path)

        doc_processor = DocumentProcessor(tokenizer)
        doc_filter = DocumentFilter()

        return agent_class(
            self.llm_provider,
            text_splitter,
            tokenizer,
            self.config.editor_max_turns_count,
            markdown_validator,
            doc_processor,
            doc_filter,
        )
