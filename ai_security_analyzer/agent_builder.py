import logging
from typing import Type

import tiktoken
from langchain_text_splitters import CharacterTextSplitter

from ai_security_analyzer.agents import CreateProjectSecurityDesignAgent
from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.dry_run import DryRunAgent
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.prompts import AGENT_PROMPTS, UPDATE_PROMPTS

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
        self.agent_prompt_type = config.agent_prompt_type

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

        agent_prompt = AGENT_PROMPTS.get(self.agent_prompt_type)
        if not agent_prompt:
            raise ValueError(f"No agent prompt for type: {self.agent_prompt_type}")

        draft_update_prompt = UPDATE_PROMPTS.get(self.agent_prompt_type)
        if not draft_update_prompt:
            raise ValueError(f"No update prompt for type: {self.agent_prompt_type}")

        return agent_class(
            self.llm_provider,
            text_splitter,
            tokenizer,
            self.config.editor_max_turns_count,
            markdown_validator,
            doc_processor,
            doc_filter,
            agent_prompt,
            draft_update_prompt,
        )
