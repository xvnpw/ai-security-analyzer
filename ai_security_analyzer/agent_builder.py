import logging
from typing import Type


import tiktoken
from langchain_text_splitters import CharacterTextSplitter

from ai_security_analyzer.full_dir_scan import FullDirScanAgent
from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.dry_run import DryRunFullDirScanAgent
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.prompts import DOC_TYPE_PROMPTS, get_agent_prompt
from ai_security_analyzer.github2_agents import GithubAgent2
from ai_security_analyzer.github2tm_agents import GithubAgent2Tm
from ai_security_analyzer.file_agents import FileAgent
from ai_security_analyzer.base_agent import AgentType

logger = logging.getLogger(__name__)


class AgentBuilder:
    def __init__(self, llm_provider: LLMProvider, config: AppConfig) -> None:
        self.llm_provider = llm_provider
        self.config = config

        self._agents: dict[AgentType, Type[BaseAgent]] = {
            AgentType.DIR: FullDirScanAgent,
            AgentType.DRY_RUN_DIR: DryRunFullDirScanAgent,
            AgentType.GITHUB: GithubAgent2,
            AgentType.GITHUB_DEEP_TM: GithubAgent2Tm,
            AgentType.FILE: FileAgent,
        }
        agent_type = AgentType.create(config)

        self._agent_type = agent_type
        self.agent_prompt_type = config.agent_prompt_type

    def build(self) -> BaseAgent:
        agent_class = self._agents.get(self._agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {self._agent_type.value}")

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

        agent_prompt = get_agent_prompt(self.agent_prompt_type, self.config.mode)
        if not agent_prompt:
            raise ValueError(f"No agent prompt for type: {self.agent_prompt_type}")

        doc_type_prompt = DOC_TYPE_PROMPTS.get(self.agent_prompt_type)
        if not doc_type_prompt:
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
            doc_type_prompt,
        )
