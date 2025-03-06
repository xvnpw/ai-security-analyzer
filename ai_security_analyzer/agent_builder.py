import logging
from typing import Type

import tiktoken
from langchain_text_splitters import CharacterTextSplitter

from ai_security_analyzer.base_agent import AgentType, BaseAgent
from ai_security_analyzer.components import DocumentProcessingMixin, DeepAnalysisMixin, VulnerabilitiesWorkflowMixin
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.dry_run import DryRunFullDirScanAgent
from ai_security_analyzer.file_agents import FileAgent
from ai_security_analyzer.full_dir_scan_agents import FullDirScanAgent
from ai_security_analyzer.github2_agents import GithubAgent2
from ai_security_analyzer.github2as_agents import GithubAgent2As
from ai_security_analyzer.github2at_agents import GithubAgent2At
from ai_security_analyzer.github2sd_agents import GithubAgent2Sd
from ai_security_analyzer.github2tm_agents import GithubAgent2Tm
from ai_security_analyzer.github2ms_agents import GithubAgent2Ms
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.prompts.prompt_manager import PromptManager
from ai_security_analyzer.vulnerabilities_workflow1 import VulnerabilitiesWorkflow1
from ai_security_analyzer.vulnerabilities_workflow2 import VulnerabilitiesWorkflow2

logger = logging.getLogger(__name__)


class AgentBuilder:
    def __init__(
        self,
        llm_provider: LLMProvider,
        checkpoint_manager: CheckpointManager,
        config: AppConfig,
        prompt_manager: PromptManager,
    ) -> None:
        self.llm_provider = llm_provider
        self.checkpoint_manager = checkpoint_manager
        self.config = config
        self.prompt_manager = prompt_manager

        self._agents: dict[AgentType, Type[BaseAgent]] = {
            AgentType.DIR: FullDirScanAgent,
            AgentType.DRY_RUN_DIR: DryRunFullDirScanAgent,
            AgentType.GITHUB: GithubAgent2,
            AgentType.GITHUB_DEEP_TM: GithubAgent2Tm,
            AgentType.GITHUB_DEEP_AS: GithubAgent2As,
            AgentType.GITHUB_DEEP_AT: GithubAgent2At,
            AgentType.GITHUB_DEEP_SD: GithubAgent2Sd,
            AgentType.GITHUB_DEEP_MS: GithubAgent2Ms,
            AgentType.FILE: FileAgent,
            AgentType.VULNERABILITIES_WORKFLOW_1: VulnerabilitiesWorkflow1,
            AgentType.VULNERABILITIES_WORKFLOW_2: VulnerabilitiesWorkflow2,
        }
        agent_type = AgentType.create(config)

        self._agent_type = agent_type

    def build(self) -> BaseAgent:
        agent_class = self._agents.get(self._agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {self._agent_type.value}")
        agent_model = self.llm_provider.create_agent_llm()
        agent_model_config = agent_model.model_config

        if issubclass(agent_class, VulnerabilitiesWorkflowMixin):
            # Agents that need document processing
            logger.debug(
                f"Configured document splitter for chunk={agent_model_config.documents_chunk_size} and overlap={agent_model_config.documents_chunk_overlap}"
            )

            text_splitter = CharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=agent_model_config.documents_chunk_size,
                chunk_overlap=agent_model_config.documents_chunk_overlap,
            )
            tokenizer = tiktoken.encoding_for_model(agent_model_config.tokenizer_model_name)
            doc_processor = DocumentProcessor(tokenizer)
            doc_filter = DocumentFilter()

            agent_prompts = self.prompt_manager.get_formatted_prompts(self.config)
            if not agent_prompts:
                raise ValueError(f"No agent prompts for type: {self.config.agent_prompt_type}")

            doc_type_prompt = self.prompt_manager.get_doc_type_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not doc_type_prompt:
                raise ValueError(f"No update prompt for type: {self.config.agent_prompt_type}")
            return agent_class(  # type: ignore[call-arg]
                llm=agent_model,
                secondary_llm=self.llm_provider.create_secondary_agent_llm(),
                text_splitter=text_splitter,
                tokenizer=tokenizer,
                doc_processor=doc_processor,
                doc_filter=doc_filter,
                agent_prompts=agent_prompts,
                doc_type_prompt=doc_type_prompt,
                checkpoint_manager=self.checkpoint_manager,
                included_classes_of_vulnerabilities=self.config.included_classes_of_vulnerabilities,
                excluded_classes_of_vulnerabilities=self.config.excluded_classes_of_vulnerabilities,
                vulnerabilities_severity_threshold=self.config.vulnerabilities_severity_threshold,
                vulnerabilities_threat_actor=self.config.vulnerabilities_threat_actor,
            )
        elif issubclass(agent_class, DocumentProcessingMixin):
            # Agents that need document processing
            logger.debug(
                f"Configured document splitter for chunk={agent_model_config.documents_chunk_size} and overlap={agent_model_config.documents_chunk_overlap}"
            )

            text_splitter = CharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=agent_model_config.documents_chunk_size,
                chunk_overlap=agent_model_config.documents_chunk_overlap,
            )
            tokenizer = tiktoken.encoding_for_model(agent_model_config.tokenizer_model_name)
            doc_processor = DocumentProcessor(tokenizer)
            doc_filter = DocumentFilter()

            agent_prompts = self.prompt_manager.get_formatted_prompts(self.config)
            if not agent_prompts:
                raise ValueError(f"No agent prompt for type: {self.config.agent_prompt_type}")

            doc_type_prompt = self.prompt_manager.get_doc_type_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not doc_type_prompt:
                raise ValueError(f"No update prompt for type: {self.config.agent_prompt_type}")
            return agent_class(  # type: ignore[call-arg]
                llm=agent_model,
                text_splitter=text_splitter,
                tokenizer=tokenizer,
                doc_processor=doc_processor,
                doc_filter=doc_filter,
                agent_prompts=agent_prompts,
                doc_type_prompt=doc_type_prompt,
                checkpoint_manager=self.checkpoint_manager,
            )
        elif issubclass(agent_class, DeepAnalysisMixin):
            agent_prompt = self.prompt_manager.get_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not agent_prompt:
                raise ValueError(f"No agent prompt for type: {self.config.agent_prompt_type}")

            deep_analysis_prompt = self.prompt_manager.get_deep_analysis_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not deep_analysis_prompt:
                raise ValueError(f"No deep analysis prompt for type: {self.config.agent_prompt_type}")

            format_prompt = self.prompt_manager.get_format_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not format_prompt:
                raise ValueError(f"No format prompt for type: {self.config.agent_prompt_type}")

            return agent_class(  # type: ignore[call-arg]
                llm=agent_model,
                structured_llm=self.llm_provider.create_agent_llm_for_structured_queries(),
                step_prompts=agent_prompt,
                deep_analysis_prompt_template=deep_analysis_prompt,
                format_prompt_template=format_prompt,
                checkpoint_manager=self.checkpoint_manager,
            )
        else:
            # Agents that only need llm_provider
            agent_prompt = self.prompt_manager.get_prompt(
                self.config.agent_provider, self.config.agent_model, self.config.mode, self.config.agent_prompt_type
            )
            if not agent_prompt:
                raise ValueError(f"No agent prompt for type: {self.config.agent_prompt_type}")

            return agent_class(llm=agent_model, step_prompts=agent_prompt, checkpoint_manager=self.checkpoint_manager)  # type: ignore[call-arg]
