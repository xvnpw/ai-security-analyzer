import logging
from abc import ABC, abstractmethod
from typing import Any, Final, List, Type

from langgraph.graph.state import CompiledStateGraph
from ai_security_analyzer.config import AppConfig
from langchain_core.documents import Document
from ai_security_analyzer.base_agent import AgentType
from ai_security_analyzer.prompts import GITHUB2_CONFIGS

logger = logging.getLogger(__name__)


class BaseGraphExecutor(ABC):
    """Abstract base class for all graph executors."""

    def __init__(self, config: AppConfig) -> None:
        self.config: Final[AppConfig] = config

    @abstractmethod
    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        pass


class FullDirScanGraphExecutor(BaseGraphExecutor):

    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        try:
            state = graph.invoke(
                {
                    "target_dir": target,
                    "project_type": self.config.project_type,
                    "exclude": self.config.exclude,
                    "exclude_mode": self.config.exclude_mode,
                    "include": self.config.include,
                    "include_mode": self.config.include_mode,
                    "filter_keywords": self.config.filter_keywords,
                }
            )
            self._write_output(state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            raise

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")
        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)


class DryRunFullDirScanGraphExecutor(FullDirScanGraphExecutor):

    def _format_docs(self, documents: List[Document]) -> str:
        formatted_docs = []
        for doc in documents:
            formatted_docs.append(doc.metadata.get("source", "Unknown"))
        return "\n".join(formatted_docs)

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        splitted_docs = state.get("splitted_docs", "")
        token_count = state.get("document_tokens", 0)

        splitted_docs_str = self._format_docs(splitted_docs)

        output = f"""=========== dry-run ===========
All documents token count: {token_count}
List of chunked files to analyze:
{splitted_docs_str}
"""
        print(output)


class GithubGraphExecutor(FullDirScanGraphExecutor):

    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        try:
            config = GITHUB2_CONFIGS[self.config.agent_prompt_type]

            state = graph.invoke(
                {
                    "target_repo": target,
                    "step_count": config["steps"],
                    "step_index": 0,
                    "step_prompts": config["step_prompts"],
                }
            )
            self._write_output(state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            raise

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)


class FileGraphExecutor(FullDirScanGraphExecutor):

    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        try:
            state = graph.invoke(
                {
                    "target_file": target,
                    "refinement_count": self.config.refinement_count,
                }
            )
            self._write_output(state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            raise


class GraphExecutorFactory:
    """Factory for creating graph executors."""

    @classmethod
    def create(cls, config: AppConfig) -> BaseGraphExecutor:
        executors: dict[AgentType, Type[BaseGraphExecutor]] = {
            AgentType.DIR: FullDirScanGraphExecutor,
            AgentType.DRY_RUN_DIR: DryRunFullDirScanGraphExecutor,
            AgentType.GITHUB: GithubGraphExecutor,
            AgentType.FILE: FileGraphExecutor,
        }
        agent_type = AgentType(f"dry-run-{config.mode}") if config.dry_run else AgentType(config.mode)
        executor_class = executors.get(agent_type)
        if not executor_class:
            raise ValueError(f"Unknown agent type: {agent_type.value}")
        return executor_class(config)
