import logging
from abc import ABC, abstractmethod
from typing import Any, Final, List, Type
import os

from langgraph.graph.state import CompiledStateGraph
from ai_security_analyzer.config import AppConfig
from langchain_core.documents import Document
from ai_security_analyzer.base_agent import AgentType
from langchain_core.runnables.config import RunnableConfig

logger = logging.getLogger(__name__)


class BaseGraphExecutor(ABC):
    """Abstract base class for all graph executors."""

    def __init__(self, config: AppConfig) -> None:
        self.config: Final[AppConfig] = config

    def get_execution_id(self, target: str) -> str:
        """Generate a unique execution ID based on input parameters"""
        return f"{self.config.mode}_{target}_{self.config.agent_prompt_type}"

    def get_runnable_config(self, target: str) -> RunnableConfig:
        return RunnableConfig(
            configurable={"thread_id": self.get_execution_id(target)},
            recursion_limit=self.config.recursion_limit,
        )

    @abstractmethod
    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        pass


class FullDirScanGraphExecutor(BaseGraphExecutor):

    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        try:
            runnable_config = self.get_runnable_config(target)

            state = graph.invoke(
                {
                    "target_dir": target,
                    "project_type": self.config.project_type,
                    "exclude": self.config.exclude,
                    "exclude_mode": self.config.exclude_mode,
                    "include": self.config.include,
                    "include_mode": self.config.include_mode,
                    "filter_keywords": self.config.filter_keywords,
                },
                runnable_config,
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
            runnable_config = self.get_runnable_config(target)

            state = graph.invoke(
                {
                    "target_repo": target,
                },
                runnable_config,
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


class GithubDeepTmGraphExecutor(GithubGraphExecutor):

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        output_dir = os.path.dirname(os.path.abspath(self.config.output_file.name))
        threats_dir = os.path.join(output_dir, "threats")

        os.makedirs(threats_dir, exist_ok=True)

        threats = state.get("output_threats", [])
        for threat in threats:
            threat_path = os.path.join(threats_dir, f"{threat.filename}.md")
            with open(threat_path, "w") as f:
                f.write(threat.detail_analysis)


class GithubDeepAsGraphExecutor(GithubGraphExecutor):

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        output_dir = os.path.dirname(os.path.abspath(self.config.output_file.name))
        attack_surfaces_dir = os.path.join(output_dir, "attack_surfaces")

        os.makedirs(attack_surfaces_dir, exist_ok=True)

        attack_surfaces = state.get("output_attack_surfaces", [])
        for attack_surface in attack_surfaces:
            attack_surface_path = os.path.join(attack_surfaces_dir, f"{attack_surface.filename}.md")
            with open(attack_surface_path, "w") as f:
                f.write(attack_surface.detail_analysis)


class GithubDeepAtGraphExecutor(GithubGraphExecutor):

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        output_dir = os.path.dirname(os.path.abspath(self.config.output_file.name))
        attack_tree_paths_dir = os.path.join(output_dir, "attack_tree_paths")

        os.makedirs(attack_tree_paths_dir, exist_ok=True)

        attack_tree_paths = state.get("output_attack_tree_paths", [])
        for attack_tree_path in attack_tree_paths:
            attack_tree_path_path = os.path.join(attack_tree_paths_dir, f"{attack_tree_path.filename}.md")
            with open(attack_tree_path_path, "w") as f:
                f.write(attack_tree_path.detail_analysis)


class GithubDeepSdGraphExecutor(GithubGraphExecutor):

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        sec_design_details_path = self._create_sec_design_details_path()

        sec_design_details = state.get("sec_design_details", "")
        with open(sec_design_details_path, "w") as f:
            f.write(sec_design_details)

    def _create_sec_design_details_path(self) -> str:
        output_base = os.path.splitext(self.config.output_file.name)[0]
        return f"{output_base}-deep-analysis.md"


class FileGraphExecutor(FullDirScanGraphExecutor):

    def execute(self, graph: CompiledStateGraph, target: str) -> None:
        try:
            runnable_config = self.get_runnable_config(target)

            state = graph.invoke(
                {
                    "target_file": target,
                    "refinement_count": self.config.refinement_count,
                },
                runnable_config,
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
            AgentType.DIR2: FullDirScanGraphExecutor,
            AgentType.DRY_RUN_DIR2: DryRunFullDirScanGraphExecutor,
            AgentType.GITHUB: GithubGraphExecutor,
            AgentType.FILE: FileGraphExecutor,
            AgentType.GITHUB_DEEP_TM: GithubDeepTmGraphExecutor,
            AgentType.GITHUB_DEEP_AS: GithubDeepAsGraphExecutor,
            AgentType.GITHUB_DEEP_AT: GithubDeepAtGraphExecutor,
            AgentType.GITHUB_DEEP_SD: GithubDeepSdGraphExecutor,
        }
        agent_type = AgentType.create(config)
        executor_class = executors.get(agent_type)
        if not executor_class:
            raise ValueError(f"Unknown agent type: {agent_type.value}")
        return executor_class(config)
