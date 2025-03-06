import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Final, List, Type

from ai_security_analyzer.base_agent import AgentType
from ai_security_analyzer.config import AppConfig
from langchain_core.documents import Document
from langchain_core.runnables.config import RunnableConfig
from langgraph.graph.state import CompiledStateGraph

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


class VulnerabilitiesWorkflow1GraphExecutor(BaseGraphExecutor):
    output_state_key = "sec_repo_docs"

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
                    "vulnerabilities_iterations": self.config.vulnerabilities_iterations,
                    "use_secondary_agent_for_vulnerabilities": False,
                    "use_secondary_agent": False,
                },
                runnable_config,
            )
            self._write_output(state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            raise

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("total_document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc_final", "")
        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        items = state.get(self.output_state_key, [])
        if len(items) > 1:
            output_dir = os.path.dirname(os.path.abspath(self.config.output_file.name))
            subdir_path = os.path.join(output_dir, self.config.vulnerabilities_output_dir)

            os.makedirs(subdir_path, exist_ok=True)

            for idx, item in enumerate(items, 1):
                filename = os.path.splitext(os.path.basename(self.config.output_file.name))[0]
                item_path = os.path.join(subdir_path, f"{filename}-{idx}.md")
                with open(item_path, "w") as f:
                    f.write(item)


class VulnerabilitiesWorkflow2GraphExecutor(VulnerabilitiesWorkflow1GraphExecutor):
    output_state_key = "sec_repo_docs"

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
                    "vulnerabilities_iterations": self.config.vulnerabilities_iterations,
                    "use_secondary_agent_for_vulnerabilities": False,
                    "use_secondary_agent": False,
                    "vulnerabilities_github_repo_url": self.config.vulnerabilities_github_repo_url,
                },
                runnable_config,
            )
            self._write_output(state)
        except Exception as e:
            logger.error(f"Graph execution failed: {e}")
            raise


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


class GithubDeepGraphExecutor(GithubGraphExecutor):
    output_subdir_name: str = ""
    output_state_key: str = ""
    output_filename_attr: str = "filename"
    output_content_attr: str = "detail_analysis"

    def _write_output(self, state: dict[str, Any] | Any) -> None:
        actual_token_count = state.get("document_tokens", 0)
        logger.info(f"Actual token usage: {actual_token_count}")
        output_content = state.get("sec_repo_doc", "")

        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)

        self._write_additional_output(state)

    def _write_additional_output(self, state: dict[str, Any] | Any) -> None:
        if not self.output_subdir_name or not self.output_state_key:
            return

        output_dir = os.path.dirname(os.path.abspath(self.config.output_file.name))
        subdir_path = os.path.join(output_dir, self.output_subdir_name)

        os.makedirs(subdir_path, exist_ok=True)

        items = state.get(self.output_state_key, [])
        for item in items:
            filename = getattr(item, self.output_filename_attr, "output")
            content = getattr(item, self.output_content_attr, "")

            item_path = os.path.join(subdir_path, f"{filename}.md")
            with open(item_path, "w") as f:
                f.write(content)


class GithubDeepTmGraphExecutor(GithubDeepGraphExecutor):
    output_subdir_name = "threats"
    output_state_key = "output_threats"


class GithubDeepAsGraphExecutor(GithubDeepGraphExecutor):
    output_subdir_name = "attack_surfaces"
    output_state_key = "output_attack_surfaces"


class GithubDeepAtGraphExecutor(GithubDeepGraphExecutor):
    output_subdir_name = "attack_tree_paths"
    output_state_key = "output_attack_tree_paths"


class GithubDeepMsGraphExecutor(GithubDeepGraphExecutor):
    output_subdir_name = "mitigation_strategies"
    output_state_key = "output_mitigation_strategies"


class GithubDeepSdGraphExecutor(GithubDeepGraphExecutor):
    def _write_additional_output(self, state: dict[str, Any] | Any) -> None:
        sec_design_details = state.get("sec_design_details", "")

        if not sec_design_details:
            return

        output_base = os.path.splitext(self.config.output_file.name)[0]
        sec_design_details_path = f"{output_base}-deep-analysis.md"

        with open(sec_design_details_path, "w") as f:
            f.write(sec_design_details)


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
            AgentType.GITHUB: GithubGraphExecutor,
            AgentType.FILE: FileGraphExecutor,
            AgentType.GITHUB_DEEP_TM: GithubDeepTmGraphExecutor,
            AgentType.GITHUB_DEEP_AS: GithubDeepAsGraphExecutor,
            AgentType.GITHUB_DEEP_AT: GithubDeepAtGraphExecutor,
            AgentType.GITHUB_DEEP_SD: GithubDeepSdGraphExecutor,
            AgentType.GITHUB_DEEP_MS: GithubDeepMsGraphExecutor,
            AgentType.VULNERABILITIES_WORKFLOW_1: VulnerabilitiesWorkflow1GraphExecutor,
            AgentType.VULNERABILITIES_WORKFLOW_2: VulnerabilitiesWorkflow2GraphExecutor,
        }
        agent_type = AgentType.create(config)
        executor_class = executors.get(agent_type)
        if not executor_class:
            raise ValueError(f"Unknown agent type: {agent_type.value}")
        return executor_class(config)
