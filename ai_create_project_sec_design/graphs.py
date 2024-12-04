import logging
from abc import ABC, abstractmethod
from typing import Any, Final, List

from langgraph.graph.state import CompiledStateGraph
from ai_create_project_sec_design.config import AppConfig
from langchain_core.documents import Document

logger = logging.getLogger(__name__)


class BaseGraphExecutor(ABC):
    """Abstract base class for all graph executors."""

    def __init__(self, config: AppConfig) -> None:
        self.config: Final[AppConfig] = config

    @abstractmethod
    def execute(self, graph: CompiledStateGraph, target_dir: str) -> None:
        pass


class RunGraphExecutor(BaseGraphExecutor):
    """Executor for simple graphs."""

    def execute(self, graph: CompiledStateGraph, target_dir: str) -> None:
        try:
            state = graph.invoke(
                {
                    "target_dir": target_dir,
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
        output_content = state.get("sec_repo_doc", "")
        if self.config.agent_preamble_enabled:
            output_content = f"{self.config.agent_preamble}\n\n{output_content}"

        self.config.output_file.write(output_content)


class DryRunGraphExecutor(BaseGraphExecutor):
    """Executor for simple graphs."""

    def execute(self, graph: CompiledStateGraph, target_dir: str) -> None:
        try:
            state = graph.invoke(
                {
                    "target_dir": target_dir,
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
List of chunked files to analyse:
{splitted_docs_str}
"""
        print(output)


class GraphExecutorFactory:
    """Factory for creating graph executors."""

    @classmethod
    def create(cls, config: AppConfig) -> BaseGraphExecutor:
        executor_class = DryRunGraphExecutor if config.dry_run else RunGraphExecutor
        return executor_class(config)
