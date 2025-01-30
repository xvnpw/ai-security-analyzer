import io
import logging
from abc import ABC, abstractmethod
from typing import Any, Final, Type

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langgraph.graph.state import CompiledStateGraph

from fabric_agent_action.config import AppConfig

logger = logging.getLogger(__name__)


class BaseGraphExecutor(ABC):
    """Abstract base class for all graph executors."""

    def __init__(self, config: AppConfig) -> None:
        self.config: Final[AppConfig] = config
        self._setup_output_encoding()

    @abstractmethod
    def execute(self, graph: CompiledStateGraph, input_str: str) -> None:
        pass

    @abstractmethod
    def _invoke_graph(self, graph: CompiledStateGraph, input_str: str) -> Any:
        pass

    @abstractmethod
    def _write_output(self, messages_state: Any) -> None:
        pass

    def _execute(self, graph: CompiledStateGraph, input_str: str) -> None:
        try:
            messages_state = self._invoke_graph(graph, input_str)
            self._log_messages(messages_state)
            self._write_output(messages_state)
        except Exception as e:
            logger.error("Graph execution failed: %s", str(e))
            raise

    def _setup_output_encoding(self) -> None:
        if isinstance(self.config.output_file, io.TextIOWrapper):
            try:
                self.config.output_file.reconfigure(encoding="utf-8")
            except Exception as e:
                logger.warning(
                    "Could not set UTF-8 encoding: %s. Falling back to system default.",
                    str(e),
                )

    def _format_output(self, content: str) -> str:
        if not self.config.agent_preamble_enabled:
            return content
        return f"{self.config.agent_preamble}\n\n{content}"

    def _log_messages(self, messages_state: dict[str, list[BaseMessage]]) -> None:
        """Log all messages for debugging."""
        for msg in messages_state["messages"]:
            logger.debug("Message: %s", msg.pretty_repr())


class RouterGraphExecutor(BaseGraphExecutor):
    """Executor for router graphs."""

    def execute(self, graph: CompiledStateGraph, input_str: str) -> None:
        self._execute(graph, input_str)

    def _invoke_graph(self, graph: CompiledStateGraph, input_str: str) -> Any:
        return graph.invoke({"messages": [HumanMessage(content=input_str)]})

    def _write_output(self, messages_state: Any) -> None:
        last_message = messages_state["messages"][-1]

        content = self._format_output(
            last_message.content if isinstance(last_message.content, str) else str(last_message.content)
        )
        self.config.output_file.write(content)


class ReActGraphExecutor(BaseGraphExecutor):
    """Executor for ReAct-style graphs."""

    def execute(self, graph: CompiledStateGraph, input_str: str) -> None:
        self._execute(graph, input_str)

    def _invoke_graph(self, graph: CompiledStateGraph, input_str: str) -> Any:
        return graph.invoke(
            {
                "messages": [HumanMessage(content=input_str)],
                "max_num_turns": self.config.fabric_max_num_turns,
            }
        )

    def _write_output(self, messages_state: Any) -> None:
        last_message = messages_state["messages"][-1]
        if not isinstance(last_message, AIMessage) or not last_message.content:
            raise ValueError("Invalid or empty AI message")

        content = self._format_output(
            last_message.content if isinstance(last_message.content, str) else str(last_message.content)
        )
        self.config.output_file.write(content)


class GraphExecutorFactory:
    """Factory for creating graph executors."""

    _EXECUTOR_MAP: Final[dict[str, Type[BaseGraphExecutor]]] = {
        "router": RouterGraphExecutor,
        "react": ReActGraphExecutor,
        "react_issue": ReActGraphExecutor,
        "react_pr": ReActGraphExecutor,
    }

    @classmethod
    def create(cls, config: AppConfig) -> BaseGraphExecutor:
        executor_class = cls._EXECUTOR_MAP.get(config.agent_type)
        if not executor_class:
            raise ValueError(f"Unknown agent type: {config.agent_type}")
        return executor_class(config)
