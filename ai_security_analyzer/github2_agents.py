import logging
from dataclasses import dataclass
from typing import List, Literal

from langchain_core.messages import HumanMessage
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens, clean_markdown
from langgraph.graph import MessagesState
from ai_security_analyzer.checkpointing import CheckpointManager


logger = logging.getLogger(__name__)


@dataclass
class AgentState(MessagesState):
    target_repo: str
    sec_repo_doc: str
    document_tokens: int
    step0: str
    step1: str
    step2: str
    step3: str
    step_index: int


class GithubAgent2(BaseAgent):
    """GithubAgent2 is a class that is used to generate security documentation based on model knowledge about specific GitHub repository.

    It was built to be used with Google's Gemini 2.0 Flask Thinking Experimental Mode.
    Experimental model is not working well with markdown and mermaid syntax, that's why cannot use GithubAgent class.
    """

    def __init__(self, llm: LLM, step_prompts: List[str], checkpoint_manager: CheckpointManager):
        super().__init__(llm, checkpoint_manager)
        self.step_prompts = step_prompts
        self.step_count = len(step_prompts)

    def _internal_step(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info(f"Internal step {state.get('step_index', 0)+1} of {self.step_count}")
        try:
            target_repo = state["target_repo"]

            repo_name = target_repo.split("/")[-1]
            step_index = state.get("step_index", 0)
            step_prompts = self.step_prompts

            step_prompt = step_prompts[step_index].format(target_repo=target_repo, repo_name=repo_name)

            step_msg = HumanMessage(content=step_prompt)

            response = self.llm.invoke(state["messages"] + [step_msg])
            document_tokens = get_total_tokens(response)
            return {
                "messages": state["messages"] + [step_msg, response],
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "step_index": step_index + 1,
                f"step{step_index}": get_response_content(response),
            }
        except Exception as e:
            logger.error(f"Error on internal step {state['step_index']} of {self.step_count}: {e}")
            raise ValueError(str(e))

    def _internal_step_condition(self, state: AgentState) -> Literal["internal_step", "final_response"]:
        current_step_index = state["step_index"]
        step_count = self.step_count

        if current_step_index < step_count:
            return "internal_step"
        else:
            return "final_response"

    def _final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting final response")
        try:
            messages = state["messages"]
            last_message = messages[-1]
            final_response = get_response_content(last_message)
            final_response = clean_markdown(final_response)

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting final response: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2.__name__}] building graph...")

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "__end__")
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph
