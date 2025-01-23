import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Literal, Annotated

from langchain_core.messages import HumanMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.utils import get_response_content, get_total_tokens, format_filename, clean_markdown
from langchain_core.output_parsers import PydanticOutputParser
from operator import add
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.prompts import (
    GITHUB2_FORMAT_MITIGATION_STRATEGIES_PROMPT,
    GITHUB2_GET_MITIGATION_STRATEGY_DETAILS_PROMPT,
)

logger = logging.getLogger(__name__)


class MitigationStrategy(BaseModel):
    title: str = Field(description="Title of the mitigation strategy.")
    text: str = Field(description="Correctly formatted markdown text content of the mitigation strategy.")


class MitigationStrategies(BaseModel):
    mitigation_strategies: List[MitigationStrategy] = Field(
        description="List of mitigation strategies.",
    )


class OutputMitigationStrategy(BaseModel):
    title: str = Field(description="Title of the mitigation strategy.")
    filename: str = Field(description="Filename of the mitigation strategy.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the mitigation strategy.")


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
    output_mitigation_strategies: Annotated[list[OutputMitigationStrategy], add]
    mitigation_strategies_index: int
    mitigation_strategies_count: int
    mitigation_strategies: List[MitigationStrategy]


class GithubAgent2Ms(BaseAgent):
    """GithubAgent2Ms is a class that is used to generate deep analysis of mitigation strategies based on model knowledge about specific GitHub repository.

    It was built to be used with Google's Gemini 2.0 Flask Thinking Experimental Mode.
    Experimental model is working well with markdown and mermaid syntax, that's why cannot use GithubAgent class.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        step_prompts: List[Callable[[str], str]],
        checkpoint_manager: CheckpointManager,
    ):
        super().__init__(llm_provider, checkpoint_manager)
        self.step_prompts = step_prompts
        self.step_count = len(step_prompts)

    def _internal_step(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(f"Internal step {state.get('step_index', 0)+1} of {self.step_count}")
        try:
            target_repo = state["target_repo"]
            step_index = state.get("step_index", 0)
            step_prompts = self.step_prompts

            step_prompt = step_prompts[step_index](target_repo)

            step_msg = HumanMessage(content=step_prompt)

            response = llm.invoke(state["messages"] + [step_msg])
            document_tokens = get_total_tokens(response)
            return {
                "messages": state["messages"] + [step_msg, response],
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "step_index": step_index + 1,
                f"step{step_index}": get_response_content(response),
            }
        except Exception as e:
            logger.error(f"Error on internal step {state['step_index']+1} of {self.step_count}: {e}")
            raise ValueError(str(e))

    def _internal_step_condition(self, state: AgentState) -> Literal["internal_step", "final_response"]:
        current_step_index = state["step_index"]
        step_count = self.step_count

        if current_step_index < step_count:
            return "internal_step"
        else:
            return "final_response"

    def _final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting intermediate response")
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

    def _structured_mitigation_strategies(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Getting structured mitigation strategies")
        try:
            sec_repo_doc = state["sec_repo_doc"]

            parser = PydanticOutputParser(pydantic_object=MitigationStrategies)

            format_prompt = GITHUB2_FORMAT_MITIGATION_STRATEGIES_PROMPT.format(
                sec_repo_doc, parser.get_format_instructions()
            )

            format_msg = HumanMessage(content=format_prompt)

            response = llm.invoke([format_msg])
            document_tokens = get_total_tokens(response)
            content = get_response_content(response)

            parsed_mitigation_strategies = parser.parse(content)
            mitigation_strategies = parsed_mitigation_strategies.mitigation_strategies
            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "mitigation_strategies": mitigation_strategies,
                "mitigation_strategies_index": 0,
                "mitigation_strategies_count": len(mitigation_strategies),
            }
        except Exception as e:
            logger.error(f"Error on structured mitigation strategies: {e}")
            raise ValueError(str(e))

    def _get_mitigation_strategy_details_condition(
        self, state: AgentState
    ) -> Literal["get_mitigation_strategy_details", "mitigation_strategies_final_response"]:
        mitigation_strategies_index = state["mitigation_strategies_index"]
        mitigation_strategies_count = state["mitigation_strategies_count"]

        if mitigation_strategies_index < mitigation_strategies_count:
            return "get_mitigation_strategy_details"
        else:
            return "mitigation_strategies_final_response"

    def _get_mitigation_strategy_details(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(
            f"Getting mitigation strategy details {state.get('mitigation_strategies_index', 0)+1} of {state['mitigation_strategies_count']}"
        )
        try:
            target_repo = state["target_repo"]
            mitigation_strategies = state["mitigation_strategies"]
            mitigation_strategies_index = state.get("mitigation_strategies_index", 0)

            get_mitigation_strategy_details_prompt = GITHUB2_GET_MITIGATION_STRATEGY_DETAILS_PROMPT.format(
                target_repo,
                mitigation_strategies[mitigation_strategies_index].title,
                mitigation_strategies[mitigation_strategies_index].text,
            )

            get_mitigation_strategy_details_msg = HumanMessage(content=get_mitigation_strategy_details_prompt)

            response = llm.invoke([get_mitigation_strategy_details_msg])
            document_tokens = get_total_tokens(response)
            mitigation_strategy_details = get_response_content(response)
            mitigation_strategy_details = clean_markdown(mitigation_strategy_details)

            output_mitigation_strategy = OutputMitigationStrategy(
                title=mitigation_strategies[mitigation_strategies_index].title,
                filename=format_filename(mitigation_strategies[mitigation_strategies_index].title),
                detail_analysis=mitigation_strategy_details,
            )

            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "mitigation_strategies_index": mitigation_strategies_index + 1,
                "output_mitigation_strategies": [output_mitigation_strategy],
            }
        except Exception as e:
            logger.error(
                f"Error on get mitigation strategy details {state['mitigation_strategies_index']+1} of {state['mitigation_strategies_count']}: {e}"
            )
            raise ValueError(str(e))

    def _mitigation_strategies_final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting mitigation strategies final response")
        try:
            mitigation_strategies = state["mitigation_strategies"]
            repo_name = state["target_repo"].split("/")[-1]
            owner_name = state["target_repo"].split("/")[-2]

            final_response = f"# Mitigation Strategies Analysis for {owner_name}/{repo_name}\n\n"
            for mitigation_strategy in mitigation_strategies:
                mitigation_strategy_filename = format_filename(mitigation_strategy.title)
                mitigation_strategy_path = f"./mitigation_strategies/{mitigation_strategy_filename}.md"
                final_response += f"## Mitigation Strategy: [{mitigation_strategy.title}]({mitigation_strategy_path})\n\n{mitigation_strategy.text}\n\n"

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting final response: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2Ms.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        structured_llm = self.llm_provider.create_agent_llm_for_structured_queries()

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state, llm.llm, llm.model_config.use_system_message)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        def structured_mitigation_strategies(state: AgentState):  # type: ignore[no-untyped-def]
            return self._structured_mitigation_strategies(
                state, structured_llm.llm, structured_llm.model_config.use_system_message
            )

        def get_mitigation_strategy_details(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_mitigation_strategy_details(state, llm.llm, llm.model_config.use_system_message)

        def mitigation_strategies_final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._mitigation_strategies_final_response(state)

        def get_mitigation_strategy_details_condition(
            state: AgentState,
        ) -> Literal["get_mitigation_strategy_details", "mitigation_strategies_final_response"]:
            return self._get_mitigation_strategy_details_condition(state)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_node("structured_mitigation_strategies", structured_mitigation_strategies)
        builder.add_node("get_mitigation_strategy_details", get_mitigation_strategy_details)
        builder.add_node("mitigation_strategies_final_response", mitigation_strategies_final_response)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "structured_mitigation_strategies")
        builder.add_conditional_edges("structured_mitigation_strategies", get_mitigation_strategy_details_condition)
        builder.add_conditional_edges("get_mitigation_strategy_details", get_mitigation_strategy_details_condition)
        builder.add_edge("mitigation_strategies_final_response", "__end__")
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph
