"""
This file introduces a new base class, BaseGithubDeepAnalysisAgent, which
encapsulates the common repeated logic found in the "deep analysis" GitHub
agents (e.g., internal steps, final response, structured parse step, iteration).
Each specialized deep agent (attack-surface, threat-modeling, etc.) will
derive from this to avoid code duplication.
"""

import logging
from typing import (
    Any,
    List,
    Literal,
    Optional,
    TypeVar,
    Generic,
    Type,
)


from langchain_core.messages import HumanMessage
from langgraph.graph import MessagesState
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.components import DeepAnalysisMixin
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import (
    get_response_content,
    get_total_tokens,
    clean_markdown,
)

from langchain_core.output_parsers import PydanticOutputParser
from langgraph.graph import START, StateGraph

logger = logging.getLogger(__name__)


class BaseDeepAnalysisState(MessagesState):
    target_repo: str
    sec_repo_doc: str
    document_tokens: int
    step0: str
    step1: str
    step2: str
    step3: str
    step_index: int
    # Some derived classes store a list of extracted "items" (e.g. threats, surfaces)
    # or extra text. We allow flexible usage by children:
    #   self-defined fields in child classes or appended at runtime.


StateType = TypeVar("StateType", bound=BaseDeepAnalysisState)
ModelType = TypeVar("ModelType", bound=BaseModel)


class BaseGithubDeepAnalysisAgent(BaseAgent, DeepAnalysisMixin, Generic[StateType, ModelType]):

    def __init__(
        self,
        llm: LLM,
        structured_llm: LLM,
        step_prompts: List[str],
        deep_analysis_prompt_template: str,
        format_prompt_template: str,
        checkpoint_manager: CheckpointManager,
        builder: StateGraph,
        # If a derived agent wants to parse the doc into structured data, provide:
        structured_parser_model: Optional[Type[ModelType]] = None,
        # By default, we do iteration if there's a structured parser
        do_iteration: bool = True,
    ):
        BaseAgent.__init__(self, llm, checkpoint_manager)
        DeepAnalysisMixin.__init__(self, deep_analysis_prompt_template, format_prompt_template)
        self.step_prompts = step_prompts
        self.step_count = len(step_prompts)
        self.structured_parser_model = structured_parser_model
        self.do_iteration = do_iteration
        self.builder = builder
        self.structured_llm = structured_llm

    def _internal_step(self, state: StateType) -> dict[str, Any]:
        step_index = int(state.get("step_index", 0))  # type: ignore
        if step_index >= len(self.step_prompts):
            logger.warning("Internal step called after all step_prompts are exhausted.")
            return {}

        target_repo = state["target_repo"]
        repo_name = target_repo.split("/")[-1]

        logger.info(f"Running internal step {step_index + 1} of {self.step_count}")
        step_prompt = self.step_prompts[step_index].format(target_repo=target_repo, repo_name=repo_name)

        step_msg = HumanMessage(content=step_prompt)
        messages = state["messages"] + [step_msg]
        response = self.llm.invoke(messages)
        doc_tokens = get_total_tokens(response)

        return {
            "messages": messages + [response],
            "document_tokens": state.get("document_tokens", 0) + doc_tokens,  # type: ignore
            "step_index": step_index + 1,
            f"step{step_index}": get_response_content(response),
        }

    def _internal_step_condition(self, state: StateType) -> Literal["internal_step", "final_response"]:
        if state.get("step_index", 0) < self.step_count:  # type: ignore
            return "internal_step"
        else:
            return "final_response"

    def _final_response(self, state: StateType) -> dict[str, Any]:
        messages = state["messages"]
        last_message = messages[-1]
        final_response = get_response_content(last_message)
        final_response = clean_markdown(final_response)

        return {"sec_repo_doc": final_response}

    def _structured_parse_step(self, state: StateType) -> dict[str, Any]:
        if not self.structured_parser_model:
            logger.info("No structured parser model provided; skipping parse step.")
            return {}

        doc_text = state["sec_repo_doc"]
        parser: PydanticOutputParser[ModelType] = PydanticOutputParser(pydantic_object=self.structured_parser_model)
        fmtted = self.format_prompt_template.format(text=doc_text, format_instructions=parser.get_format_instructions())
        parse_msg = HumanMessage(content=fmtted)
        response = self.structured_llm.invoke([parse_msg])
        doc_tokens = get_total_tokens(response)

        content = get_response_content(response)
        parsed_data: ModelType = parser.parse(content)
        # Store in a generic field. Child classes can interpret it further.
        return {
            "structured_data": parsed_data,
            "document_tokens": state.get("document_tokens", 0) + doc_tokens,  # type: ignore
        }

    def _has_more_items_condition(self, state: StateType) -> Literal["get_item_details", "items_final_response"]:
        # Default: skip iteration. Child classes override if needed.
        return "items_final_response"

    def _get_item_details(self, state: StateType) -> dict[str, Any]:
        logger.debug("No iteration in base class. Child classes should override if do_iteration=True.")
        return {}

    def _items_final_response(self, state: StateType) -> dict[str, Any]:
        return {}

    def _build(self) -> None:
        def internal_step(state: StateType) -> dict[str, Any]:
            return self._internal_step(state)

        def internal_step_condition(
            state: StateType,
        ) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: StateType) -> dict[str, Any]:
            return self._final_response(state)

        def structured_parse_step(state: StateType) -> dict[str, Any]:
            return self._structured_parse_step(state)

        def get_item_details(state: StateType) -> dict[str, Any]:
            return self._get_item_details(state)

        def items_final_response(state: StateType) -> dict[str, Any]:
            return self._items_final_response(state)

        def has_more_items_condition(
            state: StateType,
        ) -> Literal["get_item_details", "items_final_response"]:
            return self._has_more_items_condition(state)

        self.builder.add_node("internal_step", internal_step)
        self.builder.add_node("final_response", final_response)

        if self.structured_parser_model:
            self.builder.add_node("structured_parse_step", structured_parse_step)
            self.builder.add_node("get_item_details", get_item_details)
            self.builder.add_node("items_final_response", items_final_response)

        self.builder.add_edge(START, "internal_step")
        self.builder.add_conditional_edges("internal_step", internal_step_condition)

        if self.structured_parser_model:
            self.builder.add_edge("final_response", "structured_parse_step")
            self.builder.add_conditional_edges("structured_parse_step", has_more_items_condition)
            self.builder.add_conditional_edges("get_item_details", has_more_items_condition)
            self.builder.add_edge("items_final_response", "__end__")

    def build_graph(self) -> CompiledStateGraph:
        logger.debug("building graph...")
        self._build()
        graph = self.builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph
