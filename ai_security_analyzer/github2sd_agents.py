import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Literal

from langchain_core.messages import HumanMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.utils import get_response_content, get_total_tokens


from ai_security_analyzer.prompts import GITHUB2_SEC_DESIGN_DETAILS_PROMPT

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
    step_count: int
    step_prompts: List[Callable[[str], str]]
    sec_design_details: str


class GithubAgent2Sd(BaseAgent):
    """GithubAgent2Sd is a class that is used to generate deep analysis of security design review based on model knowledge about specific GitHub repository.

    It was built to be used with Google's Gemini 2.0 Flask Thinking Experimental Mode.
    Experimental model is working well with markdown and mermaid syntax, that's why cannot use GithubAgent class.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        text_splitter: CharacterTextSplitter,
        tokenizer: Encoding,
        max_editor_turns_count: int,
        markdown_validator: MarkdownMermaidValidator,
        doc_processor: DocumentProcessor,
        doc_filter: DocumentFilter,
        agent_prompt: str,
        doc_type_prompt: str,
    ):
        super().__init__(
            llm_provider,
            text_splitter,
            tokenizer,
            max_editor_turns_count,
            markdown_validator,
            doc_processor,
            doc_filter,
            agent_prompt,
            doc_type_prompt,
        )

    def _internal_step(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(f"Internal step {state.get('step_index', 0)+1} of {state['step_count']}")
        try:
            target_repo = state["target_repo"]
            step_index = state.get("step_index", 0)
            step_prompts = state["step_prompts"]

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
            logger.error(f"Error on internal step {state['step_index']} of {state['step_count']}: {e}")
            raise ValueError(str(e))

    def _internal_step_condition(self, state: AgentState) -> Literal["internal_step", "final_response"]:
        current_step_index = state["step_index"]
        step_count = state["step_count"]

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
            final_response = final_response.strip()

            if final_response.startswith("```markdown"):
                final_response = final_response.replace("```markdown", "")

            if final_response.endswith("```"):
                final_response = final_response[:-3]

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting final response: {e}")
            raise ValueError(str(e))

    def _get_sec_design_details(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Getting deep analysis of security design review")
        try:
            target_repo = state["target_repo"]
            repo_name = target_repo.split("/")[-1]
            sec_repo_doc = state["sec_repo_doc"]

            get_details_prompt = GITHUB2_SEC_DESIGN_DETAILS_PROMPT.format(
                target_repo, sec_repo_doc, repo_name, repo_name
            )

            get_details_msg = HumanMessage(content=get_details_prompt)

            response = llm.invoke([get_details_msg])
            document_tokens = get_total_tokens(response)
            sec_design_details = get_response_content(response)

            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "sec_design_details": sec_design_details,
            }
        except Exception as e:
            logger.error(f"Error on get deep analysis of security design review: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2Sd.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state, llm.llm, llm.model_config.use_system_message)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        def get_sec_design_details(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_sec_design_details(state, llm.llm, llm.model_config.use_system_message)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_node("get_sec_design_details", get_sec_design_details)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "get_sec_design_details")
        builder.add_edge("get_sec_design_details", "__end__")
        graph = builder.compile()

        return graph
