import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Literal, Annotated

from langchain_core.messages import HumanMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field
from tiktoken import Encoding

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.utils import get_response_content, get_total_tokens, format_filename
from langchain_core.output_parsers import PydanticOutputParser
from operator import add


from ai_security_analyzer.prompts import GITHUB2_GET_ATTACK_SURFACE_DETAILS_PROMPT

logger = logging.getLogger(__name__)


class AttackSurface(BaseModel):
    title: str = Field(description="Title of the attack surface.")
    text: str = Field(description="Correctly formatted markdown text content of the attack surface.")


class AttackSurfaceAnalysis(BaseModel):
    attack_surfaces: List[AttackSurface] = Field(
        description="List of attack surfaces.",
    )


class OutputAttackSurface(BaseModel):
    title: str = Field(description="Title of the attack surface.")
    filename: str = Field(description="Filename of the attack surface.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the attack surface.")


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
    output_attack_surfaces: Annotated[list[OutputAttackSurface], add]
    attack_surfaces_index: int
    attack_surfaces_count: int
    attack_surfaces: List[AttackSurface]


class GithubAgent2As(BaseAgent):
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

    def _structured_attack_surface(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Getting structured attack surface analysis")
        try:
            sec_repo_doc = state["sec_repo_doc"]

            parser = PydanticOutputParser(pydantic_object=AttackSurfaceAnalysis)

            format_prompt = f"You are task with formatting attack surface analysis. Don't change any text content of attack surfaces only format it to json. Follow instructions carefully:\nATTACK SURFACE ANALYSIS:\n{sec_repo_doc}\n{parser.get_format_instructions()}"

            format_msg = HumanMessage(content=format_prompt)

            response = llm.invoke([format_msg])
            document_tokens = get_total_tokens(response)
            content = get_response_content(response)

            parsed_attack_surface_analysis = parser.parse(content)
            attack_surfaces = parsed_attack_surface_analysis.attack_surfaces
            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "attack_surfaces": attack_surfaces,
                "attack_surfaces_index": 0,
                "attack_surfaces_count": len(attack_surfaces),
            }
        except Exception as e:
            logger.error(f"Error on structured attack surface analysis: {e}")
            raise ValueError(str(e))

    def _get_attack_surface_details_condition(
        self, state: AgentState
    ) -> Literal["get_attack_surface_details", "attack_surfaces_final_response"]:
        attack_surfaces_index = state["attack_surfaces_index"]
        attack_surfaces_count = state["attack_surfaces_count"]

        if attack_surfaces_index < attack_surfaces_count:
            return "get_attack_surface_details"
        else:
            return "attack_surfaces_final_response"

    def _get_attack_surface_details(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(
            f"Getting attack surface details {state.get('attack_surfaces_index', 0)+1} of {state['attack_surfaces_count']}"
        )
        try:
            target_repo = state["target_repo"]
            attack_surfaces = state["attack_surfaces"]
            attack_surfaces_index = state.get("attack_surfaces_index", 0)

            get_attack_surface_details_prompt = GITHUB2_GET_ATTACK_SURFACE_DETAILS_PROMPT.format(
                target_repo, attack_surfaces[attack_surfaces_index].title, attack_surfaces[attack_surfaces_index].text
            )

            get_attack_surface_details_msg = HumanMessage(content=get_attack_surface_details_prompt)

            response = llm.invoke([get_attack_surface_details_msg])
            document_tokens = get_total_tokens(response)
            attack_surface_details = get_response_content(response)

            output_attack_surface = OutputAttackSurface(
                title=attack_surfaces[attack_surfaces_index].title,
                filename=format_filename(attack_surfaces[attack_surfaces_index].title),
                detail_analysis=attack_surface_details,
            )

            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "attack_surfaces_index": attack_surfaces_index + 1,
                "output_attack_surfaces": [output_attack_surface],
            }
        except Exception as e:
            logger.error(
                f"Error on get attack surface details {state['attack_surfaces_index']} of {state['attack_surfaces_count']}: {e}"
            )
            raise ValueError(str(e))

    def _attack_surfaces_final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting attack surfaces final response")
        try:
            attack_surfaces = state["attack_surfaces"]
            repo_name = state["target_repo"].split("/")[-1]
            owner_name = state["target_repo"].split("/")[-2]

            final_response = f"# Attack Surface Analysis for {owner_name}/{repo_name}\n\n"
            for attack_surface in attack_surfaces:
                attack_surface_filename = format_filename(attack_surface.title)
                attack_surface_path = f"./attack_surfaces/{attack_surface_filename}.md"
                final_response += (
                    f"## Attack Surface: [{attack_surface.title}]({attack_surface_path})\n\n{attack_surface.text}\n\n"
                )

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting attack surfaces final response: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2As.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        structured_llm = self.llm_provider.create_agent_llm_for_structured_queries()

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state, llm.llm, llm.model_config.use_system_message)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        def structured_attack_surface(state: AgentState):  # type: ignore[no-untyped-def]
            return self._structured_attack_surface(
                state, structured_llm.llm, structured_llm.model_config.use_system_message
            )

        def get_attack_surface_details(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_attack_surface_details(state, llm.llm, llm.model_config.use_system_message)

        def attack_surfaces_final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._attack_surfaces_final_response(state)

        def get_attack_surface_details_condition(
            state: AgentState,
        ) -> Literal["get_attack_surface_details", "attack_surfaces_final_response"]:
            return self._get_attack_surface_details_condition(state)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_node("structured_attack_surface", structured_attack_surface)
        builder.add_node("get_attack_surface_details", get_attack_surface_details)
        builder.add_node("attack_surfaces_final_response", attack_surfaces_final_response)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "structured_attack_surface")
        builder.add_conditional_edges("structured_attack_surface", get_attack_surface_details_condition)
        builder.add_conditional_edges("get_attack_surface_details", get_attack_surface_details_condition)
        builder.add_edge("attack_surfaces_final_response", "__end__")
        graph = builder.compile()

        return graph
