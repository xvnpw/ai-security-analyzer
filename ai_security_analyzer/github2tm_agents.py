import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Literal, Annotated

from langchain_core.messages import HumanMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.utils import get_response_content, get_total_tokens, format_filename
from langchain_core.output_parsers import PydanticOutputParser
from operator import add
from ai_security_analyzer.checkpointing import CheckpointManager

from ai_security_analyzer.prompts import GITHUB2_FORMAT_THREAT_MODEL_PROMPT, GITHUB2_GET_THREAT_DETAILS_PROMPT

logger = logging.getLogger(__name__)


class Threat(BaseModel):
    title: str = Field(description="Title of the threat.")
    text: str = Field(description="Correctly formatted markdown text content of the threat.")


class ThreatModel(BaseModel):
    threats: List[Threat] = Field(
        description="List of threats.",
    )


class OutputThreat(BaseModel):
    title: str = Field(description="Title of the threat.")
    filename: str = Field(description="Filename of the threat.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the threat.")


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
    output_threats: Annotated[list[OutputThreat], add]
    threats_index: int
    threats_count: int
    threats: List[Threat]


class GithubAgent2Tm(BaseAgent):
    """GithubAgent2Tm is a class that is used to generate deep analysis of threat model based on model knowledge about specific GitHub repository.

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

    def _structured_threat_model(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Getting structured threat model")
        try:
            sec_repo_doc = state["sec_repo_doc"]

            parser = PydanticOutputParser(pydantic_object=ThreatModel)

            format_prompt = GITHUB2_FORMAT_THREAT_MODEL_PROMPT.format(sec_repo_doc, parser.get_format_instructions())

            format_msg = HumanMessage(content=format_prompt)

            response = llm.invoke([format_msg])
            document_tokens = get_total_tokens(response)
            content = get_response_content(response)

            parsed_threat_model = parser.parse(content)
            threats = parsed_threat_model.threats
            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "threats": threats,
                "threats_index": 0,
                "threats_count": len(threats),
            }
        except Exception as e:
            logger.error(f"Error on structured threat model: {e}")
            raise ValueError(str(e))

    def _get_threat_details_condition(
        self, state: AgentState
    ) -> Literal["get_threat_details", "threats_final_response"]:
        threats_index = state["threats_index"]
        threats_count = state["threats_count"]

        if threats_index < threats_count:
            return "get_threat_details"
        else:
            return "threats_final_response"

    def _get_threat_details(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(f"Getting threat details {state.get('threats_index', 0)+1} of {state['threats_count']}")
        try:
            target_repo = state["target_repo"]
            threats = state["threats"]
            threats_index = state.get("threats_index", 0)

            get_threat_details_prompt = GITHUB2_GET_THREAT_DETAILS_PROMPT.format(
                target_repo, threats[threats_index].title, threats[threats_index].text
            )

            get_threat_details_msg = HumanMessage(content=get_threat_details_prompt)

            response = llm.invoke([get_threat_details_msg])
            document_tokens = get_total_tokens(response)
            threat_details = get_response_content(response)

            output_threat = OutputThreat(
                title=threats[threats_index].title,
                filename=format_filename(threats[threats_index].title),
                detail_analysis=threat_details,
            )

            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "threats_index": threats_index + 1,
                "output_threats": [output_threat],
            }
        except Exception as e:
            logger.error(f"Error on get threat details {state['threats_index']+1} of {state['threats_count']}: {e}")
            raise ValueError(str(e))

    def _threats_final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting threats final response")
        try:
            threats = state["threats"]
            repo_name = state["target_repo"].split("/")[-1]
            owner_name = state["target_repo"].split("/")[-2]

            final_response = f"# Threat Model Analysis for {owner_name}/{repo_name}\n\n"
            for threat in threats:
                threat_filename = format_filename(threat.title)
                threat_path = f"./threats/{threat_filename}.md"
                final_response += f"## Threat: [{threat.title}]({threat_path})\n\n{threat.text}\n\n"

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting final response: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2Tm.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        structured_llm = self.llm_provider.create_agent_llm_for_structured_queries()

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state, llm.llm, llm.model_config.use_system_message)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        def structured_threat_model(state: AgentState):  # type: ignore[no-untyped-def]
            return self._structured_threat_model(
                state, structured_llm.llm, structured_llm.model_config.use_system_message
            )

        def get_threat_details(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_threat_details(state, llm.llm, llm.model_config.use_system_message)

        def threats_final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._threats_final_response(state)

        def get_threat_details_condition(state: AgentState) -> Literal["get_threat_details", "threats_final_response"]:
            return self._get_threat_details_condition(state)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_node("structured_threat_model", structured_threat_model)
        builder.add_node("get_threat_details", get_threat_details)
        builder.add_node("threats_final_response", threats_final_response)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "structured_threat_model")
        builder.add_conditional_edges("structured_threat_model", get_threat_details_condition)
        builder.add_conditional_edges("get_threat_details", get_threat_details_condition)
        builder.add_edge("threats_final_response", "__end__")
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph
