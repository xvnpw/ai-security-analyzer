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


from ai_security_analyzer.prompts import GITHUB2_GET_ATTACK_TREE_PATH_DETAILS_PROMPT

logger = logging.getLogger(__name__)


class AttackTreePath(BaseModel):
    title: str = Field(description="Title of the attack tree path.")
    text: str = Field(description="Correctly formatted markdown text content of the attack tree path.")


class AttackTreeAnalysis(BaseModel):
    attack_tree_objective: str = Field(description="Objective of the attack tree analysis.")
    attack_sub_tree_visualization: str = Field(
        description="Correctly formatted markdown visualization of the attack sub-tree."
    )
    attack_sub_tree_paths: List[AttackTreePath] = Field(
        description="List of attack sub-tree paths.",
    )


class OutputAttackTreePath(BaseModel):
    title: str = Field(description="Title of the attack tree path.")
    filename: str = Field(description="Filename of the attack tree path.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the attack tree path.")


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
    output_attack_tree_paths: Annotated[list[OutputAttackTreePath], add]
    attack_tree_paths_index: int
    attack_tree_paths_count: int
    attack_tree_paths: List[AttackTreePath]
    attack_tree_visualization: str
    attack_tree_objective: str


class GithubAgent2At(BaseAgent):
    """GithubAgent2At is a class that is used to generate deep analysis of attack tree based on model knowledge about specific GitHub repository.

    It was built to be used with Google's Gemini 2.0 Flask Thinking Experimental Mode.
    Experimental model is working well with markdown and mermaid syntax, that's why cannot use GithubAgent class.
    """

    def __init__(self, llm_provider: LLMProvider, step_prompts: List[Callable[[str], str]]):
        super().__init__(llm_provider)
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

    def _structured_attack_tree_path(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Getting structured attack tree path analysis")
        try:
            sec_repo_doc = state["sec_repo_doc"]

            parser = PydanticOutputParser(pydantic_object=AttackTreeAnalysis)

            format_prompt = f"You are task with formatting attack tree path analysis. Don't change any text content of attack tree paths only format it to json. Follow instructions carefully:\nATTACK TREE PATH ANALYSIS:\n{sec_repo_doc}\n{parser.get_format_instructions()}"

            format_msg = HumanMessage(content=format_prompt)

            response = llm.invoke([format_msg])
            document_tokens = get_total_tokens(response)
            content = get_response_content(response)

            parsed_attack_tree_analysis = parser.parse(content)
            attack_tree_paths = parsed_attack_tree_analysis.attack_sub_tree_paths
            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "attack_tree_paths": attack_tree_paths,
                "attack_tree_visualization": parsed_attack_tree_analysis.attack_sub_tree_visualization,
                "attack_tree_objective": parsed_attack_tree_analysis.attack_tree_objective,
                "attack_tree_paths_index": 0,
                "attack_tree_paths_count": len(attack_tree_paths),
            }
        except Exception as e:
            logger.error(f"Error on structured attack tree path analysis: {e}")
            raise ValueError(str(e))

    def _get_attack_tree_path_details_condition(
        self, state: AgentState
    ) -> Literal["get_attack_tree_path_details", "attack_tree_paths_final_response"]:
        attack_tree_paths_index = state["attack_tree_paths_index"]
        attack_tree_paths_count = state["attack_tree_paths_count"]

        if attack_tree_paths_index < attack_tree_paths_count:
            return "get_attack_tree_path_details"
        else:
            return "attack_tree_paths_final_response"

    def _get_attack_tree_path_details(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info(
            f"Getting attack tree path details {state.get('attack_tree_paths_index', 0)+1} of {state['attack_tree_paths_count']}"
        )
        try:
            target_repo = state["target_repo"]
            attack_tree_paths = state["attack_tree_paths"]
            attack_tree_paths_index = state.get("attack_tree_paths_index", 0)

            get_attack_tree_path_details_prompt = GITHUB2_GET_ATTACK_TREE_PATH_DETAILS_PROMPT.format(
                target_repo,
                attack_tree_paths[attack_tree_paths_index].title,
                attack_tree_paths[attack_tree_paths_index].text,
            )

            get_attack_tree_path_details_msg = HumanMessage(content=get_attack_tree_path_details_prompt)

            response = llm.invoke([get_attack_tree_path_details_msg])
            document_tokens = get_total_tokens(response)
            attack_tree_path_details = get_response_content(response)

            output_attack_tree_path = OutputAttackTreePath(
                title=attack_tree_paths[attack_tree_paths_index].title,
                filename=format_filename(attack_tree_paths[attack_tree_paths_index].title),
                detail_analysis=attack_tree_path_details,
            )

            return {
                "document_tokens": state.get("document_tokens", 0) + document_tokens,
                "attack_tree_paths_index": attack_tree_paths_index + 1,
                "output_attack_tree_paths": [output_attack_tree_path],
            }
        except Exception as e:
            logger.error(
                f"Error on get attack tree path details {state['attack_tree_paths_index']} of {state['attack_tree_paths_count']}: {e}"
            )
            raise ValueError(str(e))

    def _attack_tree_paths_final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting attack tree paths final response")
        try:
            attack_tree_paths = state["attack_tree_paths"]
            repo_name = state["target_repo"].split("/")[-1]
            owner_name = state["target_repo"].split("/")[-2]

            attack_tree_visualization = state["attack_tree_visualization"]
            attack_tree_visualization = self._format_attack_tree_visualization(attack_tree_visualization)

            final_response = f"# Attack Tree Analysis for {owner_name}/{repo_name}\n\n"
            final_response += f"Objective: {state['attack_tree_objective']}\n\n"
            final_response += f"## Attack Tree Visualization\n\n{attack_tree_visualization}\n\n"
            for attack_tree_path in attack_tree_paths:
                attack_tree_path_filename = format_filename(attack_tree_path.title)
                attack_tree_path_path = f"./attack_tree_paths/{attack_tree_path_filename}.md"
                final_response += f"## Attack Tree Path: [{attack_tree_path.title}]({attack_tree_path_path})\n\n{attack_tree_path.text}\n\n"

            return {
                "sec_repo_doc": final_response,
            }
        except Exception as e:
            logger.error(f"Error on getting attack tree paths final response: {e}")
            raise ValueError(str(e))

    def _format_attack_tree_visualization(self, visualization: str) -> str:
        visualization = visualization.strip()
        if not visualization.startswith("```"):
            visualization = f"```\n{visualization}"

        if not visualization.endswith("```"):
            visualization = f"{visualization}\n```\n"

        return visualization

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent2At.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        structured_llm = self.llm_provider.create_agent_llm_for_structured_queries()

        def internal_step(state: AgentState):  # type: ignore[no-untyped-def]
            return self._internal_step(state, llm.llm, llm.model_config.use_system_message)

        def internal_step_condition(state: AgentState) -> Literal["internal_step", "final_response"]:
            return self._internal_step_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        def structured_attack_tree_path(state: AgentState):  # type: ignore[no-untyped-def]
            return self._structured_attack_tree_path(
                state, structured_llm.llm, structured_llm.model_config.use_system_message
            )

        def get_attack_tree_path_details(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_attack_tree_path_details(state, llm.llm, llm.model_config.use_system_message)

        def attack_tree_paths_final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._attack_tree_paths_final_response(state)

        def get_attack_tree_path_details_condition(
            state: AgentState,
        ) -> Literal["get_attack_tree_path_details", "attack_tree_paths_final_response"]:
            return self._get_attack_tree_path_details_condition(state)

        builder = StateGraph(AgentState)
        builder.add_node("internal_step", internal_step)
        builder.add_node("final_response", final_response)
        builder.add_node("structured_attack_tree_path", structured_attack_tree_path)
        builder.add_node("get_attack_tree_path_details", get_attack_tree_path_details)
        builder.add_node("attack_tree_paths_final_response", attack_tree_paths_final_response)
        builder.add_edge(START, "internal_step")
        builder.add_conditional_edges("internal_step", internal_step_condition)
        builder.add_edge("final_response", "structured_attack_tree_path")
        builder.add_conditional_edges("structured_attack_tree_path", get_attack_tree_path_details_condition)
        builder.add_conditional_edges("get_attack_tree_path_details", get_attack_tree_path_details_condition)
        builder.add_edge("attack_tree_paths_final_response", "__end__")
        graph = builder.compile()

        return graph
