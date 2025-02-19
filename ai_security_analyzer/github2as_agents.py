import logging
from typing import List, Literal, Annotated, Any

from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage

from ai_security_analyzer.github2_deep_base_agents import (
    BaseGithubDeepAnalysisAgent,
    BaseDeepAnalysisState,
)
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.utils import (
    clean_markdown,
    get_response_content,
    get_total_tokens,
    format_filename,
)
from langgraph.graph import StateGraph
from operator import add
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class AttackSurface(BaseModel):
    title: str = Field(description="Title of the attack surface.")
    text: str = Field(description="Markdown text content of the attack surface.")


class AttackSurfaceAnalysis(BaseModel):
    attack_surfaces: List[AttackSurface] = Field(description="List of attack surfaces.")


class OutputAttackSurface(BaseModel):
    title: str = Field(description="Title of the attack surface.")
    filename: str = Field(description="Filename of the attack surface.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the attack surface.")


@dataclass
class AgentState(BaseDeepAnalysisState):
    attack_surfaces: List[AttackSurface]
    attack_surfaces_index: int
    attack_surfaces_count: int
    output_attack_surfaces: Annotated[List[OutputAttackSurface], add]


class GithubAgent2As(BaseGithubDeepAnalysisAgent[AgentState, AttackSurfaceAnalysis]):
    """
    Performs deep analysis of "attack surfaces" for a GitHub repo.
    Inherits the repeated logic from BaseGithubDeepAnalysisAgent.
    """

    def __init__(
        self,
        llm: LLM,
        structured_llm: LLM,
        step_prompts: List[str],
        deep_analysis_prompt_template: str,
        format_prompt_template: str,
        checkpoint_manager: CheckpointManager,
    ):
        super().__init__(
            llm=llm,
            structured_llm=structured_llm,
            step_prompts=step_prompts,
            deep_analysis_prompt_template=deep_analysis_prompt_template,
            format_prompt_template=format_prompt_template,
            checkpoint_manager=checkpoint_manager,
            structured_parser_model=AttackSurfaceAnalysis,
            do_iteration=True,
            builder=StateGraph(AgentState),
        )

    def _has_more_items_condition(self, state: AgentState) -> Literal["get_item_details", "items_final_response"]:
        if state["attack_surfaces_index"] < state["attack_surfaces_count"]:
            return "get_item_details"
        else:
            return "items_final_response"

    def _structured_parse_step(self, state: AgentState) -> dict[str, Any]:
        # Call the base method to parse
        result = super()._structured_parse_step(state)

        surfaces = result["structured_data"].attack_surfaces
        result["attack_surfaces"] = surfaces
        result["attack_surfaces_index"] = 0
        result["attack_surfaces_count"] = len(surfaces)
        return result

    def _get_item_details(self, state: AgentState) -> dict[str, Any]:
        idx = state["attack_surfaces_index"]
        surfaces = state["attack_surfaces"]
        target_repo = state["target_repo"]
        title = surfaces[idx].title
        text = surfaces[idx].text

        prompt = self.deep_analysis_prompt_template.format(
            target_repo=target_repo,
            title=title,
            text=text,
        )
        msg = HumanMessage(content=prompt)
        response = self.llm.invoke([msg])
        tokens = get_total_tokens(response)
        detail = clean_markdown(get_response_content(response))

        output_attack_surface = OutputAttackSurface(
            title=title,
            filename=format_filename(title),
            detail_analysis=detail,
        )

        return {
            "attack_surfaces_index": idx + 1,
            "output_attack_surfaces": [output_attack_surface],
            "document_tokens": state["document_tokens"] + tokens,
        }

    def _items_final_response(self, state: AgentState) -> dict[str, Any]:
        surfaces = state["attack_surfaces"]
        repo_name = state["target_repo"].split("/")[-1]
        owner_name = state["target_repo"].split("/")[-2]

        final_response = f"# Attack Surface Analysis for {owner_name}/{repo_name}\n\n"
        for surface in surfaces:
            surface_filename = format_filename(surface.title)
            surface_path = f"./attack_surfaces/{surface_filename}.md"
            final_response += f"## Attack Surface: [{surface.title}]({surface_path})\n\n" f"{surface.text}\n\n"

        return {
            "sec_repo_doc": final_response,
        }
