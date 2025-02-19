import logging
from dataclasses import dataclass
from typing import Any, List, Literal, Annotated

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from pydantic import BaseModel, Field

from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens, format_filename, clean_markdown
from operator import add


from ai_security_analyzer.github2_deep_base_agents import (
    BaseGithubDeepAnalysisAgent,
    BaseDeepAnalysisState,
)


logger = logging.getLogger(__name__)


class AttackTreePath(BaseModel):
    title: str = Field(description="Title of the attack tree path.")
    text: str = Field(description="Markdown text content of the attack tree path.")


class AttackTreeAnalysis(BaseModel):
    attack_tree_objective: str = Field(description="Objective of the attack tree.")
    attack_sub_tree_visualization: str = Field(description="Markdown for sub-tree visualization.")
    attack_sub_tree_paths: List[AttackTreePath] = Field(description="List of sub-tree paths.")


class OutputAttackTreePath(BaseModel):
    title: str = Field(description="Title of the attack tree path.")
    filename: str = Field(description="Filename of the attack tree path.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the attack tree path.")


@dataclass
class AgentState(BaseDeepAnalysisState):
    attack_tree_paths: List[AttackTreePath]
    attack_tree_paths_index: int
    attack_tree_paths_count: int
    attack_tree_visualization: str
    attack_tree_objective: str
    output_attack_tree_paths: Annotated[list[OutputAttackTreePath], add]


class GithubAgent2At(BaseGithubDeepAnalysisAgent[AgentState, AttackTreeAnalysis]):
    """
    Performs deep analysis of "attack tree" for a GitHub repo.
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
            structured_parser_model=AttackTreeAnalysis,
            do_iteration=True,
            builder=StateGraph(AgentState),
        )

    def _structured_parse_step(self, state: AgentState) -> dict[str, Any]:
        result = super()._structured_parse_step(state)

        tree_data = result["structured_data"]
        paths = tree_data.attack_sub_tree_paths
        result["attack_tree_paths"] = paths
        result["attack_tree_paths_index"] = 0
        result["attack_tree_paths_count"] = len(paths)
        result["attack_tree_visualization"] = tree_data.attack_sub_tree_visualization
        result["attack_tree_objective"] = tree_data.attack_tree_objective
        return result

    def _has_more_items_condition(self, state: AgentState) -> Literal["get_item_details", "items_final_response"]:
        if state["attack_tree_paths_index"] < state["attack_tree_paths_count"]:
            return "get_item_details"
        return "items_final_response"

    def _get_item_details(self, state: AgentState) -> dict[str, Any]:
        idx = state["attack_tree_paths_index"]
        paths = state["attack_tree_paths"]
        target_repo = state["target_repo"]

        prompt = self.deep_analysis_prompt_template.format(
            target_repo=target_repo,
            title=paths[idx].title,
            text=paths[idx].text,
        )
        msg = HumanMessage(content=prompt)
        response = self.llm.invoke([msg])
        tokens = get_total_tokens(response)
        detail = clean_markdown(get_response_content(response))

        output_attack_tree_path = OutputAttackTreePath(
            title=paths[idx].title,
            filename=format_filename(paths[idx].title),
            detail_analysis=detail,
        )

        return {
            "attack_tree_paths_index": idx + 1,
            "output_attack_tree_paths": [output_attack_tree_path],
            "document_tokens": state["document_tokens"] + tokens,
        }

    def _items_final_response(self, state: AgentState) -> dict[str, Any]:
        paths = state.get("attack_tree_paths", [])
        vis = state.get("attack_tree_visualization", "")
        obj = state.get("attack_tree_objective", "")
        repo_name = state["target_repo"].split("/")[-1]
        owner_name = state["target_repo"].split("/")[-2]

        final_response = f"# Attack Tree Analysis for {owner_name}/{repo_name}\n\n"
        final_response += f"Objective: {obj}\n\n"
        final_response += f"## Attack Tree Visualization\n\n{vis}\n\n"

        for p in paths:
            link_name = format_filename(p.title)
            path = f"./attack_tree_paths/{link_name}.md"
            final_response += f"## Attack Tree Path: [{p.title}]({path})\n\n{p.text}\n\n"

        return {"sec_repo_doc": final_response}
