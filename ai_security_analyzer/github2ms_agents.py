import logging
from dataclasses import dataclass
from typing import Any, List, Literal, Annotated

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from pydantic import BaseModel, Field

from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens, format_filename, clean_markdown
from operator import add
from ai_security_analyzer.checkpointing import CheckpointManager


from ai_security_analyzer.github2_deep_base_agents import (
    BaseGithubDeepAnalysisAgent,
    BaseDeepAnalysisState,
)


logger = logging.getLogger(__name__)


class MitigationStrategy(BaseModel):
    title: str = Field(description="Title of the mitigation strategy.")
    text: str = Field(description="Markdown text for the mitigation strategy.")


class MitigationStrategies(BaseModel):
    mitigation_strategies: List[MitigationStrategy] = Field(description="List of strategies.")


class OutputMitigationStrategy(BaseModel):
    title: str = Field(description="Title of the mitigation strategy.")
    filename: str = Field(description="Filename of the mitigation strategy.")
    detail_analysis: str = Field(description="Markdown formatted detailed analysis of the mitigation strategy.")


@dataclass
class AgentState(BaseDeepAnalysisState):
    mitigation_strategies: List[MitigationStrategy]
    mitigation_strategies_index: int
    mitigation_strategies_count: int
    output_mitigation_strategies: Annotated[list[OutputMitigationStrategy], add]


class GithubAgent2Ms(BaseGithubDeepAnalysisAgent[AgentState, MitigationStrategies]):
    """
    Performs deep analysis of "mitigation strategies" for a GitHub repo.
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
            structured_parser_model=MitigationStrategies,
            do_iteration=True,
            builder=StateGraph(AgentState),
        )

    def _structured_parse_step(self, state: AgentState) -> dict[str, Any]:
        result = super()._structured_parse_step(state)

        data = result["structured_data"]
        strats = data.mitigation_strategies
        result["mitigation_strategies"] = strats
        result["mitigation_strategies_index"] = 0
        result["mitigation_strategies_count"] = len(strats)
        return result

    def _has_more_items_condition(self, state: AgentState) -> Literal["get_item_details", "items_final_response"]:
        if state["mitigation_strategies_index"] < state["mitigation_strategies_count"]:
            return "get_item_details"
        return "items_final_response"

    def _get_item_details(self, state: AgentState) -> dict[str, Any]:
        idx = state["mitigation_strategies_index"]
        strats = state["mitigation_strategies"]
        target_repo = state["target_repo"]

        prompt = self.deep_analysis_prompt_template.format(
            target_repo=target_repo,
            title=strats[idx].title,
            text=strats[idx].text,
        )
        msg = HumanMessage(content=prompt)
        response = self.llm.invoke([msg])
        tokens = get_total_tokens(response)
        detail = clean_markdown(get_response_content(response))

        output_mitigation_strategy = OutputMitigationStrategy(
            title=strats[idx].title,
            filename=format_filename(strats[idx].title),
            detail_analysis=detail,
        )

        return {
            "mitigation_strategies_index": idx + 1,
            "output_mitigation_strategies": [output_mitigation_strategy],
            "document_tokens": state["document_tokens"] + tokens,
        }

    def _items_final_response(self, state: AgentState) -> dict[str, Any]:
        strats = state.get("mitigation_strategies", [])
        repo_name = state["target_repo"].split("/")[-1]
        owner_name = state["target_repo"].split("/")[-2]

        final = f"# Mitigation Strategies Analysis for {owner_name}/{repo_name}\n\n"
        for s in strats:
            link_name = format_filename(s.title)
            path = f"./mitigation_strategies/{link_name}.md"
            final += f"## Mitigation Strategy: [{s.title}]({path})\n\n{s.text}\n\n"
        return {"sec_repo_doc": final}
