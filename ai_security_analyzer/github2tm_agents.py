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
class AgentState(BaseDeepAnalysisState):
    threats: List[Threat]
    threats_index: int
    threats_count: int
    output_threats: Annotated[list[OutputThreat], add]


class GithubAgent2Tm(BaseGithubDeepAnalysisAgent[AgentState, ThreatModel]):
    """
    Performs deep analysis (threat modeling).
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
            structured_parser_model=ThreatModel,
            do_iteration=True,
            builder=StateGraph(AgentState),
        )

    def _structured_parse_step(self, state: AgentState) -> dict[str, Any]:
        result = super()._structured_parse_step(state)

        data = result["structured_data"]
        thr = data.threats
        result["threats"] = thr
        result["threats_index"] = 0
        result["threats_count"] = len(thr)
        return result

    def _has_more_items_condition(self, state: AgentState) -> Literal["get_item_details", "items_final_response"]:
        idx = state["threats_index"]
        if idx < state["threats_count"]:
            return "get_item_details"
        return "items_final_response"

    def _get_item_details(self, state: AgentState) -> dict[str, Any]:
        idx = state["threats_index"]
        thr = state["threats"]
        target_repo = state["target_repo"]

        prompt = self.deep_analysis_prompt_template.format(
            target_repo=target_repo,
            title=thr[idx].title,
            text=thr[idx].text,
        )
        msg = HumanMessage(content=prompt)
        response = self.llm.invoke([msg])
        tokens = get_total_tokens(response)
        detail = clean_markdown(get_response_content(response))

        output_threat = OutputThreat(
            title=thr[idx].title,
            filename=format_filename(thr[idx].title),
            detail_analysis=detail,
        )
        return {
            "threats_index": idx + 1,
            "document_tokens": state["document_tokens"] + tokens,
            "output_threats": [output_threat],
        }

    def _items_final_response(self, state: AgentState) -> dict[str, Any]:
        thr = state.get("threats", [])
        repo_name = state["target_repo"].split("/")[-1]
        owner_name = state["target_repo"].split("/")[-2]

        final_response = f"# Threat Model Analysis for {owner_name}/{repo_name}\n\n"
        for t in thr:
            fname = format_filename(t.title)
            path = f"./threats/{fname}.md"
            final_response += f"## Threat: [{t.title}]({path})\n\n{t.text}\n\n"
        return {"sec_repo_doc": final_response}
