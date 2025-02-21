import logging
from dataclasses import dataclass
from typing import Any, List

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph

from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens
from ai_security_analyzer.checkpointing import CheckpointManager
from pydantic import BaseModel


from ai_security_analyzer.github2_deep_base_agents import (
    BaseGithubDeepAnalysisAgent,
    BaseDeepAnalysisState,
)


logger = logging.getLogger(__name__)


class NoneBaseModel(BaseModel):
    pass


@dataclass
class AgentState(BaseDeepAnalysisState):
    # For sec-design, we don't iterate over items. We'll store final text:
    sec_design_details: str


class GithubAgent2Sd(BaseGithubDeepAnalysisAgent[AgentState, NoneBaseModel]):
    """
    Performs deep analysis of security design review.
    Notice this one does NOT do item-by-item iteration,
    so we set do_iteration=False.
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
            structured_parser_model=None,  # Not needed
            do_iteration=False,  # No iteration
            builder=StateGraph(AgentState),
        )

    def _get_sec_design_details(self, state: AgentState) -> dict[str, Any]:
        """
        Child-specific method. Called once after final_response,
        but we skip iteration. We'll do  "extra deep detail" step below if needed.
        """
        repo = state["target_repo"]

        doc = state["sec_repo_doc"]
        prompt = self.deep_analysis_prompt_template.format(
            target_repo=repo,
            repo_name=repo.split("/")[-1],
            text=doc,
        )
        msg = HumanMessage(content=prompt)
        response = self.llm.invoke([msg])
        tokens = get_total_tokens(response)
        details = get_response_content(response)
        return {
            "sec_design_details": details,
            "document_tokens": state["document_tokens"] + tokens,
        }

    def _build(self) -> None:
        super()._build()

        def get_sec_design_wrap(state: AgentState) -> dict[str, Any]:
            return self._get_sec_design_details(state)

        self.builder.add_node("get_sec_design_details", get_sec_design_wrap)
        self.builder.add_edge("final_response", "get_sec_design_details")
        self.builder.add_edge("get_sec_design_details", "__end__")
