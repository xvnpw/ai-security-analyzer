import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Literal, Optional, Union

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding
from typing_extensions import TypedDict

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from ai_security_analyzer.utils import get_response_content, get_total_tokens

logger = logging.getLogger(__name__)


class GraphNodeType(Enum):
    REFINE_DRAFT = "refine_draft"
    MARKDOWN_VALIDATOR = "markdown_validator"
    EDITOR = "editor"


MESSAGE_TYPE = Literal["create", "update"]


@dataclass
class AgentState(TypedDict):
    target_repo: str
    sec_repo_doc: str
    sec_repo_doc_validation_error: Optional[str]
    editor_turns_count: int
    document_tokens: int
    refinement_count: int
    current_refinement_count: int


class GithubAgent(BaseAgent):
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

    def _create_initial_draft(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Creating initial draft")
        try:
            agent_msg = (
                SystemMessage(content=self.agent_prompt)
                if use_system_message
                else HumanMessage(content=self.agent_prompt)
            )

            human_prompt = self._create_human_prompt(
                message_type="create",
                current_description="",
                doc_type_prompt=self.doc_type_prompt,
                target_repo=state["target_repo"],
            )
            messages = [agent_msg, HumanMessage(content=human_prompt)]

            response = llm.invoke(messages)
            document_tokens = get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "document_tokens": document_tokens,
            }
        except Exception as e:
            logger.error(f"Error creating initial draft: {e}")
            raise ValueError(str(e))

    def _refine_draft(self, state: AgentState, llm: Any, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Refining draft")
        try:
            current_description = state.get("sec_repo_doc", "")
            target_repo = state["target_repo"]

            messages = self._create_update_messages(current_description, use_system_message, target_repo)

            response = llm.invoke(messages)
            document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "document_tokens": document_tokens,
                "current_refinement_count": state.get("current_refinement_count", 0) + 1,
            }
        except Exception as e:
            logger.error(f"Error updating draft: {e}")
            raise ValueError(str(e))

    def _refine_draft_condition(self, state: AgentState) -> Literal["refine_draft", "markdown_validator"]:
        current_refinement_count = state.get("current_refinement_count", 0)
        refinement_count = state["refinement_count"]

        if current_refinement_count < refinement_count:
            logger.info(f"Refining draft. Iteration {current_refinement_count+1} of {refinement_count}")
            return GraphNodeType.REFINE_DRAFT.value
        else:
            return GraphNodeType.MARKDOWN_VALIDATOR.value

    def _markdown_validator(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Validating markdown")
        sec_repo_doc = state["sec_repo_doc"]

        is_valid, error = self.markdown_validator.validate_content(sec_repo_doc)

        if not is_valid:
            logger.debug(f"Markdown validation error: {error}")
            return {"sec_repo_doc_validation_error": error}

    def _markdown_error_condition(self, state: AgentState) -> Literal["editor", "__end__"]:
        sec_repo_doc_validation_error = state.get("sec_repo_doc_validation_error", "")
        editor_turns_count = state.get("editor_turns_count", 0)
        if sec_repo_doc_validation_error and editor_turns_count < self.max_editor_turns_count:
            logger.info(
                f"Markdown validation error. Fixing. Try {editor_turns_count+1} of {self.max_editor_turns_count}"
            )
            return GraphNodeType.EDITOR.value
        else:
            return "__end__"

    def _editor(self, state: AgentState, llm: BaseChatModel, use_system_message: bool):  # type: ignore[no-untyped-def]
        logger.info("Fixing markdown broken formatting")
        sec_repo_doc = state["sec_repo_doc"]
        sec_repo_doc_validation_error = state["sec_repo_doc_validation_error"]

        editor_prompt = self._get_editor_prompt()
        editor_msg: Union[SystemMessage, HumanMessage] = (
            SystemMessage(content=editor_prompt) if use_system_message else HumanMessage(content=editor_prompt)
        )

        human_prompt = f"""MARKDOWN MERMAID RENDER ERRORS:
        {sec_repo_doc_validation_error}

        INPUT:
        {sec_repo_doc}"""

        messages = [editor_msg, HumanMessage(content=human_prompt)]

        response = llm.invoke(messages)
        document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
        return {
            "sec_repo_doc": get_response_content(response),
            "sec_repo_doc_validation_error": "",
            "editor_turns_count": state.get("editor_turns_count", 0) + 1,
            "document_tokens": document_tokens,
        }

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{GithubAgent.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        editor_llm = self.llm_provider.create_editor_llm()

        def create_initial_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._create_initial_draft(state, llm.llm, llm.model_config.use_system_message)

        def refine_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._refine_draft(state, llm.llm, llm.model_config.use_system_message)

        def refine_draft_condition(
            state: AgentState,
        ) -> Literal["refine_draft", "markdown_validator"]:
            return self._refine_draft_condition(state)

        def markdown_validator(state: AgentState):  # type: ignore[no-untyped-def]
            return self._markdown_validator(state)

        def markdown_error_condition(state: AgentState) -> Literal["editor", "__end__"]:
            return self._markdown_error_condition(state)

        def editor(state: AgentState):  # type: ignore[no-untyped-def]
            return self._editor(state, editor_llm.llm, editor_llm.model_config.use_system_message)

        builder = StateGraph(AgentState)
        builder.add_node("create_initial_draft", create_initial_draft)
        builder.add_node(GraphNodeType.REFINE_DRAFT.value, refine_draft)
        builder.add_node(GraphNodeType.MARKDOWN_VALIDATOR.value, markdown_validator)
        builder.add_node(GraphNodeType.EDITOR.value, editor)
        builder.add_edge(START, "create_initial_draft")
        builder.add_conditional_edges("create_initial_draft", refine_draft_condition)
        builder.add_conditional_edges(GraphNodeType.REFINE_DRAFT.value, refine_draft_condition)
        builder.add_conditional_edges(GraphNodeType.MARKDOWN_VALIDATOR.value, markdown_error_condition)
        builder.add_edge(GraphNodeType.EDITOR.value, GraphNodeType.MARKDOWN_VALIDATOR.value)
        graph = builder.compile()

        return graph

    def _create_update_messages(
        self,
        current_description: str,
        use_system_message: bool,
        target_repo: str,
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for updating the draft"""
        agent_msg = (
            SystemMessage(content=self.agent_prompt) if use_system_message else HumanMessage(content=self.agent_prompt)
        )

        human_prompt = self._create_human_prompt("update", current_description, self.doc_type_prompt, target_repo)

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        message_type: MESSAGE_TYPE,
        current_description: str,
        doc_type_prompt: str,
        target_repo: str,
    ) -> str:
        """Create human prompt for document processing"""
        if message_type == "create":
            return f"GITHUB REPOSITORY: {target_repo}"
        else:
            return f"""GITHUB REPOSITORY: {target_repo}
CURRENT {doc_type_prompt}:
{current_description}
"""

    def _get_editor_prompt(self) -> str:
        return """# IDENTITY and PURPOSE

You are an expert at cleaning up broken and, malformatted, markdown text, for example: line breaks in weird places, broken mermaid diagrams, etc.

# Steps

- Read the entire document and fully understand it.
- Remove any strange line breaks that disrupt formatting.
- Add capitalization, punctuation, line breaks, paragraphs and other formatting where necessary.
- Fix broken markdown formatting
- Fix broken mermaid diagrams
- Do NOT change any content or spelling whatsoever.

# OUTPUT INSTRUCTIONS

- Output the full, properly-formatted text.
- Do not output warnings or notes—just the requested sections.
- Do not complain about anything, just do what you're told.
- Do not add explanations or commentary
- Do not format or restructure the output
- Do not summarize or paraphrase

# INPUT:

INPUT:

    """
