from dataclasses import dataclass
from enum import Enum
import logging
from typing import Any, List, Literal, Optional, Set, Union
from typing_extensions import TypedDict

from langchain_core.documents import Document
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.loaders import RepoDirectoryLoader
from ai_security_analyzer.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class GraphNodeType(Enum):
    UPDATE_DRAFT = "update_draft_with_new_docs"
    MARKDOWN_VALIDATOR = "markdown_validator"
    EDITOR = "editor"


MESSAGE_TYPE = Literal["create", "update"]


@dataclass
class AgentState(TypedDict):
    target_dir: str
    project_type: str
    exclude: Optional[List[str]]
    exclude_mode: Literal["add", "override"]
    include: Optional[List[str]]
    include_mode: Literal["add", "override"]
    filter_keywords: Optional[Set[str]]
    repo_docs: List[Document]
    sorted_filtered_docs: List[Document]
    splitted_docs: List[Document]
    sec_repo_doc: str
    processed_docs_count: int
    sec_repo_doc_validation_error: Optional[str]
    editor_turns_count: int
    document_tokens: int


class CreateProjectSecurityDesignAgent(BaseAgent):
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
        draft_update_prompt: str,
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
            draft_update_prompt,
        )

    def _load_files(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Loading files")
        try:
            loader = RepoDirectoryLoader(
                state["target_dir"],
                state["project_type"],
                state["exclude"],
                state["exclude_mode"],
                state["include"],
                state["include_mode"],
            )
            docs = loader.load()
            logger.info(f"Loaded {len(docs)} documents")
            return {"repo_docs": docs}
        except Exception as e:
            logger.error(f"Error loading files: {e}")
            raise ValueError(f"Failed to load files: {str(e)}")

    def _sort_filter_docs(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Sorting and filtering documents")
        try:
            filter_keywords = state["filter_keywords"]
            sorted_filtered = self.doc_filter.sort_and_filter_docs(state["repo_docs"], filter_keywords)
            logger.info(f"Documents after sorting and filtering: {len(sorted_filtered)}")
            return {"sorted_filtered_docs": sorted_filtered}
        except Exception as e:
            logger.error(f"Error sorting/filtering documents: {e}")
            raise ValueError(str(e))

    def _split_docs_to_window(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Splitting documents")
        try:
            split_docs = self.text_splitter.split_documents(state["sorted_filtered_docs"])
            logger.info(f"Splitted documents into smaller chunks: {len(split_docs)}")
            return {"splitted_docs": split_docs}
        except Exception as e:
            logger.error(f"Error splitting documents: {e}")
            raise ValueError(f"Failed to split documents: {str(e)}")

    def _create_initial_draft(  # type: ignore[no-untyped-def]
        self, state: AgentState, llm: Any, documents_context_window: int, use_system_message: bool
    ):
        logger.info("Creating initial draft")
        try:
            documents = state["splitted_docs"]
            if len(documents) == 0:
                raise ValueError("Empty documents list. Check you filtering configuration.")
            first_batch = self.doc_processor.get_docs_batch(documents, documents_context_window)
            logger.info(f"Processing first batch of documents: {len(first_batch)} of {len(documents)}")

            agent_msg = (
                SystemMessage(content=self.agent_prompt)
                if use_system_message
                else HumanMessage(content=self.agent_prompt)
            )

            human_prompt = self._create_human_prompt(
                documents=documents,
                batch=first_batch,
                processed_count=0,
                message_type="create",
                current_description="",
                draft_update_prompt=self.draft_update_prompt,
            )
            messages = [agent_msg, HumanMessage(content=human_prompt)]

            response = llm.invoke(messages)
            return {"sec_repo_doc": response.content, "processed_docs_count": len(first_batch)}
        except Exception as e:
            logger.error(f"Error creating initial draft: {e}")
            raise ValueError(str(e))

    def _update_draft_with_new_docs(  # type: ignore[no-untyped-def]
        self, state: AgentState, llm: Any, documents_context_window: int, use_system_message: bool
    ):
        logger.info("Updating draft with new documents")
        try:
            documents = state["splitted_docs"]
            current_description = state.get("sec_repo_doc", "")
            processed_count = state.get("processed_docs_count", 0)

            remaining_docs = documents[processed_count:]
            if not remaining_docs:
                return {"sec_repo_doc": current_description}

            next_batch = self.doc_processor.get_docs_batch(remaining_docs, documents_context_window)
            if not next_batch:
                raise ValueError("Documents are not fitting into context window")

            logger.info(
                f"Processing next batch of documents: {len(next_batch)} [{processed_count+len(next_batch)} of {len(documents)}]"
            )

            messages = self._create_update_messages(
                processed_count, current_description, documents, next_batch, use_system_message
            )

            response = llm.invoke(messages)
            return {
                "sec_repo_doc": response.content,
                "processed_docs_count": processed_count + len(next_batch),
            }
        except Exception as e:
            logger.error(f"Error updating draft: {e}")
            raise ValueError(str(e))

    def _update_draft_condition(self, state: AgentState) -> Literal["update_draft_with_new_docs", "markdown_validator"]:
        documents = state["splitted_docs"]
        processed_docs_count = state["processed_docs_count"]

        if processed_docs_count == len(documents):
            return GraphNodeType.MARKDOWN_VALIDATOR.value
        else:
            return GraphNodeType.UPDATE_DRAFT.value

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
        return {
            "sec_repo_doc": response.content,
            "sec_repo_doc_validation_error": "",
            "editor_turns_count": state.get("editor_turns_count", 0) + 1,
        }

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{CreateProjectSecurityDesignAgent.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()
        editor_llm = self.llm_provider.create_editor_llm()

        def load_files(state: AgentState):  # type: ignore[no-untyped-def]
            return self._load_files(state)

        def sort_filter_docs(state: AgentState):  # type: ignore[no-untyped-def]
            return self._sort_filter_docs(state)

        def split_docs_to_window(state: AgentState):  # type: ignore[no-untyped-def]
            return self._split_docs_to_window(state)

        def create_initial_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._create_initial_draft(
                state, llm.llm, llm.model_config.documents_context_window, llm.model_config.use_system_message
            )

        def update_draft_with_new_docs(state: AgentState):  # type: ignore[no-untyped-def]
            return self._update_draft_with_new_docs(
                state, llm.llm, llm.model_config.documents_context_window, llm.model_config.use_system_message
            )

        def update_draft_condition(
            state: AgentState,
        ) -> Literal["update_draft_with_new_docs", "markdown_validator"]:
            return self._update_draft_condition(state)

        def markdown_validator(state: AgentState):  # type: ignore[no-untyped-def]
            return self._markdown_validator(state)

        def markdown_error_condition(state: AgentState) -> Literal["editor", "__end__"]:
            return self._markdown_error_condition(state)

        def editor(state: AgentState):  # type: ignore[no-untyped-def]
            return self._editor(state, editor_llm.llm, editor_llm.model_config.use_system_message)

        builder = StateGraph(AgentState)
        builder.add_node("load_files", load_files)
        builder.add_node("sort_filter_docs", sort_filter_docs)
        builder.add_node("split_docs_to_window", split_docs_to_window)
        builder.add_node("create_initial_draft", create_initial_draft)
        builder.add_node(GraphNodeType.UPDATE_DRAFT.value, update_draft_with_new_docs)
        builder.add_node(GraphNodeType.MARKDOWN_VALIDATOR.value, markdown_validator)
        builder.add_node(GraphNodeType.EDITOR.value, editor)
        builder.add_edge(START, "load_files")
        builder.add_edge("load_files", "sort_filter_docs")
        builder.add_edge("sort_filter_docs", "split_docs_to_window")
        builder.add_edge("split_docs_to_window", "create_initial_draft")
        builder.add_conditional_edges("create_initial_draft", update_draft_condition)
        builder.add_conditional_edges(GraphNodeType.UPDATE_DRAFT.value, update_draft_condition)
        builder.add_conditional_edges(GraphNodeType.MARKDOWN_VALIDATOR.value, markdown_error_condition)
        builder.add_edge(GraphNodeType.EDITOR.value, GraphNodeType.MARKDOWN_VALIDATOR.value)
        graph = builder.compile()

        return graph

    def _create_update_messages(
        self,
        processed_count: int,
        current_description: str,
        documents: List[Document],
        batch: List[Document],
        use_system_message: bool,
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for updating the draft"""
        agent_msg = (
            SystemMessage(content=self.agent_prompt) if use_system_message else HumanMessage(content=self.agent_prompt)
        )

        human_prompt = self._create_human_prompt(
            documents, batch, processed_count, "update", current_description, self.draft_update_prompt
        )

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        documents: List[Document],
        batch: List[Document],
        processed_count: int,
        message_type: MESSAGE_TYPE,
        current_description: str,
        draft_update_prompt: str,
    ) -> str:
        """Create human prompt for document processing"""
        remaining_after_batch = len(documents) - (processed_count + len(batch))
        more_files = remaining_after_batch > 0

        formatted_docs = self.doc_processor.format_docs_for_prompt(batch)

        return (
            f"Based on the following PROJECT FILES, {message_type} the {draft_update_prompt}.\n"
            f"{'There will be more files to analyze after this batch.' if more_files else ''}\n\n"
            f"CURRENT {draft_update_prompt}:\n"
            + (f"{current_description}\n\n" if current_description else "")  # noqa: W503
            + f"PROJECT FILES:\n{formatted_docs}"  # noqa: W503
        )

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
