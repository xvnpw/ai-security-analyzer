from dataclasses import dataclass
from enum import Enum
import logging
from typing import List, Literal, Optional, Set, Union
from typing_extensions import TypedDict

from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.loaders import RepoDirectoryLoader
from ai_security_analyzer.utils import get_response_content, get_total_tokens, clean_markdown
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.components import DocumentProcessingMixin


logger = logging.getLogger(__name__)


class GraphNodeType(Enum):

    UPDATE_DRAFT = "update_draft_with_new_docs"
    FINAL_RESPONSE = "final_response"


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
    document_tokens: int


class FullDirScanAgent(BaseAgent, DocumentProcessingMixin):
    def __init__(
        self,
        llm: LLM,
        text_splitter: CharacterTextSplitter,
        tokenizer: Encoding,
        doc_processor: DocumentProcessor,
        doc_filter: DocumentFilter,
        agent_prompts: List[str],
        doc_type_prompt: str,
        checkpoint_manager: CheckpointManager,
    ):
        BaseAgent.__init__(self, llm, checkpoint_manager)
        DocumentProcessingMixin.__init__(self, text_splitter, tokenizer, doc_processor, doc_filter)
        self.agent_prompt = agent_prompts[0]
        self.doc_type_prompt = doc_type_prompt

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

    def _create_initial_draft(self, state: AgentState, llm: LLM):  # type: ignore[no-untyped-def]
        logger.info("Creating initial draft")

        try:
            documents_context_window = llm.model_config.documents_context_window

            documents = state["splitted_docs"]
            if len(documents) == 0:
                raise ValueError("Empty documents list. Check you filtering configuration.")

            first_batch = self.doc_processor.get_docs_batch(documents, documents_context_window)
            logger.info(f"Processing first batch of documents: {len(first_batch)} of {len(documents)}")

            agent_msg = SystemMessage(content=self.agent_prompt)

            human_prompt = self._create_human_prompt(
                documents=documents,
                batch=first_batch,
                processed_count=0,
                message_type="create",
                current_description="",
                doc_type_prompt=self.doc_type_prompt,
            )
            messages = [agent_msg, HumanMessage(content=human_prompt)]

            response = llm.invoke(messages)
            document_tokens = get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "processed_docs_count": len(first_batch),
                "document_tokens": document_tokens,
            }
        except Exception as e:
            logger.error(f"Error creating initial draft: {e}")
            raise ValueError(str(e))

    def _update_draft_with_new_docs(self, state: AgentState, llm: LLM):  # type: ignore[no-untyped-def]
        logger.info("Updating draft with new documents")
        try:
            documents_context_window = llm.model_config.documents_context_window

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

            messages = self._create_update_messages(processed_count, current_description, documents, next_batch)

            response = llm.invoke(messages)
            document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "processed_docs_count": processed_count + len(next_batch),
                "document_tokens": document_tokens,
            }
        except Exception as e:
            logger.error(f"Error updating draft: {e}")
            raise ValueError(str(e))

    def _update_draft_condition(self, state: AgentState) -> Literal["update_draft_with_new_docs", "final_response"]:
        documents = state["splitted_docs"]
        processed_docs_count = state["processed_docs_count"]

        if processed_docs_count == len(documents):
            return GraphNodeType.FINAL_RESPONSE.value
        else:
            return GraphNodeType.UPDATE_DRAFT.value

    def _final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Generating final response")
        sec_repo_doc = state["sec_repo_doc"]

        sec_repo_doc = clean_markdown(sec_repo_doc)

        return {"sec_repo_doc": sec_repo_doc}

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{FullDirScanAgent.__name__}] building graph...")

        def load_files(state: AgentState):  # type: ignore[no-untyped-def]
            return self._load_files(state)

        def sort_filter_docs(state: AgentState):  # type: ignore[no-untyped-def]
            return self._sort_filter_docs(state)

        def split_docs_to_window(state: AgentState):  # type: ignore[no-untyped-def]
            return self._split_docs_to_window(state)

        def create_initial_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._create_initial_draft(state, self.llm)

        def update_draft_with_new_docs(state: AgentState):  # type: ignore[no-untyped-def]
            return self._update_draft_with_new_docs(state, self.llm)

        def update_draft_condition(state: AgentState) -> Literal["update_draft_with_new_docs", "final_response"]:
            return self._update_draft_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        builder = StateGraph(AgentState)
        builder.add_node("load_files", load_files)
        builder.add_node("sort_filter_docs", sort_filter_docs)
        builder.add_node("split_docs_to_window", split_docs_to_window)
        builder.add_node("create_initial_draft", create_initial_draft)
        builder.add_node(GraphNodeType.UPDATE_DRAFT.value, update_draft_with_new_docs)
        builder.add_node(GraphNodeType.FINAL_RESPONSE.value, final_response)
        builder.add_edge(START, "load_files")
        builder.add_edge("load_files", "sort_filter_docs")
        builder.add_edge("sort_filter_docs", "split_docs_to_window")
        builder.add_edge("split_docs_to_window", "create_initial_draft")
        builder.add_conditional_edges("create_initial_draft", update_draft_condition)
        builder.add_conditional_edges(GraphNodeType.UPDATE_DRAFT.value, update_draft_condition)
        builder.add_edge(GraphNodeType.FINAL_RESPONSE.value, END)
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph

    def _create_update_messages(
        self,
        processed_count: int,
        current_description: str,
        documents: List[Document],
        batch: List[Document],
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for updating the draft"""
        agent_msg = SystemMessage(content=self.agent_prompt)

        human_prompt = self._create_human_prompt(
            documents, batch, processed_count, "update", current_description, self.doc_type_prompt
        )

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        documents: List[Document],
        batch: List[Document],
        processed_count: int,
        message_type: MESSAGE_TYPE,
        current_description: str,
        doc_type_prompt: str,
    ) -> str:
        """Create human prompt for document processing"""
        remaining_after_batch = len(documents) - (processed_count + len(batch))
        more_files = remaining_after_batch > 0

        formatted_docs = self.doc_processor.format_docs_for_prompt(batch)

        return (
            f"Based on the following PROJECT FILES, {message_type} the {doc_type_prompt}.\n"
            f"{'There will be more files to analyze after this batch.' if more_files else ''}\n\n"
            f"CURRENT {doc_type_prompt}:\n"
            + (f"{current_description}\n\n" if current_description else "")  # noqa: W503
            + f"PROJECT FILES:\n{formatted_docs}"  # noqa: W503
        )
