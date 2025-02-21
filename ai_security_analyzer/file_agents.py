import logging
from dataclasses import dataclass
from enum import Enum
from typing import List, Literal, Union

from langchain_community.document_loaders.text import TextLoader
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding
from typing_extensions import TypedDict

from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.components import DocumentProcessingMixin
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import clean_markdown, get_response_content, get_total_tokens
from ai_security_analyzer.checkpointing import CheckpointManager


logger = logging.getLogger(__name__)


class GraphNodeType(Enum):
    REFINE_DRAFT = "refine_draft"
    FINAL_RESPONSE = "final_response"


MESSAGE_TYPE = Literal["create", "update"]


@dataclass
class AgentState(TypedDict):
    target_file: str
    sec_repo_doc: str
    document_tokens: int
    refinement_count: int
    current_refinement_count: int
    repo_doc: Document


class FileAgent(BaseAgent, DocumentProcessingMixin):
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

    def _load_file(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Loading file")
        try:
            loader = TextLoader(state["target_file"], encoding="utf-8")
            docs = loader.load()
            logger.info(f"Loaded {len(docs)} document")
            return {"repo_doc": docs[0]}
        except Exception as e:
            logger.error(f"Error loading file: {e}")
            raise ValueError(f"Failed to load file: {str(e)}")

    def _create_initial_draft(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Creating initial draft")
        try:
            agent_msg = SystemMessage(content=self.agent_prompt)

            human_prompt = self._create_human_prompt(
                document=state["repo_doc"],
                message_type="create",
                current_description="",
                doc_type_prompt=self.doc_type_prompt,
            )
            messages = [agent_msg, HumanMessage(content=human_prompt)]

            response = self.llm.invoke(messages)
            document_tokens = get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "document_tokens": document_tokens,
            }
        except Exception as e:
            logger.error(f"Error creating initial draft: {e}")
            raise ValueError(str(e))

    def _refine_draft(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Refining draft")
        try:
            current_description = state.get("sec_repo_doc", "")

            repo_doc = state["repo_doc"]

            messages = self._create_update_messages(current_description, repo_doc)

            response = self.llm.invoke(messages)
            document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
            return {
                "sec_repo_doc": get_response_content(response),
                "document_tokens": document_tokens,
                "current_refinement_count": state.get("current_refinement_count", 0) + 1,
            }
        except Exception as e:
            logger.error(f"Error updating draft: {e}")
            raise ValueError(str(e))

    def _refine_draft_condition(self, state: AgentState) -> Literal["refine_draft", "final_response"]:
        current_refinement_count = state.get("current_refinement_count", 0)
        refinement_count = state["refinement_count"]

        if current_refinement_count < refinement_count:
            logger.info(f"Refining draft. Iteration {current_refinement_count+1} of {refinement_count}")
            return GraphNodeType.REFINE_DRAFT.value
        else:
            return GraphNodeType.FINAL_RESPONSE.value

    def _final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Generating final response")
        sec_repo_doc = state["sec_repo_doc"]

        sec_repo_doc = clean_markdown(sec_repo_doc)

        return {"sec_repo_doc": sec_repo_doc}

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{FileAgent.__name__}] building graph...")

        def load_file(state: AgentState):  # type: ignore[no-untyped-def]
            return self._load_file(state)

        def create_initial_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._create_initial_draft(state)

        def refine_draft(state: AgentState):  # type: ignore[no-untyped-def]
            return self._refine_draft(state)

        def refine_draft_condition(state: AgentState) -> Literal["refine_draft", "final_response"]:
            return self._refine_draft_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        builder = StateGraph(AgentState)
        builder.add_node("load_file", load_file)
        builder.add_node("create_initial_draft", create_initial_draft)
        builder.add_node(GraphNodeType.REFINE_DRAFT.value, refine_draft)
        builder.add_node(GraphNodeType.FINAL_RESPONSE.value, final_response)
        builder.add_edge(START, "load_file")
        builder.add_edge("load_file", "create_initial_draft")
        builder.add_conditional_edges("create_initial_draft", refine_draft_condition)
        builder.add_conditional_edges(GraphNodeType.REFINE_DRAFT.value, refine_draft_condition)
        builder.add_edge(GraphNodeType.FINAL_RESPONSE.value, END)
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph

    def _create_update_messages(
        self,
        current_description: str,
        document: Document,
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for updating the draft"""
        agent_msg = SystemMessage(content=self.agent_prompt)

        human_prompt = self._create_human_prompt(document, "update", current_description, self.doc_type_prompt)

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        document: Document,
        message_type: MESSAGE_TYPE,
        current_description: str,
        doc_type_prompt: str,
    ) -> str:
        """Create human prompt for document processing"""
        formatted_docs = self.doc_processor.format_docs_for_prompt([document])

        return (
            f"Based on the following FILE, {message_type} the {doc_type_prompt}.\n"
            f"CURRENT {doc_type_prompt}:\n"
            + (f"{current_description}\n\n" if current_description else "")  # noqa: W503
            + f"FILE:\n{formatted_docs}"  # noqa: W503
        )
