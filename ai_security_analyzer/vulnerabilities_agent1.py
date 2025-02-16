from dataclasses import dataclass
from enum import Enum
import logging
from typing import List, Literal, Optional, Set, Union, Annotated
from typing_extensions import TypedDict

from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding

from ai_security_analyzer.full_dir_scan_agents import FullDirScanAgent
from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider, LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.components import DocumentProcessingMixin
import operator

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
    vulnerabilities_iterations: int
    current_iteration: int
    sec_repo_docs: Annotated[List[str], operator.add]
    sec_repo_doc_final: str


class VulnerabilitiesAgent1(BaseAgent, DocumentProcessingMixin):
    def __init__(
        self,
        llm_provider: LLMProvider,
        text_splitter: CharacterTextSplitter,
        tokenizer: Encoding,
        doc_processor: DocumentProcessor,
        doc_filter: DocumentFilter,
        agent_prompt: List[str],
        doc_type_prompt: str,
        checkpoint_manager: CheckpointManager,
    ):
        BaseAgent.__init__(self, llm_provider, checkpoint_manager)
        DocumentProcessingMixin.__init__(self, text_splitter, tokenizer, doc_processor, doc_filter)
        self.agent_prompt = agent_prompt[0]
        self.doc_type_prompt = doc_type_prompt

        self.full_dir_scan_agent = FullDirScanAgent(
            llm_provider=self.llm_provider,
            text_splitter=text_splitter,
            tokenizer=tokenizer,
            doc_processor=doc_processor,
            doc_filter=doc_filter,
            agent_prompt=agent_prompt,
            doc_type_prompt=doc_type_prompt,
            checkpoint_manager=self.checkpoint_manager,
        )

    def _init_state(self, state: AgentState) -> AgentState:
        current_iteration = state.get("current_iteration", -1)
        return {
            "current_iteration": current_iteration + 1,
            "sec_repo_doc": "",
            "processed_docs_count": 0,
        }

    def _read_response(self, state: AgentState) -> AgentState:
        return {
            "sec_repo_docs": [state["sec_repo_doc"]],
        }

    def _iterate_condition(self, state: AgentState) -> Literal["init_state", "final_response"]:
        current_iteration = state["current_iteration"]
        vulnerabilities_iterations = state["vulnerabilities_iterations"]

        return (
            "init_state" if current_iteration < vulnerabilities_iterations - 1 else GraphNodeType.FINAL_RESPONSE.value
        )

    def _final_response(self, state: AgentState, llm: LLM):
        logger.info("Consolidating vulnerabilities")
        try:
            sec_repo_docs = state["sec_repo_docs"]

            if len(sec_repo_docs) <= 1:
                return {
                    "sec_repo_doc_final": sec_repo_docs[0],
                }

            messages = self._create_consolidated_prompt(sec_repo_docs)

            response = llm.invoke(messages)
            document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
            return {
                "sec_repo_doc_final": get_response_content(response),
                "document_tokens": document_tokens,
            }
        except Exception as e:
            logger.error(f"Error consolidating vulnerabilities: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{VulnerabilitiesAgent1.__name__}] building graph...")

        llm = self.llm_provider.create_agent_llm()

        def init_state(state: AgentState) -> AgentState:
            return self._init_state(state)

        def read_response(state: AgentState) -> AgentState:
            return self._read_response(state)

        def iterate_condition(state: AgentState) -> Literal["init_state", "final_response"]:
            return self._iterate_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state, llm)

        builder = StateGraph(AgentState)
        builder.add_node("init_state", init_state)
        builder.add_node("read_response", read_response)
        builder.add_node("full_dir_scan_agent", self.full_dir_scan_agent.build_graph())
        builder.add_node(GraphNodeType.FINAL_RESPONSE.value, final_response)
        builder.add_edge(START, "init_state")
        builder.add_edge("init_state", "full_dir_scan_agent")
        builder.add_edge("full_dir_scan_agent", "read_response")
        builder.add_conditional_edges("read_response", iterate_condition)
        builder.add_edge(GraphNodeType.FINAL_RESPONSE.value, END)
        graph = builder.compile(checkpointer=self.checkpoint_manager.get_checkpointer())

        return graph

    def _create_consolidated_prompt(
        self,
        sec_repo_docs: List[str],
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for updating the draft"""
        agent_msg = SystemMessage(
            content=f"I will give you {len(sec_repo_docs)} lists of vulnerabilities. Please consolidate them into a single list."
        )

        human_prompt = self._create_human_prompt(sec_repo_docs)

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        sec_repo_docs: List[str],
    ) -> str:
        """Create human prompt for document processing"""
        separator = "\n" + "-" * 50 + "\n"
        return "Here are the vulnerabilities:\n" + separator.join(sec_repo_docs)
