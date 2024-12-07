import logging

from langchain_text_splitters import CharacterTextSplitter
from langgraph.graph import START, END, StateGraph
from langgraph.graph.state import CompiledStateGraph
from tiktoken import Encoding

from ai_security_analyzer.agents import (
    CreateProjectSecurityDesignAgent,
    AgentState,
)
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class DryRunAgent(CreateProjectSecurityDesignAgent):
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

    def _count_token(self, state: AgentState):  # type: ignore[no-untyped-def]
        documents = state["splitted_docs"]
        tokens = 0
        for doc in documents:
            doc_tokens = len(self.tokenizer.encode(doc.page_content))
            tokens = tokens + doc_tokens
        return {"document_tokens": tokens}

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{DryRunAgent.__name__}] building graph...")

        def load_files(state: AgentState):  # type: ignore[no-untyped-def]
            return self._load_files(state)

        def sort_filter_docs(state: AgentState):  # type: ignore[no-untyped-def]
            return self._sort_filter_docs(state)

        def split_docs_to_window(state: AgentState):  # type: ignore[no-untyped-def]
            return self._split_docs_to_window(state)

        def count_tokens(state: AgentState):  # type: ignore[no-untyped-def]
            return self._count_token(state)

        builder = StateGraph(AgentState)
        builder.add_node("load_files", load_files)
        builder.add_node("sort_filter_docs", sort_filter_docs)
        builder.add_node("split_docs_to_window", split_docs_to_window)
        builder.add_node("count_tokens", count_tokens)
        builder.add_edge(START, "load_files")
        builder.add_edge("load_files", "sort_filter_docs")
        builder.add_edge("sort_filter_docs", "split_docs_to_window")
        builder.add_edge("split_docs_to_window", "count_tokens")
        builder.add_edge("count_tokens", END)
        graph = builder.compile()

        return graph