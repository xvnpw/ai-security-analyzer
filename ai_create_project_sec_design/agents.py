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

from ai_create_project_sec_design.base_agent import BaseAgent
from ai_create_project_sec_design.documents import DocumentFilter, DocumentProcessor
from ai_create_project_sec_design.llms import LLMProvider
from ai_create_project_sec_design.loaders import RepoDirectoryLoader
from ai_create_project_sec_design.markdowns import MarkdownMermaidValidator

logger = logging.getLogger(__name__)


class GraphNodeType(Enum):
    UPDATE_DRAFT = "update_draft_with_new_docs"
    MARKDOWN_VALIDATOR = "markdown_validator"
    EDITOR = "editor"


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
    ):
        super().__init__(
            llm_provider,
            text_splitter,
            tokenizer,
            max_editor_turns_count,
            markdown_validator,
            doc_processor,
            doc_filter,
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
                SystemMessage(content=self._get_agent_prompt())
                if use_system_message
                else HumanMessage(content=self._get_agent_prompt())
            )

            human_prompt = self._create_human_prompt(documents, first_batch)
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
            SystemMessage(content=self._get_agent_prompt())
            if use_system_message
            else HumanMessage(content=self._get_agent_prompt())
        )

        # Calculate remaining documents after this batch
        remaining_after_batch = len(documents) - (processed_count + len(batch))
        more_files = remaining_after_batch > 0

        formatted_docs = self.doc_processor.format_docs_for_prompt(batch)

        human_prompt = (
            f"Based on the following PROJECT FILES, update the DESIGN DOCUMENT.\n"
            f"{'There will be more files to analyze after this batch.' if more_files else ''}\n\n"
            f"CURRENT DESIGN DOCUMENT:\n{current_description}\n\n"
            f"PROJECT FILES:\n{formatted_docs}"
        )

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(self, documents: List[Document], batch: List[Document]) -> str:
        """Create human prompt for document processing"""
        remaining_after_batch = len(documents) - len(batch)
        more_files = remaining_after_batch > 0

        formatted_docs = self.doc_processor.format_docs_for_prompt(batch)

        return (
            f"Based on the following PROJECT FILES, create the DESIGN DOCUMENT.\n"
            f"{'There will be more files to analyze after this batch.' if more_files else ''}\n\n"
            f"CURRENT DESIGN DOCUMENT:\n\n"
            f"PROJECT FILES:\n{formatted_docs}"
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

    def _get_agent_prompt(self) -> str:
        return """# IDENTITY and PURPOSE

You are an expert in software, cloud and cybersecurity architecture. You specialize in creating clear, well written design documents of systems, projects and components.

# GOAL

Given a PROJECT FILES and CURRENT DESIGN DOCUMENT, provide a well written, detailed project design document that will be use later for threat modelling.

# STEPS

- Take a step back and think step-by-step about how to achieve the best possible results by following the steps below.

- Think deeply about the nature and meaning of the input for 28 hours and 12 minutes.

- Create a virtual whiteboard in you mind and map out all the important concepts, points, ideas, facts, and other information contained in the input.

- Appreciate the fact that each company is different. Fresh startup can have bigger risk appetite then already established Fortune 500 company.

- If CURRENT DESIGN DOCUMENT is not empty - it means that draft of this document was created in previous interactions with LLM using previous batch of PROJECT FILES. In such case update CURRENT DESIGN DESCRIPTION with new information that you get from current PROJECT FILES. In case CURRENT DESIGN DESCRIPTION is empty it means that you get first batch of PROJECT FILES

- PROJECT FILES will contain typical files that can be found in github repository. Those will be configuration, scripts, README, production code and testing code, etc.

- Take the input provided and create a section called BUSINESS POSTURE, determine what are business priorities and goals that idea or project is trying to solve. Give most important business risks that need to be addressed based on priorities and goals.

- Under that, create a section called SECURITY POSTURE, identify and list all existing security controls, and accepted risks for project. Focus on secure software development lifecycle and deployment model. Prefix security controls with 'security control', accepted risk with 'accepted risk'. Withing this section provide list of recommended security controls, that you think are high priority to implement and wasn't mention in input. Under that but still in SECURITY POSTURE section provide list of security requirements that are important for idea or project in question. Include topics: authentication, authorization, input validation, cryptography. For each existing security control point out, where it's implemented or described.

- Under that, create a section called DESIGN. Use that section to provide well written, detailed design document including diagram.

- In DESIGN section, create subsection called C4 CONTEXT and provide mermaid diagram that will represent a project context diagram showing project as a box in the centre, surrounded by its users and the other systems/projects that it interacts with.

- Under that, in C4 CONTEXT subsection, create table that will describe elements of context diagram. Include columns: 1. Name - name of element; 2. Type - type of element; 3. Description - description of element; 4. Responsibilities - responsibilities of element; 5. Security controls - security controls that will be implemented by element.

- Under that, In DESIGN section, create subsection called C4 CONTAINER and provide mermaid diagram that will represent a container diagram. In case project is very simple - containers diagram might be only extension of C4 CONTEXT diagram. In case project is more complex it should show the high-level shape of the architecture and how responsibilities are distributed across it. It also shows the major technology choices and how the containers communicate with one another.

- Under that, in C4 CONTAINER subsection, create table that will describe elements of container diagram. Include columns: 1. Name - name of element; 2. Type - type of element; 3. Description - description of element; 4. Responsibilities - responsibilities of element; 5. Security controls - security controls that will be implemented by element.

- Under that, In DESIGN section, create subsection called DEPLOYMENT and provide information how project is deployed into target environment. Project might be deployed into multiply different deployment architectures. First list all possible solutions and pick one to descried in details. Include mermaid diagram to visualize deployment. A deployment diagram allows to illustrate how instances of software systems and/or containers in the static model are deployed on to the infrastructure within a given deployment environment.

- Under that, in DEPLOYMENT subsection, create table that will describe elements of deployment diagram. Include columns: 1. Name - name of element; 2. Type - type of element; 3. Description - description of element; 4. Responsibilities - responsibilities of element; 5. Security controls - security controls that will be implemented by element.

- Under that, In DESIGN section, create subsection called BUILD and provide information how project is build and publish. Focus on security controls of build process, e.g. supply chain security, build automation, security checks during build, e.g. SAST scanners, linters, etc. Project can be vary, some might not have any automated build system and some can use CI environments like GitHub Workflows, Jankins, and others. Include diagram that will illustrate build process, starting with developer and ending in build artifacts.

- Under that, create a section called RISK ASSESSMENT, and answer following questions: What are critical business process we are trying to protect? What data we are trying to protect and what is their sensitivity?

- Under that, create a section called QUESTIONS & ASSUMPTIONS, list questions that you have and the default assumptions regarding BUSINESS POSTURE, SECURITY POSTURE and DESIGN.

# OUTPUT INSTRUCTIONS

- Output in the format above only using valid Markdown.

- Do not use bold or italic formatting in the Markdown (no asterisks).

- Do not complain about anything, just do what you're told.

# INPUT FORMATTING

- You will get PROJECT FILES - batch of projects files that fits into context window

- CURRENT DESIGN DOCUMENT - document that was created in previous interactions with LLM based on previous batches of project files

# INPUT:

        """
