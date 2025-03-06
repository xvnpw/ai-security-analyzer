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
from ai_security_analyzer.llms import LLM
from ai_security_analyzer.utils import get_response_content, get_total_tokens, clean_markdown
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.components import DocumentProcessingMixin, VulnerabilitiesWorkflowMixin
import operator
from ai_security_analyzer.loaders import RepoDirectoryLoader

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
    total_document_tokens: int
    vulnerabilities_iterations: int
    current_iteration: int
    sec_repo_docs: Annotated[List[str], operator.add]
    sec_repo_doc_final: str
    use_secondary_agent: bool
    use_secondary_agent_for_vulnerabilities: bool
    vulnerabilities_github_repo_url: str
    readme: Document
    attack_vector_description: str


class VulnerabilitiesWorkflow2(BaseAgent, DocumentProcessingMixin, VulnerabilitiesWorkflowMixin):
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
        included_classes_of_vulnerabilities: str,
        excluded_classes_of_vulnerabilities: str,
        vulnerabilities_severity_threshold: str,
        vulnerabilities_threat_actor: str,
        secondary_llm: LLM,
    ):
        BaseAgent.__init__(self, llm, checkpoint_manager)
        DocumentProcessingMixin.__init__(self, text_splitter, tokenizer, doc_processor, doc_filter)
        VulnerabilitiesWorkflowMixin.__init__(
            self,
            included_classes_of_vulnerabilities,
            excluded_classes_of_vulnerabilities,
            vulnerabilities_severity_threshold,
            vulnerabilities_threat_actor,
        )
        self.agent_prompt = agent_prompts[0]
        self.doc_type_prompt = doc_type_prompt
        self.secondary_llm = secondary_llm

        self.full_dir_scan_agent = FullDirScanAgent(
            llm=self.llm,
            text_splitter=text_splitter,
            tokenizer=tokenizer,
            doc_processor=doc_processor,
            doc_filter=doc_filter,
            agent_prompts=[self.agent_prompt],
            doc_type_prompt=doc_type_prompt,
            checkpoint_manager=self.checkpoint_manager,
        )
        self.secondary_full_dir_scan_agent = FullDirScanAgent(
            llm=self.secondary_llm,
            text_splitter=text_splitter,
            tokenizer=tokenizer,
            doc_processor=doc_processor,
            doc_filter=doc_filter,
            agent_prompts=[self.agent_prompt],
            doc_type_prompt=doc_type_prompt,
            checkpoint_manager=self.checkpoint_manager,
        )

    def _format_prompt_for_vulnerabilities(self, agent_prompt: str, attack_vector_description: str) -> str:
        return agent_prompt.format(
            attack_vector_description=attack_vector_description,
        )

    def _load_readme(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Loading README.md")
        try:
            loader = RepoDirectoryLoader(
                state["target_dir"],
                state["project_type"],
            )
            readme = loader.load_readme()
            logger.info("Loaded README.md")
            return {"readme": readme}
        except Exception as e:
            logger.error(f"Error loading README.md: {e}")
            raise ValueError(f"Failed to load README.md: {str(e)}")

    def _init_state(self, state: AgentState):  # type: ignore[no-untyped-def]
        current_iteration = state.get("current_iteration", -1)

        return {
            "current_iteration": current_iteration + 1,
            "sec_repo_doc": "",
            "processed_docs_count": 0,
        }

    def _get_attack_vector_description(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Getting attack vector description")
        try:
            readme = state["readme"]
            github_repo_url = state["vulnerabilities_github_repo_url"]
            messages = self._create_attack_vector_description_prompt(readme, github_repo_url)

            response = self.llm.invoke(messages)
            attack_vector_description = get_response_content(response)
            attack_vector_description = clean_markdown(attack_vector_description)

            total_document_tokens = state.get("total_document_tokens", 0) + get_total_tokens(response)

            agent_prompt = self._format_prompt_for_vulnerabilities(self.agent_prompt, attack_vector_description)
            self.full_dir_scan_agent.agent_prompt = agent_prompt
            self.secondary_full_dir_scan_agent.agent_prompt = agent_prompt

            return {
                "attack_vector_description": attack_vector_description,
                "total_document_tokens": total_document_tokens,
            }
        except Exception as e:
            logger.error(f"Error getting attack vector description: {e}")
            raise ValueError(str(e))

    def _use_secondary_condition(
        self, state: AgentState
    ) -> Literal["full_dir_scan_agent", "secondary_full_dir_scan_agent"]:
        return "secondary_full_dir_scan_agent" if state.get("use_secondary_agent", False) else "full_dir_scan_agent"

    def _filter_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Filtering vulnerabilities")
        try:
            sec_repo_doc = state["sec_repo_doc"]
            attack_vector_description = state["attack_vector_description"]
            messages = self._create_filter_prompt(sec_repo_doc, attack_vector_description)

            response = self.llm.invoke(messages)
            sec_repo_doc = get_response_content(response)
            sec_repo_doc = clean_markdown(sec_repo_doc)

            total_document_tokens = state.get("document_tokens", 0) + get_total_tokens(response)
            use_secondary_agent = not state["use_secondary_agent"]

            return {
                "sec_repo_doc": sec_repo_doc,
                "total_document_tokens": total_document_tokens + state.get("total_document_tokens", 0),
                "use_secondary_agent": use_secondary_agent,
            }
        except Exception as e:
            logger.error(f"Error filtering vulnerabilities: {e}")
            raise ValueError(str(e))

    def _read_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        return {
            "sec_repo_docs": [state["sec_repo_doc"]],
        }

    def _iterate_condition(self, state: AgentState) -> Literal["init_state", "final_response"]:
        current_iteration = state["current_iteration"]
        vulnerabilities_iterations = state["vulnerabilities_iterations"]

        return (
            "init_state" if current_iteration < vulnerabilities_iterations - 1 else GraphNodeType.FINAL_RESPONSE.value
        )

    def _final_response(self, state: AgentState):  # type: ignore[no-untyped-def]
        logger.info("Consolidating vulnerabilities")
        try:
            sec_repo_docs = state["sec_repo_docs"]

            if len(sec_repo_docs) <= 1:
                return {
                    "sec_repo_doc_final": sec_repo_docs[0],
                }

            messages = self._create_consolidated_prompt(sec_repo_docs)

            response = self.llm.invoke(messages)
            final_response = get_response_content(response)
            final_response = clean_markdown(final_response)

            total_document_tokens = state.get("total_document_tokens", 0) + get_total_tokens(response)
            return {
                "sec_repo_doc_final": final_response,
                "total_document_tokens": total_document_tokens,
            }
        except Exception as e:
            logger.error(f"Error consolidating vulnerabilities: {e}")
            raise ValueError(str(e))

    def build_graph(self) -> CompiledStateGraph:
        logger.debug(f"[{VulnerabilitiesWorkflow2.__name__}] building graph...")

        def load_readme(state: AgentState):  # type: ignore[no-untyped-def]
            return self._load_readme(state)

        def init_state(state: AgentState):  # type: ignore[no-untyped-def]
            return self._init_state(state)

        def get_attack_vector_description(state: AgentState):  # type: ignore[no-untyped-def]
            return self._get_attack_vector_description(state)

        def use_secondary_condition(
            state: AgentState,
        ) -> Literal["full_dir_scan_agent", "secondary_full_dir_scan_agent"]:
            return self._use_secondary_condition(state)

        def filter_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._filter_response(state)

        def read_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._read_response(state)

        def iterate_condition(state: AgentState) -> Literal["init_state", "final_response"]:
            return self._iterate_condition(state)

        def final_response(state: AgentState):  # type: ignore[no-untyped-def]
            return self._final_response(state)

        builder = StateGraph(AgentState)
        builder.add_node("load_readme", load_readme)
        builder.add_node("init_state", init_state)
        builder.add_node("get_attack_vector_description", get_attack_vector_description)
        builder.add_node("filter_response", filter_response)
        builder.add_node("read_response", read_response)
        builder.add_node("full_dir_scan_agent", self.full_dir_scan_agent.build_graph())
        builder.add_node("secondary_full_dir_scan_agent", self.secondary_full_dir_scan_agent.build_graph())
        builder.add_node(GraphNodeType.FINAL_RESPONSE.value, final_response)
        builder.add_edge(START, "load_readme")
        builder.add_edge("load_readme", "init_state")
        builder.add_edge("init_state", "get_attack_vector_description")
        builder.add_conditional_edges("get_attack_vector_description", use_secondary_condition)
        builder.add_edge("full_dir_scan_agent", "filter_response")
        builder.add_edge("secondary_full_dir_scan_agent", "filter_response")
        builder.add_edge("filter_response", "read_response")
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
            content=f"""I will give you {len(sec_repo_docs)} lists of vulnerabilities. Please combine them into a single list, by removing duplicate vulnerabilities. Format the output as a markdown with main paragraph and subparagraphs for each vulnerability. If at least one vulnerability exists in lists keep existing descriptions of vulnerabilities: vulnerability name, description (describe in details step by step how someone can trigger vulnerability), impact (describe the impact of the vulnerability), vulnerability rank (low,medium,high or critical), currently implemented mitigations (describe if this vulnerability is mitigated in the project and where), missing mitigations (describe what mitigations are missing in the project), preconditions (describe any preconditions that are needed to trigger this vulnerability), source code analysis (go step by step through code and describe how vulnerability can be triggered; if needed use visualization; be detail and descriptive), security test case (describe step by step test for the vulnerability to prove it's valid; assume that threat actor will be external attacker with access to publicly available instance of application). If no vulnerabilities exist in lists return "No vulnerabilities found".

            Exclude vulnerabilities that:
            - are only missing documentation to mitigate.
            - are deny of service vulnerabilities.
            - are not realistic for attacker to exploit in real-world.
            - are not completely described, e.g. missing source code analysis or security test case.
            - are only theoretical, e.g. missing evidence of exploit in source code analysis.
            - are not high or critical severity.
            """
        )

        human_prompt = self._create_human_prompt(sec_repo_docs)

        return [agent_msg, HumanMessage(content=human_prompt)]

    def _create_human_prompt(
        self,
        sec_repo_docs: List[str],
    ) -> str:
        """Create human prompt for document processing"""
        separator = "\n\n" + "=" * 100 + "\n\n"
        return "Lists of vulnerabilities:\n" + separator.join(sec_repo_docs)

    def _create_attack_vector_description_prompt(
        self,
        readme: Document,
        github_repo_url: str,
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for attack vector description"""
        system_prompt = """You are cybersecurity expert. I will give you github repository link and README from this repository. Your task is to return what are most likely way attacker will try to hack someone using this repository.

Follow instruction:
- write 1 sentence about project in repository. Is it library, standalone application, samples, tutorial, driver. What is programming language used.
- write 1 most likely attack vector attacker would try to use to hack someone using this repository. It might be web attack using specific vulnerability.
- exclude deny of service attacks, compromising repository, 3rd party dependencies vulnerabilities or compromises.
- it should be real-world risk to the project in question, as opposed to any fantastical concerns.
"""

        system_message = SystemMessage(content=system_prompt)
        human_message = HumanMessage(
            content=f"GITHUB REPOSITORY: {github_repo_url}\n\nREADME:\n{readme.page_content}\n"
        )

        return [system_message, human_message]

    def _create_filter_prompt(
        self,
        sec_repo_doc: str,
        attack_vector_description: str,
    ) -> List[Union[SystemMessage, HumanMessage]]:
        """Create messages for filtering the sec_repo_doc"""
        prompt = """I will give you list of vulnerabilities. Please update the list according to instructions:

Include only valid vulnerabilities that are part of attack vector:
{attack_vector_description}

Exclude vulnerabilities that:
- are only missing documentation to mitigate.
- are deny of service vulnerabilities.
- are not realistic for attacker to exploit in real-world.
- are not completely described, e.g. missing source code analysis or security test case.
- are only theoretical, e.g. missing evidence of exploit in source code analysis.
- are not high or critical severity.

Return empty list if non input vulnerabilities are matching conditions. In case there are vulnerabilities matching conditions return list of vulnerabilities in markdown format. Keep existing descriptions of vulnerabilities: vulnerability name, description (describe in details step by step how someone can trigger vulnerability), impact (describe the impact of the vulnerability), vulnerability rank (low,medium,high or critical), currently implemented mitigations (describe if this vulnerability is mitigated in the project and where), missing mitigations (describe what mitigations are missing in the project), preconditions (describe any preconditions that are needed to trigger this vulnerability), source code analysis (go step by step through code and describe how vulnerability can be triggered; if needed use visualization; be detail and descriptive), security test case (describe step by step test for the vulnerability to prove it's valid; assume that threat actor will be external attacker with access to publicly available instance of application).
            """

        prompt = self._format_prompt_for_vulnerabilities(prompt, attack_vector_description)

        agent_msg = SystemMessage(content=prompt)

        return [agent_msg, HumanMessage(content=sec_repo_doc)]
