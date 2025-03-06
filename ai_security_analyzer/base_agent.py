import logging
from abc import ABC, abstractmethod
from enum import Enum

from langgraph.graph.state import CompiledStateGraph

from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.llms import LLM

logger = logging.getLogger(__name__)


class AgentType(Enum):
    DIR = "dir"
    DRY_RUN_DIR = "dry-run-dir"
    GITHUB = "github"
    GITHUB_DEEP_TM = "github-deep-tm"
    FILE = "file"
    GITHUB_DEEP_AS = "github-deep-as"
    GITHUB_DEEP_AT = "github-deep-at"
    GITHUB_DEEP_SD = "github-deep-sd"
    GITHUB_DEEP_MS = "github-deep-ms"
    VULNERABILITIES_WORKFLOW_1 = "vulnerabilities-workflow-1"
    VULNERABILITIES_WORKFLOW_2 = "vulnerabilities-workflow-2"

    @staticmethod
    def create(config: AppConfig) -> "AgentType":
        if config.dry_run:
            return AgentType(f"dry-run-{config.mode}")

        if config.deep_analysis and config.agent_prompt_type == "threat-modeling":
            return AgentType.GITHUB_DEEP_TM
        elif config.deep_analysis and config.agent_prompt_type == "attack-surface":
            return AgentType.GITHUB_DEEP_AS
        elif config.deep_analysis and config.agent_prompt_type == "attack-tree":
            return AgentType.GITHUB_DEEP_AT
        elif config.deep_analysis and config.agent_prompt_type == "sec-design":
            return AgentType.GITHUB_DEEP_SD
        elif config.deep_analysis and config.agent_prompt_type == "mitigations":
            return AgentType.GITHUB_DEEP_MS
        elif config.mode == "dir" and config.agent_prompt_type == "vulnerabilities-workflow-1":
            return AgentType.VULNERABILITIES_WORKFLOW_1
        elif config.mode == "dir" and config.agent_prompt_type == "vulnerabilities-workflow-2":
            return AgentType.VULNERABILITIES_WORKFLOW_2
        else:
            return AgentType(config.mode)


class BaseAgent(ABC):
    def __init__(self, llm: LLM, checkpoint_manager: CheckpointManager):
        self.llm = llm
        self.checkpoint_manager = checkpoint_manager

    @abstractmethod
    def build_graph(self) -> CompiledStateGraph:
        """Build and return the agent's graph"""
        pass
