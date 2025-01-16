# test_agent_builder.py
import pytest
from unittest.mock import Mock
from io import TextIOWrapper

from ai_security_analyzer.agent_builder import AgentBuilder
from ai_security_analyzer.base_agent import AgentType
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.full_dir_scan_agents import FullDirScanAgent
from ai_security_analyzer.dry_run import DryRunFullDirScanAgent
from ai_security_analyzer.github2_agents import GithubAgent2
from ai_security_analyzer.checkpointing import CheckpointManager


@pytest.fixture
def mock_llm_provider():
    provider = Mock(spec=LLMProvider)
    provider.create_agent_llm.return_value = Mock(
        model_config=Mock(documents_chunk_size=1000, documents_chunk_overlap=200, tokenizer_model_name="gpt-4")
    )
    return provider


@pytest.fixture
def mock_output_file():
    return Mock(spec=TextIOWrapper)


@pytest.fixture
def base_config():
    return AppConfig(
        mode="dir",
        target="/some/path",
        output_file=Mock(spec=TextIOWrapper),
        project_type="python",
        agent_prompt_type="sec-design",
        node_path="/usr/local/bin/node",
    )


@pytest.fixture
def mock_checkpoint_manager():
    return Mock(spec=CheckpointManager)


def test_agent_builder_initialization(mock_llm_provider, mock_checkpoint_manager, base_config):
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    assert builder.llm_provider == mock_llm_provider
    assert builder.config == base_config
    assert builder._agent_type == AgentType.DIR


def test_build_dir_agent(mock_llm_provider, mock_checkpoint_manager, base_config):
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    agent = builder.build()
    assert isinstance(agent, FullDirScanAgent)


def test_build_dry_run_dir_agent(mock_llm_provider, mock_checkpoint_manager, base_config):
    base_config.dry_run = True
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    agent = builder.build()
    assert isinstance(agent, DryRunFullDirScanAgent)


def test_build_github_agent(mock_llm_provider, mock_checkpoint_manager, base_config):
    base_config.mode = "github"
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2)


def test_invalid_agent_type(mock_llm_provider, mock_checkpoint_manager, base_config):
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    # Manually set an invalid agent type
    builder._agent_type = Mock(spec=AgentType)
    builder._agent_type.value = "invalid-agent-type"

    with pytest.raises(ValueError, match="Unknown agent type"):
        builder.build()


def test_missing_agent_prompt(mock_llm_provider, mock_checkpoint_manager, base_config):
    base_config.agent_prompt_type = "invalid-prompt-type"  # type: ignore

    with pytest.raises(ValueError, match="No prompt template for prompt type: invalid-prompt-type"):
        builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
        builder.build()


@pytest.mark.parametrize(
    "mode,expected_type",
    [
        ("dir", AgentType.DIR),
        ("github", AgentType.GITHUB),
        ("file", AgentType.FILE),
    ],
)
def test_different_agent_modes(mock_llm_provider, mock_checkpoint_manager, base_config, mode, expected_type):
    base_config.mode = mode
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    assert builder._agent_type == expected_type


def test_deep_analysis_config(mock_llm_provider, mock_checkpoint_manager, base_config):
    base_config.mode = "github"
    base_config.deep_analysis = True
    base_config.agent_prompt_type = "threat-modeling"

    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, base_config)
    assert builder._agent_type == AgentType.GITHUB_DEEP_TM
