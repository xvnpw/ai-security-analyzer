import pytest
from unittest.mock import MagicMock
import io

from ai_security_analyzer.agent_builder import AgentBuilder
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.dry_run import DryRunFullDirScanAgent
from ai_security_analyzer.file_agents import FileAgent
from ai_security_analyzer.full_dir_scan_agents import FullDirScanAgent
from ai_security_analyzer.github2_agents import GithubAgent2
from ai_security_analyzer.github2as_agents import GithubAgent2As
from ai_security_analyzer.github2at_agents import GithubAgent2At
from ai_security_analyzer.github2sd_agents import GithubAgent2Sd
from ai_security_analyzer.github2tm_agents import GithubAgent2Tm
from ai_security_analyzer.github2ms_agents import GithubAgent2Ms


@pytest.fixture
def mock_components():
    mock_llm_provider = MagicMock()
    mock_checkpoint_manager = MagicMock()
    mock_prompt_manager = MagicMock()

    # Mock LLMProvider.create_agent_llm to return a mock with model_config
    mock_agent_llm = MagicMock()
    mock_agent_llm.model_config = MagicMock(
        documents_chunk_size=1000, documents_chunk_overlap=50, tokenizer_model_name="gpt2"
    )
    mock_llm_provider.create_agent_llm.return_value = mock_agent_llm

    # Mock PromptManager to return dummy prompts
    mock_prompt_manager.get_prompt.return_value = "agent_prompt"
    mock_prompt_manager.get_doc_type_prompt.return_value = "doc_type_prompt"
    mock_prompt_manager.get_deep_analysis_prompt.return_value = "deep_analysis_prompt"
    mock_prompt_manager.get_format_prompt.return_value = "format_prompt"

    return mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager


def _create_config(mode="dir", deep_analysis=False, agent_prompt_type="sec-design", dry_run=False):
    output_file_mock = MagicMock(spec=io.TextIOWrapper)
    config_dict = {
        "mode": mode,
        "target": "test_target",
        "output_file": output_file_mock,
        "project_type": "python",
        "verbose": False,
        "debug": False,
        "agent_prompt_type": agent_prompt_type,
        "agent_provider": "fake",
        "agent_model": "test_model",
        "agent_temperature": 0.0,
        "agent_preamble_enabled": False,
        "agent_preamble": "",
        "deep_analysis": deep_analysis,
        "recursion_limit": 30,
        "exclude": None,
        "exclude_mode": "add",
        "include": None,
        "include_mode": "add",
        "filter_keywords": None,
        "files_context_window": None,
        "files_chunk_size": None,
        "dry_run": dry_run,
        "refinement_count": 0,
        "resume": False,
        "clear_checkpoints": False,
        "checkpoint_dir": ".checkpoints",
        "reasoning_effort": None,
    }
    return AppConfig(**config_dict)


def test_build_dir_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="dir")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, FullDirScanAgent)


def test_build_dry_run_dir_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="dir", dry_run=True)
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, DryRunFullDirScanAgent)


def test_build_file_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="file")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, FileAgent)


def test_build_github_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2)


def test_build_github_deep_tm_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="threat-modeling")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2Tm)


def test_build_github_deep_as_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="attack-surface")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2As)


def test_build_github_deep_at_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="attack-tree")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2At)


def test_build_github_deep_sd_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="sec-design")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2Sd)


def test_build_github_deep_ms_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="mitigations")
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    agent = builder.build()
    assert isinstance(agent, GithubAgent2Ms)


def test_build_no_agent_prompt(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="dir")
    mock_prompt_manager.get_formatted_prompts.return_value = None  # Simulate no prompt found
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    with pytest.raises(ValueError) as context:
        builder.build()
    assert "No agent prompt for type" in str(context.value)


def test_build_no_doc_type_prompt_for_doc_processing_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="dir")
    mock_prompt_manager.get_doc_type_prompt.return_value = None  # Simulate no doc_type prompt
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    with pytest.raises(ValueError) as context:
        builder.build()
    assert "No update prompt for type" in str(context.value)


def test_build_no_deep_analysis_prompt_for_deep_analysis_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="threat-modeling")
    mock_prompt_manager.get_deep_analysis_prompt.return_value = None  # Simulate no deep analysis prompt
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    with pytest.raises(ValueError) as context:
        builder.build()
    assert "No deep analysis prompt for type" in str(context.value)


def test_build_no_format_prompt_for_deep_analysis_agent(mock_components):
    mock_llm_provider, mock_checkpoint_manager, mock_prompt_manager = mock_components
    config = _create_config(mode="github", deep_analysis=True, agent_prompt_type="threat-modeling")
    mock_prompt_manager.get_format_prompt.return_value = None  # Simulate no format prompt
    builder = AgentBuilder(mock_llm_provider, mock_checkpoint_manager, config, mock_prompt_manager)
    with pytest.raises(ValueError) as context:
        builder.build()
    assert "No format prompt for type" in str(context.value)
