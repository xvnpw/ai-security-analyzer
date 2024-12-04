from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from ai_create_project_sec_design.agent_builder import AgentBuilder
from ai_create_project_sec_design.agents import CreateProjectSecurityDesignAgent
from ai_create_project_sec_design.llms import LLM, LLMProvider, ModelConfig


@dataclass
class AppConfigTest:
    agent_provider: str = "openai"
    agent_model: str = "gpt-4o"
    agent_temperature: float = 0.7
    files_chunk_size: int = 1000
    files_context_window: int = 1000
    editor_provider: str = "anthropic"
    editor_model: str = "claude-v1"
    editor_temperature: float = 0.4
    editor_max_turns_count: int = 3
    dry_run: bool = False
    node_path = "/usr/bin/node"


@pytest.fixture
def llm_provider():
    mock_llm_provider = Mock(LLMProvider)
    mock_llm = Mock(LLM)
    mock_llm.model_config = Mock(ModelConfig)
    mock_llm.model_config.documents_chunk_size = 1000
    mock_llm.model_config.documents_chunk_overlap = 0
    mock_llm.model_config.tokenizer_model_name = "gpt2"
    mock_llm.llm = MagicMock()
    mock_llm_provider.create_agent_llm.return_value = mock_llm
    return mock_llm_provider


def test_agent_builder_with_valid_agent_type(llm_provider):
    builder = AgentBuilder(llm_provider, AppConfigTest())
    agent = builder.build()
    assert agent is not None


def test_simple_agent_load_files(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    assert isinstance(agent, CreateProjectSecurityDesignAgent)

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": target_dir,
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    new_state = agent._load_files(state)

    assert len(new_state["repo_docs"]) > 0


def test_simple_agent_sort_filter_docs(llm_provider):
    # given
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    assert isinstance(agent, CreateProjectSecurityDesignAgent)

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": target_dir,
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    new_state = agent._load_files(state)

    new_state["filter_keywords"] = None

    # when
    new_state2 = agent._sort_filter_docs(new_state)

    # then
    assert len(new_state2["sorted_filtered_docs"]) > 0


def test_simple_agent_split_docs_to_window(llm_provider):
    # given
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    assert isinstance(agent, CreateProjectSecurityDesignAgent)

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": target_dir,
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    new_state = agent._load_files(state)
    new_state["filter_keywords"] = None
    new_state2 = agent._sort_filter_docs(new_state)

    # when
    new_state3 = agent._split_docs_to_window(new_state2)

    # then
    assert len(new_state3["splitted_docs"]) > len(new_state2["sorted_filtered_docs"])


def test_simple_agent_create_initial_draft(llm_provider):
    # given
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    assert isinstance(agent, CreateProjectSecurityDesignAgent)
    llm = llm_provider.create_agent_llm().llm

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": target_dir,
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    new_state = agent._load_files(state)
    new_state["filter_keywords"] = None
    new_state2 = agent._sort_filter_docs(new_state)
    new_state3 = agent._split_docs_to_window(new_state2)

    # when
    new_state4 = agent._create_initial_draft(new_state3, llm, 30000, True)

    # then
    assert new_state4["sec_repo_doc"]
    assert new_state4["processed_docs_count"] > 0
    llm.invoke.assert_called_once()
