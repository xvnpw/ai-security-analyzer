from dataclasses import dataclass
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, Mock

import pytest

from ai_security_analyzer.agent_builder import AgentBuilder
from ai_security_analyzer.agents import (
    CreateProjectSecurityDesignAgent,
    GraphNodeType,
)
from ai_security_analyzer.base_agent import BaseAgent
from ai_security_analyzer.documents import DocumentFilter, DocumentProcessor
from ai_security_analyzer.llms import LLM, LLMProvider, ModelConfig
from ai_security_analyzer.markdowns import MarkdownMermaidValidator
from langchain_core.documents import Document


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
    agent_prompt_type = "sec-design"


@pytest.fixture
def llm_provider():
    mock_llm_provider = Mock(spec=LLMProvider)
    mock_llm = Mock(spec=LLM)
    mock_model_config = Mock(spec=ModelConfig)
    mock_model_config.documents_chunk_size = 1000
    mock_model_config.documents_chunk_overlap = 0
    mock_model_config.tokenizer_model_name = "gpt2"
    mock_model_config.documents_context_window = 1000
    mock_model_config.use_system_message = True
    mock_llm.model_config = mock_model_config
    mock_llm.llm = Mock()
    mock_llm_provider.create_agent_llm.return_value = mock_llm
    mock_llm_provider.create_editor_llm.return_value = mock_llm
    return mock_llm_provider


@pytest.fixture
def doc_processor():
    return DocumentProcessor()


@pytest.fixture
def doc_filter():
    return DocumentFilter()


@pytest.fixture
def markdown_validator():
    validator = Mock(spec=MarkdownMermaidValidator)
    return validator


def test_agent_builder_with_valid_agent_type(llm_provider):
    builder = AgentBuilder(llm_provider, AppConfigTest())
    agent = builder.build()
    assert agent is not None
    assert isinstance(agent, BaseAgent)
    assert isinstance(agent, CreateProjectSecurityDesignAgent)


def test_load_files_with_invalid_directory(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    state = {
        "target_dir": "/non/existent/directory",
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    with pytest.raises(ValueError) as exc_info:
        agent._load_files(state)

    assert "Failed to load files" in str(exc_info.value)


def test_simple_agent_sort_filter_docs(llm_provider, doc_filter):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    agent.doc_filter = doc_filter
    assert isinstance(agent, CreateProjectSecurityDesignAgent)

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": str(target_dir),
        "project_type": "python",
        "include_mode": "add",
        "exclude_mode": "add",
        "exclude": None,
        "include": None,
    }

    new_state = agent._load_files(state)
    new_state["filter_keywords"] = None

    new_state2 = agent._sort_filter_docs(new_state)

    assert "sorted_filtered_docs" in new_state2
    assert len(new_state2["sorted_filtered_docs"]) > 0


def test_sort_filter_docs_with_no_docs(llm_provider, doc_filter):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    agent.doc_filter = doc_filter
    state = {"repo_docs": [], "filter_keywords": None}

    new_state = agent._sort_filter_docs(state)

    assert "sorted_filtered_docs" in new_state
    assert len(new_state["sorted_filtered_docs"]) == 0


def test_simple_agent_split_docs_to_window(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    assert isinstance(agent, CreateProjectSecurityDesignAgent)

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": str(target_dir),
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

    assert "splitted_docs" in new_state3
    assert len(new_state3["splitted_docs"]) >= len(new_state2["sorted_filtered_docs"])


def test_split_docs_with_empty_docs(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    state = {"sorted_filtered_docs": []}

    new_state = agent._split_docs_to_window(state)

    assert "splitted_docs" in new_state
    assert len(new_state["splitted_docs"]) == 0


def test_simple_agent_create_initial_draft(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    llm = llm_provider.create_agent_llm().llm

    target_dir = Path(__file__).resolve().parent / "testdata"
    state = {
        "target_dir": str(target_dir),
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

    mock_response = MagicMock()
    mock_response.content = "Initial Draft Content"
    llm.invoke.return_value = mock_response

    new_state4 = agent._create_initial_draft(new_state3, llm, 30000, True)

    assert "sec_repo_doc" in new_state4
    assert new_state4["sec_repo_doc"] == "Initial Draft Content"
    assert new_state4["processed_docs_count"] > 0
    llm.invoke.assert_called_once()


def test_create_initial_draft_with_empty_documents(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    llm = llm_provider.create_agent_llm().llm
    state = {"splitted_docs": []}

    with pytest.raises(ValueError):
        agent._create_initial_draft(state, llm, 1000, True)


def test_update_draft_with_new_docs(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    llm = llm_provider.create_agent_llm().llm

    mock_response = MagicMock()
    mock_response.content = "Updated Draft Content"
    llm.invoke.return_value = mock_response

    state = {
        "splitted_docs": [Document(page_content="page content")] * 10,
        "sec_repo_doc": "Current Draft Content",
        "processed_docs_count": 5,
    }

    new_state = agent._update_draft_with_new_docs(state, llm, 1000, True)

    assert new_state["sec_repo_doc"] == "Updated Draft Content"
    assert new_state["processed_docs_count"] > 5
    llm.invoke.assert_called_once()


def test_update_draft_condition_complete_docs():
    agent = CreateProjectSecurityDesignAgent(None, None, None, 3, None, None, None, None, None)
    state = {"splitted_docs": [1, 2, 3], "processed_docs_count": 3}
    result = agent._update_draft_condition(state)
    assert result == GraphNodeType.MARKDOWN_VALIDATOR.value


def test_update_draft_condition_more_docs():
    agent = CreateProjectSecurityDesignAgent(None, None, None, 3, None, None, None, None, None)
    state = {"splitted_docs": [1, 2, 3], "processed_docs_count": 2}
    result = agent._update_draft_condition(state)
    assert result == GraphNodeType.UPDATE_DRAFT.value


def test_markdown_validator_with_valid_markdown(markdown_validator):
    markdown_validator.validate_content.return_value = (True, None)

    agent = CreateProjectSecurityDesignAgent(
        llm_provider=None,
        text_splitter=None,
        tokenizer=None,
        max_editor_turns_count=3,
        markdown_validator=markdown_validator,
        doc_processor=None,
        doc_filter=None,
        agent_prompt=None,
        draft_update_prompt=None,
    )

    state = {"sec_repo_doc": "Valid Markdown Content"}

    agent._markdown_validator(state)

    assert "sec_repo_doc_validation_error" not in state


def test_markdown_validator_with_invalid_markdown(markdown_validator):
    markdown_validator.validate_content.return_value = (False, "Error message")

    agent = CreateProjectSecurityDesignAgent(
        llm_provider=None,
        text_splitter=None,
        tokenizer=None,
        max_editor_turns_count=3,
        markdown_validator=markdown_validator,
        doc_processor=None,
        doc_filter=None,
        agent_prompt=None,
        draft_update_prompt=None,
    )

    state = {"sec_repo_doc": "Invalid Markdown Content"}

    new_state = agent._markdown_validator(state)

    assert "sec_repo_doc_validation_error" in new_state
    assert new_state["sec_repo_doc_validation_error"] == "Error message"


def test_markdown_error_condition_with_error_and_max_turns():
    agent = CreateProjectSecurityDesignAgent(None, None, None, 3, None, None, None, None, None)
    state = {"sec_repo_doc_validation_error": "Error", "editor_turns_count": 3}
    result = agent._markdown_error_condition(state)
    assert result == "__end__"


def test_markdown_error_condition_with_error_and_less_than_max_turns():
    agent = CreateProjectSecurityDesignAgent(None, None, None, 3, None, None, None, None, None)
    state = {"sec_repo_doc_validation_error": "Error", "editor_turns_count": 2}
    result = agent._markdown_error_condition(state)
    assert result == GraphNodeType.EDITOR.value


def test_editor_fixing_markdown(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()
    llm = llm_provider.create_editor_llm().llm

    mock_response = MagicMock()
    mock_response.content = "Fixed Markdown Content"
    llm.invoke.return_value = mock_response

    state = {
        "sec_repo_doc": "Invalid Markdown Content",
        "sec_repo_doc_validation_error": "Error message",
        "editor_turns_count": 1,
    }

    new_state = agent._editor(state, llm, True)

    assert new_state["sec_repo_doc"] == "Fixed Markdown Content"
    assert new_state["sec_repo_doc_validation_error"] == ""
    assert new_state["editor_turns_count"] == 2
    llm.invoke.assert_called_once()


def test_build_graph(llm_provider):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()

    graph = agent.build_graph()
    assert graph


@pytest.mark.parametrize(
    "message_type, documents, batch,current_description,processed_count,update_draft_prompt,",
    [
        ("create", [Document("test1"), Document("test2")], [Document("test1")], "current desc", 0, "DESIGN DOCUMENT"),
        (
            "update",
            [Document("test1"), Document("test2"), Document("test3")],
            [Document("test1")],
            "current desc",
            1,
            "DESIGN DOCUMENT",
        ),
        (
            "create",
            [Document("test1"), Document("test2")],
            [Document("test1"), Document("test2")],
            None,
            0,
            "DESIGN DOCUMENT",
        ),
    ],
)
def test_create_human_prompt(
    llm_provider,
    message_type: str,
    documents: List[Document],
    batch: List[Document],
    current_description: str,
    processed_count: int,
    update_draft_prompt: str,
):
    agent = AgentBuilder(llm_provider, AppConfigTest()).build()

    ret = agent._create_human_prompt(
        documents, batch, processed_count, message_type, current_description, update_draft_prompt
    )

    ret_by_lines = ret.splitlines()

    assert ret_by_lines[0] == f"Based on the following PROJECT FILES, {message_type} the DESIGN DOCUMENT."
    assert ret_by_lines[1] == (
        "There will be more files to analyze after this batch." if len(documents) > len(batch) else ""
    )
    assert ret_by_lines[3] == "CURRENT DESIGN DOCUMENT:"

    lines = 0
    if current_description:
        assert ret_by_lines[4] == current_description
        lines = 2

    assert ret_by_lines[4 + lines] == "PROJECT FILES:"
