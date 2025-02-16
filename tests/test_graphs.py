from unittest.mock import Mock, patch
from ai_security_analyzer.graphs import (
    FullDirScanGraphExecutor,
    DryRunFullDirScanGraphExecutor,
    GraphExecutorFactory,
    GithubGraphExecutor,
)
from ai_security_analyzer.config import AppConfig
from langgraph.graph.state import CompiledStateGraph
from langchain_core.documents import Document


def test_run_graph_executor_success():
    # Arrange
    config = Mock(spec=AppConfig)
    config.project_type = "test_project"
    config.exclude = []
    config.exclude_mode = "exclude_mode_test"
    config.include = []
    config.include_mode = "include_mode_test"
    config.filter_keywords = []
    config.agent_preamble_enabled = True
    config.agent_preamble = "Test Preamble"
    config.output_file = Mock()
    config.recursion_limit = 10
    config.mode = "dir"
    config.agent_prompt_type = "sec-design"

    executor = FullDirScanGraphExecutor(config)

    graph = Mock(spec=CompiledStateGraph)
    # Mocking graph.invoke to return a state dict with token count
    state = {"sec_repo_doc": "Test Content", "document_tokens": 1000}
    graph.invoke.return_value = state

    target = "/path/to/target_dir"

    # Act
    with patch("ai_security_analyzer.graphs.logger") as mock_logger:
        executor.execute(graph, target)

        # Assert logger was called with token count
        mock_logger.info.assert_called_with("Actual token usage: 1000")

    # Check that output_file.write was called with the correct content
    expected_output = f"{config.agent_preamble}\n\n{state['sec_repo_doc']}"
    config.output_file.write.assert_called_once_with(expected_output)


def test_dry_run_graph_executor_success(capfd):
    # Arrange
    config = Mock(spec=AppConfig)
    config.project_type = "test_project"
    config.exclude = []
    config.exclude_mode = "exclude_mode_test"
    config.include = []
    config.include_mode = "include_mode_test"
    config.filter_keywords = []
    config.deep_analysis = False
    config.recursion_limit = 10
    config.mode = "dir"
    config.agent_prompt_type = "sec-design"
    executor = DryRunFullDirScanGraphExecutor(config)

    graph = Mock(spec=CompiledStateGraph)
    # Mocking state returned by graph.invoke
    doc1 = Mock(spec=Document)
    doc1.metadata = {"source": "file1.py"}
    doc2 = Mock(spec=Document)
    doc2.metadata = {"source": "file2.py"}
    splitted_docs = [doc1, doc2]
    state = {
        "splitted_docs": splitted_docs,
        "document_tokens": 1234,
    }
    graph.invoke.return_value = state

    target = "/path/to/target_dir"

    # Act
    executor.execute(graph, target)

    # Capture the printed output
    out, err = capfd.readouterr()

    # Build expected output
    expected_output = """=========== dry-run ===========
All documents token count: 1234
List of chunked files to analyze:
file1.py
file2.py
"""
    # Remove whitespace differences
    assert out.strip() == expected_output.strip()


def test_graph_executor_factory_dir_executor():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = False
    config.mode = "dir"
    config.deep_analysis = False
    config.agent_prompt_type = "sec-design"
    # Act
    executor = GraphExecutorFactory.create(config)
    # Assert
    assert isinstance(executor, FullDirScanGraphExecutor)


def test_graph_executor_factory_github_executor():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = False
    config.mode = "github"
    config.deep_analysis = False
    # Act
    executor = GraphExecutorFactory.create(config)
    # Assert
    assert isinstance(executor, GithubGraphExecutor)


def test_graph_executor_factory_dry_run_executor():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = True
    config.mode = "dir"
    config.deep_analysis = False
    # Act
    executor = GraphExecutorFactory.create(config)
    # Assert
    assert isinstance(executor, DryRunFullDirScanGraphExecutor)


def test_graph_executor_factory_invalid_type():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = False
    config.mode = "invalid"
    config.deep_analysis = False
    # Act & Assert
    try:
        GraphExecutorFactory.create(config)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "invalid" in str(e)
