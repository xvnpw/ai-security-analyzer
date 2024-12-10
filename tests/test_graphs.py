from unittest.mock import Mock
from ai_security_analyzer.graphs import RunGraphExecutor, DryRunGraphExecutor, GraphExecutorFactory
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

    executor = RunGraphExecutor(config)

    graph = Mock(spec=CompiledStateGraph)
    # Mocking graph.invoke to return a state dict
    state = {"sec_repo_doc": "Test Content"}
    graph.invoke.return_value = state

    target_dir = "/path/to/target_dir"

    # Act
    executor.execute(graph, target_dir)

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
    executor = DryRunGraphExecutor(config)

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

    target_dir = "/path/to/target_dir"

    # Act
    executor.execute(graph, target_dir)

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


def test_graph_executor_factory_run_executor():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = False
    # Act
    executor = GraphExecutorFactory.create(config)
    # Assert
    assert isinstance(executor, RunGraphExecutor)


def test_graph_executor_factory_dry_run_executor():
    # Arrange
    config = Mock(spec=AppConfig)
    config.dry_run = True
    # Act
    executor = GraphExecutorFactory.create(config)
    # Assert
    assert isinstance(executor, DryRunGraphExecutor)
