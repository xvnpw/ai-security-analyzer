from ai_create_project_sec_design.markdowns import MarkdownMermaidValidator
from ai_create_project_sec_design.utils import find_node_binary

NODE_PATH = find_node_binary()
if not NODE_PATH:
    raise FileNotFoundError("Node.js binary not found. Please install Node.js.")


def test_markdown_validation_correct():
    # given
    validator = MarkdownMermaidValidator(NODE_PATH)
    content = """## DEPLOYMENT

```mermaid
graph TD
    Developer --> GitHubRepository[GitHub Repository]
    GitHubRepository --> GitHubActions[GitHub Actions Runner]
    GitHubActions --> DockerImage[Fabric Agent Action Docker Image]
    DockerImage --> LLMProvider
```
    """

    # when
    is_valid, error = validator.validate_content(content)

    # then
    assert error is None
    assert is_valid


def test_markdown_validation_incorrect():
    # given
    validator = MarkdownMermaidValidator(NODE_PATH)
    content = """## DEPLOYMENT

```mermaid
graph C4Context
    title[Fabric Agent Action Context Diagram]
    subgraph fabric_agent_action[Fabric Agent Action]
        fabric_agent[Fabric Agent]
    end
    user[GitHub User]
    github[GitHub]
    llm_provider[LLM Provider]

    user -->|Uses| github
    github -->|Triggers| fabric_agent_action
    fabric_agent_action -->|Requests| llm_provider
    fabric_agent_action -->|Posts results| github
```

bla bla


    """

    # when
    is_valid, error = validator.validate_content(content)

    # then
    assert error is not None
    assert not is_valid


def test_markdown_validation_incorrect2():
    # given
    validator = MarkdownMermaidValidator(NODE_PATH)
    content = "```mermaid graph C4Context title[Fabric Agent Action Context Diagram]```"

    # when
    is_valid, error = validator.validate_content(content)

    # then
    assert error is not None
    assert not is_valid
