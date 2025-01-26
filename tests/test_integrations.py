from ai_security_analyzer.app import app
from ai_security_analyzer.config import AppConfig
import pytest
import os


@pytest.mark.parametrize(
    "agent_prompt_type,agent_provider,agent_model,agent_temperature",
    [
        ("sec-design", "openai", "o1", 1),
        ("threat-modeling", "openai", "o1", 1),
        ("attack-surface", "openai", "o1", 1),
        ("attack-tree", "openai", "o1", 1),
        ("mitigations", "openai", "o1", 1),
        ("sec-design", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("threat-modeling", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-surface", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-tree", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("mitigations", "google", "gemini-2.0-flash-thinking-exp", 0),
    ],
)
@pytest.mark.integration
def test_app_github_mode(agent_prompt_type, agent_provider, agent_model, agent_temperature):
    output_path = f"tests-output/github-{agent_prompt_type}-flask-{agent_model}.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        config = AppConfig(
            mode="github",
            target="https://github.com/pallets/flask",
            output_file=output_file,
            agent_provider=agent_provider,
            agent_model=agent_model,
            agent_temperature=agent_temperature,
            agent_prompt_type=agent_prompt_type,
            verbose=True,
        )

        app(config)

    # Verify output file exists and is not empty
    assert os.path.exists(output_path), f"Output file {output_path} was not created"
    assert os.path.getsize(output_path) > 100, f"Output file {output_path} is empty"


@pytest.mark.parametrize(
    "agent_prompt_type,agent_provider,agent_model,agent_temperature",
    [
        ("sec-design", "openai", "o1", 1),
        ("threat-modeling", "openai", "o1", 1),
        ("attack-surface", "openai", "o1", 1),
        ("attack-tree", "openai", "o1", 1),
        ("mitigations", "openai", "o1", 1),
    ],
)
@pytest.mark.integration
def test_app_file_mode(agent_prompt_type, agent_provider, agent_model, agent_temperature):
    output_path = f"tests-output/file-{agent_prompt_type}-flask-{agent_model}.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        config = AppConfig(
            mode="file",
            target="tests/EXAMPLE_ARCHITECTURE.md",
            output_file=output_file,
            agent_provider=agent_provider,
            agent_model=agent_model,
            agent_temperature=agent_temperature,
            agent_prompt_type=agent_prompt_type,
            verbose=True,
        )

        app(config)

    # Verify output file exists and is not empty
    assert os.path.exists(output_path), f"Output file {output_path} was not created"
    assert os.path.getsize(output_path) > 100, f"Output file {output_path} is empty"


@pytest.mark.parametrize(
    "agent_prompt_type,agent_provider,agent_model,agent_temperature",
    [
        ("sec-design", "openai", "o1", 1),
        ("threat-modeling", "openai", "o1", 1),
        ("attack-surface", "openai", "o1", 1),
        ("attack-tree", "openai", "o1", 1),
        ("mitigations", "openai", "o1", 1),
        ("sec-design", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("threat-modeling", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-surface", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-tree", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("mitigations", "google", "gemini-2.0-flash-thinking-exp", 0),
    ],
)
@pytest.mark.integration
def test_app_dir_mode(agent_prompt_type, agent_provider, agent_model, agent_temperature):
    output_path = f"tests-output/dir-{agent_prompt_type}-flask-{agent_model}.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        config = AppConfig(
            mode="dir",
            target="tests/testdata/",
            output_file=output_file,
            agent_provider=agent_provider,
            agent_model=agent_model,
            agent_temperature=agent_temperature,
            agent_prompt_type=agent_prompt_type,
            verbose=True,
        )

        app(config)

    # Verify output file exists and is not empty
    assert os.path.exists(output_path), f"Output file {output_path} was not created"
    assert os.path.getsize(output_path) > 100, f"Output file {output_path} is empty"


@pytest.mark.parametrize(
    "agent_prompt_type,agent_provider,agent_model,agent_temperature",
    [
        ("sec-design", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("threat-modeling", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-surface", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("attack-tree", "google", "gemini-2.0-flash-thinking-exp", 0),
        ("mitigations", "google", "gemini-2.0-flash-thinking-exp", 0),
    ],
)
@pytest.mark.integration
def test_app_github_deep_analysis_mode(agent_prompt_type, agent_provider, agent_model, agent_temperature):
    output_path = f"tests-output/github-deep-analysis-{agent_prompt_type}-flask-{agent_model}.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        config = AppConfig(
            mode="github",
            target="https://github.com/pallets/flask",
            output_file=output_file,
            agent_provider=agent_provider,
            agent_model=agent_model,
            agent_temperature=agent_temperature,
            agent_prompt_type=agent_prompt_type,
            verbose=True,
            deep_analysis=True,
        )

        app(config)

    # Verify output file exists and is not empty
    assert os.path.exists(output_path), f"Output file {output_path} was not created"
    assert os.path.getsize(output_path) > 100, f"Output file {output_path} is empty"
