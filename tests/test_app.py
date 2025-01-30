from ai_security_analyzer.app import app
from ai_security_analyzer.config import AppConfig
import os
from unittest.mock import patch
import ai_security_analyzer.constants as consts

FAKE_ENVS = {
    "FAKE_API_KEY": "fake",
    consts.OPENAI_API_KEY: None,
    consts.ANTHROPIC_API_KEY: None,
    consts.GOOGLE_API_KEY: None,
}


def test_app_file_mode():
    # given
    agent_provider = "fake"
    agent_model = "o1"
    agent_temperature = 1
    agent_prompt_type = "sec-design"

    output_path = "tests-output/test_app_file_mode.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    try:
        # when
        with patch("os.environ", FAKE_ENVS):
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
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)


def test_app_github_mode():
    # given
    agent_provider = "fake"
    agent_model = "o1"
    agent_temperature = 1
    agent_prompt_type = "sec-design"

    output_path = "tests-output/test_app_github_mode.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    try:
        # when
        with patch("os.environ", FAKE_ENVS):
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
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)


def test_app_dir_mode():
    # given
    agent_provider = "fake"
    agent_model = "o1"
    agent_temperature = 1
    agent_prompt_type = "sec-design"

    output_path = "tests-output/test_app_dir_mode.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    try:
        # when
        with patch("os.environ", FAKE_ENVS):
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
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)


def test_app_dir_dry_run_mode():
    # given
    agent_provider = "fake"
    agent_model = "o1"
    agent_temperature = 1
    agent_prompt_type = "sec-design"

    output_path = "tests-output/test_app_dir_dry_run_mode.md"

    # Create output directory if it doesn't exist
    os.makedirs("tests-output", exist_ok=True)

    try:
        # when
        with patch("os.environ", FAKE_ENVS):
            with open(output_path, "w", encoding="utf-8") as output_file:
                config = AppConfig(
                    mode="dir",
                    dry_run=True,
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
        assert os.path.getsize(output_path) == 0, f"Output file {output_path} is not empty"
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)
