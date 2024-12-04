import os
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel

from ai_create_project_sec_design import constants
from ai_create_project_sec_design.llms import LLMProvider


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


def test_create_agent_llm_success():
    # Set up the environment variables for API keys
    with patch.dict(os.environ, {constants.OPENAI_API_KEY: "fake-openai-api-key"}):
        config = AppConfigTest()
        provider = LLMProvider(config)
        agent_llm = provider.create_agent_llm()

        assert agent_llm is not None
        assert isinstance(agent_llm.llm, BaseChatModel)
        assert agent_llm.model_config.tokenizer_model_name == "gpt-4o"
        assert agent_llm.model_config.max_number_of_tools == 128
        assert agent_llm.model_config.documents_chunk_size == 1000
        assert agent_llm.model_config.documents_context_window == 1000


def test_create_editor_llm_success():
    # Set up the environment variables for API keys
    with patch.dict(os.environ, {constants.ANTHROPIC_API_KEY: "fake-anthropic-api-key"}):
        config = AppConfigTest()
        provider = LLMProvider(config)
        editor_llm = provider.create_editor_llm()

        assert editor_llm is not None
        assert isinstance(editor_llm.llm, BaseChatModel)
        # Since 'claude-v1' is not defined in _model_configs, default model config is used
        assert editor_llm.model_config.tokenizer_model_name == "gpt2"  # Default tokenizer model name
        assert editor_llm.model_config.max_number_of_tools == 1000  # Default max_number_of_tools


def test_create_llm_with_invalid_provider():
    # Set up the environment variables for API keys
    with patch.dict(os.environ, {}):
        config = AppConfigTest(
            agent_provider="invalid_provider",
        )
        provider = LLMProvider(config)

        with pytest.raises(ValueError) as exc_info:
            provider.create_agent_llm()
        assert "Unsupported provider" in str(exc_info.value)


def test_create_llm_with_missing_api_key():
    # Clear the environment variables
    with patch.dict(os.environ, {}, clear=True):
        config = AppConfigTest()
        provider = LLMProvider(config)

        with pytest.raises(SystemExit) as exc_info:
            provider.create_agent_llm()
        assert "1" in str(exc_info.value)
