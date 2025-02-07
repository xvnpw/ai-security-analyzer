import os
from unittest.mock import patch, mock_open

import pytest
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models.fake_chat_models import ParrotFakeChatModel

from ai_security_analyzer.llms import LLMProvider, LLMConfig, ModelConfig, LLM, ProviderConfig
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.constants import (
    OPENAI_API_KEY,
    OPENROUTER_API_KEY,
    OPENROUTER_API_BASE,
    ANTHROPIC_API_KEY,
    GOOGLE_API_KEY,
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_CHUNK_SIZE,
)
from langchain_core.messages import SystemMessage, HumanMessage


# --- Mock model_configs.yaml content for testing ---
_TEST_MODEL_CONFIGS_YAML = """
models:
  test-model:
    max_number_of_tools: 5
    use_system_message: true
    documents_chunk_size: 1000
    documents_chunk_overlap: 50
    documents_context_window: 2000
    tokenizer_model_name: 'test-tokenizer'
    supports_structured_output: false
    reasoning_effort: 'low'
    system_message_type: 'developer'
  test-model-no-reasoning:
    max_number_of_tools: 5
    use_system_message: true
    documents_chunk_size: 1000
    documents_chunk_overlap: 50
    documents_context_window: 2000
    tokenizer_model_name: 'test-tokenizer'
    supports_structured_output: false
    system_message_type: 'system'
default:
  max_number_of_tools: 10
  use_system_message: false
  documents_chunk_size: 500
  documents_chunk_overlap: 25
  documents_context_window: 1000
  tokenizer_model_name: 'default-tokenizer'
  supports_structured_output: false
"""


@pytest.fixture
def mock_model_configs_yaml():
    return _TEST_MODEL_CONFIGS_YAML


@pytest.fixture
def app_config():
    """Fixture to provide a default AppConfig object with all mandatory fields."""
    return AppConfig(
        mode="dir",
        target=".",
        output_file=open(os.devnull, "w"),  # Dummy output file
        project_type="python",
        verbose=False,
        debug=False,
        agent_prompt_type="sec-design",
        agent_provider="openai",
        agent_model="gpt-4o",
        agent_temperature=0,
        agent_preamble_enabled=False,
        agent_preamble="##### (🤖 AI Generated)",
        deep_analysis=False,
        recursion_limit=30,
        exclude=None,
        exclude_mode="add",
        include=None,
        include_mode="add",
        filter_keywords=None,
        files_context_window=None,
        files_chunk_size=None,
        dry_run=False,
        refinement_count=0,
        resume=False,
        clear_checkpoints=False,
        checkpoint_dir=".checkpoints",
        reasoning_effort=None,
    )


@pytest.fixture
def llm_provider(app_config, mock_model_configs_yaml, monkeypatch):
    """Fixture to provide an LLMProvider instance with mocked model configs."""
    monkeypatch.setattr("builtins.open", mock_open(read_data=mock_model_configs_yaml))
    return LLMProvider(app_config)


def test_model_config_dataclass():
    config_data = {
        "max_number_of_tools": 3,
        "use_system_message": False,
        "documents_chunk_size": 500,
        "documents_chunk_overlap": 20,
        "documents_context_window": 1000,
        "tokenizer_model_name": "test_tokenizer",
        "supports_structured_output": False,
        "reasoning_effort": "medium",
        "structured_output_supports_temperature": False,
    }
    model_config = ModelConfig(**config_data)
    assert model_config.max_number_of_tools == 3
    assert not model_config.use_system_message
    assert model_config.documents_chunk_size == 500
    assert model_config.documents_chunk_overlap == 20
    assert model_config.documents_context_window == 1000
    assert model_config.tokenizer_model_name == "test_tokenizer"
    assert not model_config.supports_structured_output
    assert model_config.reasoning_effort == "medium"


def test_llm_dataclass():
    mock_llm_instance = ParrotFakeChatModel()
    mock_model_config = ModelConfig(
        max_number_of_tools=1,
        use_system_message=True,
        documents_chunk_size=100,
        documents_chunk_overlap=10,
        documents_context_window=200,
        tokenizer_model_name="test_tokenizer",
        supports_structured_output=False,
        system_message_type="system",
        structured_output_supports_temperature=False,
    )
    llm_obj = LLM(llm=mock_llm_instance, model_config=mock_model_config, provider="fake")
    assert isinstance(llm_obj.llm, ParrotFakeChatModel)
    assert isinstance(llm_obj.model_config, ModelConfig)

    assert llm_obj.model_config.max_number_of_tools == 1


def test_llm_config_dataclass():
    llm_config = LLMConfig(provider="openai", model="gpt-4o", temperature=0.5, for_structured_output=False)
    assert llm_config.provider == "openai"
    assert llm_config.model == "gpt-4o"
    assert llm_config.temperature == 0.5


def test_provider_config_dataclass():
    provider_config = ProviderConfig(env_key="TEST_API_KEY", api_base="https://test.api", model_class=ChatOpenAI)
    assert provider_config.env_key == "TEST_API_KEY"
    assert provider_config.api_base == "https://test.api"
    assert provider_config.model_class == ChatOpenAI


def test_llm_provider_initialization(llm_provider):
    assert isinstance(llm_provider, LLMProvider)
    assert isinstance(llm_provider._model_configs, dict)
    assert isinstance(llm_provider._default_model_config, ModelConfig)
    assert "test-model" in llm_provider._model_configs
    assert llm_provider._model_configs["test-model"].max_number_of_tools == 5
    assert llm_provider._default_model_config.max_number_of_tools == 10


def test_llm_provider_initialization_file_not_found(app_config, monkeypatch):
    monkeypatch.setattr("builtins.open", mock_open())  # Mock to simulate file not found
    with pytest.raises(SystemExit):  # Expecting SystemExit because of file reading error in init
        LLMProvider(app_config)


def test_llm_provider_initialization_invalid_yaml(app_config, monkeypatch):
    monkeypatch.setattr("builtins.open", mock_open(read_data="invalid yaml"))
    with pytest.raises(SystemExit):  # Expecting SystemExit because of YAML parsing error in init
        LLMProvider(app_config)


def test_get_chunk_size_config_override(app_config, llm_provider):
    app_config.files_chunk_size = 999
    mc_dict = {"documents_chunk_size": 1000}
    chunk_size = llm_provider._get_chunk_size(mc_dict, app_config)
    assert chunk_size == 999


def test_get_chunk_size_model_config(app_config, llm_provider):
    app_config.files_chunk_size = None
    mc_dict = {"documents_chunk_size": 1000}
    chunk_size = llm_provider._get_chunk_size(mc_dict, app_config)
    assert chunk_size == 1000


def test_get_chunk_size_default(app_config, llm_provider):
    app_config.files_chunk_size = None
    mc_dict = {}
    chunk_size = llm_provider._get_chunk_size(mc_dict, app_config)
    assert chunk_size == DEFAULT_CHUNK_SIZE


def test_get_context_window_config_override(app_config, llm_provider):
    app_config.files_context_window = 1999
    mc_dict = {"documents_context_window": 2000}
    context_window = llm_provider._get_context_window(mc_dict, app_config)
    assert context_window == 1999


def test_get_context_window_model_config(app_config, llm_provider):
    app_config.files_context_window = None
    mc_dict = {"documents_context_window": 2000}
    context_window = llm_provider._get_context_window(mc_dict, app_config)
    assert context_window == 2000


def test_get_context_window_default(app_config, llm_provider):
    app_config.files_context_window = None
    mc_dict = {}
    context_window = llm_provider._get_context_window(mc_dict, app_config)
    assert context_window == DEFAULT_CONTEXT_WINDOW


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_get_llm_instance_openai(llm_provider, app_config):
    llm_config = LLMConfig(provider="openai", model="gpt-4o", temperature=0.1, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatOpenAI)
    assert llm_instance.llm.temperature == 0.1
    assert llm_instance.llm.model_name == "gpt-4o"
    assert llm_instance.model_config == llm_provider._default_model_config  # using default config


@patch.dict(os.environ, {OPENROUTER_API_KEY: "test_openrouter_key"})
def test_get_llm_instance_openrouter(llm_provider, app_config):
    llm_config = LLMConfig(provider="openrouter", model="test-model", temperature=0.2, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatOpenAI)  # OpenRouter uses ChatOpenAI class
    assert llm_instance.llm.temperature == 0.2
    assert llm_instance.llm.model_name == "test-model"
    assert llm_instance.llm.openai_api_base == OPENROUTER_API_BASE
    assert llm_instance.model_config == llm_provider._model_configs["test-model"]


@patch.dict(os.environ, {ANTHROPIC_API_KEY: "test_anthropic_key"})
def test_get_llm_instance_anthropic(llm_provider, app_config):
    llm_config = LLMConfig(provider="anthropic", model="claude-v1.3", temperature=0.3, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatAnthropic)
    assert llm_instance.llm.temperature == 0.3
    assert llm_instance.llm.model == "claude-v1.3"
    assert llm_instance.model_config == llm_provider._default_model_config  # using default config


@patch.dict(os.environ, {GOOGLE_API_KEY: "test_google_key"})
def test_get_llm_instance_google(llm_provider, app_config):
    llm_config = LLMConfig(provider="google", model="gemini-pro", temperature=0.4, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatGoogleGenerativeAI)
    assert llm_instance.llm.temperature == 0.4
    assert llm_instance.llm.model == "models/gemini-pro"
    assert llm_instance.model_config == llm_provider._default_model_config  # using default config


@patch.dict(os.environ, {"FAKE_API_KEY": "test_fake_key"})
def test_get_llm_instance_fake(llm_provider, app_config):
    llm_config = LLMConfig(provider="fake", model="fake-model", temperature=0.5, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ParrotFakeChatModel)


def test_get_llm_instance_unsupported_provider(llm_provider, app_config):
    llm_config = LLMConfig(provider="unsupported", model="some-model", temperature=0.1, for_structured_output=False)
    with pytest.raises(ValueError, match="Unsupported provider: unsupported"):
        llm_provider._get_llm_instance(llm_config)


@patch.dict(os.environ, {}, clear=True)  # Ensure no API keys are set
def test_get_llm_instance_missing_api_key_openai(llm_provider, app_config):
    llm_config = LLMConfig(provider="openai", model="gpt-4o", temperature=0.1, for_structured_output=False)
    with pytest.raises(SystemExit):  # Expecting SystemExit because API key is missing
        llm_provider._get_llm_instance(llm_config)


@patch.dict(os.environ, {}, clear=True)  # Ensure no API keys are set
def test_get_llm_instance_missing_api_key_openrouter(llm_provider, app_config):
    llm_config = LLMConfig(provider="openrouter", model="test-model", temperature=0.1, for_structured_output=False)
    with pytest.raises(SystemExit):  # Expecting SystemExit because API key is missing
        llm_provider._get_llm_instance(llm_config)


@patch.dict(os.environ, {}, clear=True)  # Ensure no API keys are set
def test_get_llm_instance_missing_api_key_anthropic(llm_provider, app_config):
    llm_config = LLMConfig(provider="anthropic", model="claude-v1.3", temperature=0.1, for_structured_output=False)
    with pytest.raises(SystemExit):  # Expecting SystemExit because API key is missing
        llm_provider._get_llm_instance(llm_config)


@patch.dict(os.environ, {}, clear=True)  # Ensure no API keys are set
def test_get_llm_instance_missing_api_key_google(llm_provider, app_config):
    llm_config = LLMConfig(provider="google", model="gemini-pro", temperature=0.1, for_structured_output=False)
    with pytest.raises(SystemExit):  # Expecting SystemExit because API key is missing
        llm_provider._get_llm_instance(llm_config)


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_create_agent_llm(llm_provider, app_config):
    app_config.agent_provider = "openai"
    app_config.agent_model = "gpt-4o"
    app_config.agent_temperature = 0.6
    llm = llm_provider.create_agent_llm()
    assert isinstance(llm, LLM)
    assert isinstance(llm.llm, ChatOpenAI)
    assert llm.llm.temperature == 0.6
    assert llm.llm.model_name == "gpt-4o"


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_create_agent_llm_for_structured_queries_non_fix_temp_model(llm_provider, app_config):
    app_config.agent_provider = "openai"
    app_config.agent_model = "gpt-4o"  # not in FIX_TEMPERATURE_MODELS
    app_config.agent_temperature = 0.7  # this should be overridden to 0
    llm = llm_provider.create_agent_llm_for_structured_queries()
    assert isinstance(llm, LLM)
    assert isinstance(llm.llm, ChatOpenAI)
    assert llm.llm.temperature == 0.0  # should be 0 for structured queries
    assert llm.llm.model_name == "gpt-4o"


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_create_agent_llm_for_structured_queries_fix_temp_model(llm_provider, app_config):
    app_config.agent_provider = "openai"
    app_config.agent_model = "o1-preview"  # in FIX_TEMPERATURE_MODELS
    app_config.agent_temperature = 0.1  # this should be overridden to 1
    llm = llm_provider.create_agent_llm_for_structured_queries()
    assert isinstance(llm, LLM)
    assert isinstance(llm.llm, ChatOpenAI)
    assert llm.llm.temperature == 1.0  # should be 1 for fix temp models
    assert llm.llm.model_name == "o1-preview"


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_get_llm_instance_with_reasoning_effort(llm_provider, app_config):
    llm_config = LLMConfig(provider="openai", model="test-model", temperature=0.1, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatOpenAI)
    assert llm_instance.llm.reasoning_effort == "low"
    assert llm_instance.model_config.reasoning_effort == "low"


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_get_llm_instance_no_reasoning_effort_in_config(llm_provider, app_config):
    llm_config = LLMConfig(
        provider="openai", model="test-model-no-reasoning", temperature=0.1, for_structured_output=False
    )
    llm_instance = llm_provider._get_llm_instance(llm_config)
    assert isinstance(llm_instance.llm, ChatOpenAI)
    assert llm_instance.llm.reasoning_effort is None
    assert llm_instance.model_config.reasoning_effort is None


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_update_system_message_use_system_message_false(llm_provider, app_config):
    llm_config = LLMConfig(
        provider="openai", model="test-model-no-system", temperature=0.1, for_structured_output=False
    )
    llm_instance = llm_provider._get_llm_instance(llm_config)

    system_message = SystemMessage(content="Test system message")
    updated_message = llm_instance._update_system_message(system_message)
    assert isinstance(updated_message, HumanMessage)
    assert updated_message.content == "Test system message"


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_update_system_message_system_type(llm_provider, app_config):
    llm_config = LLMConfig(
        provider="openai", model="test-model-no-reasoning", temperature=0.1, for_structured_output=False
    )
    llm_instance = llm_provider._get_llm_instance(llm_config)

    system_message = SystemMessage(content="Test system message")
    updated_message = llm_instance._update_system_message(system_message)
    assert isinstance(updated_message, SystemMessage)
    assert updated_message.content == "Test system message"
    assert updated_message.additional_kwargs == {}


@patch.dict(os.environ, {OPENAI_API_KEY: "test_openai_key"})
def test_update_system_message_developer_type_openai_provider(llm_provider, app_config):
    llm_config = LLMConfig(provider="openai", model="test-model", temperature=0.1, for_structured_output=False)
    llm_instance = llm_provider._get_llm_instance(llm_config)

    system_message = SystemMessage(content="Test system message")
    updated_message = llm_instance._update_system_message(system_message)
    assert isinstance(updated_message, SystemMessage)
    assert updated_message.content == "Formatting re-enabled\nTest system message"
    assert updated_message.additional_kwargs == {"__openai_role__": "developer"}
