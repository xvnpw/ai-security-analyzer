import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Literal, Type, Optional, Dict
from pathlib import Path

import yaml
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models.fake_chat_models import ParrotFakeChatModel

from ai_security_analyzer.constants import (
    OPENAI_API_KEY,
    OPENROUTER_API_KEY,
    OPENROUTER_API_BASE,
    ANTHROPIC_API_KEY,
    GOOGLE_API_KEY,
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_CHUNK_SIZE,
)
from ai_security_analyzer.config import AppConfig

logger = logging.getLogger(__name__)

ProviderType = Literal["openai", "openrouter", "anthropic", "google", "fake"]  # fake: only for testing


@dataclass(frozen=True)
class ModelConfig:
    max_number_of_tools: int
    use_system_message: bool
    documents_chunk_size: int
    documents_chunk_overlap: int
    documents_context_window: int
    tokenizer_model_name: str
    supports_structured_output: bool
    reasoning_effort: Optional[str] = None
    system_message_type: Optional[Literal["system", "developer"]] = None

    def __post_init__(self) -> None:
        if self.use_system_message and self.system_message_type is None:
            raise ValueError("system_message_type must be set when use_system_message is True")


@dataclass(frozen=True)
class LLM:
    llm: BaseChatModel
    model_config: ModelConfig
    provider: ProviderType


@dataclass(frozen=True)
class LLMConfig:
    provider: ProviderType
    model: str
    temperature: float


@dataclass(frozen=True)
class ProviderConfig:
    env_key: str
    api_base: Optional[str]
    model_class: Type[BaseChatModel]


FIX_TEMPERATURE_MODELS = ["o1", "o1-preview"]


class LLMProvider:
    def _get_chunk_size(self, mc: dict[str, Any], config: AppConfig) -> int:
        return config.files_chunk_size or mc.get("documents_chunk_size") or DEFAULT_CHUNK_SIZE

    def _get_context_window(self, mc: dict[str, Any], config: AppConfig) -> int:
        return config.files_context_window or mc.get("documents_context_window") or DEFAULT_CONTEXT_WINDOW

    def __init__(self, config: AppConfig) -> None:
        self.base_path = Path(__file__).parent
        self.config = config

        # Map provider to environment variables and model classes
        self._provider_configs: Dict[str, ProviderConfig] = {
            "fake": ProviderConfig(
                env_key="FAKE_API_KEY",
                api_base=None,
                model_class=ParrotFakeChatModel,
            ),
            "openai": ProviderConfig(
                env_key=OPENAI_API_KEY,
                api_base=None,
                model_class=ChatOpenAI,
            ),
            "openrouter": ProviderConfig(
                env_key=OPENROUTER_API_KEY,
                api_base=OPENROUTER_API_BASE,
                model_class=ChatOpenAI,
            ),
            "anthropic": ProviderConfig(
                env_key=ANTHROPIC_API_KEY,
                api_base=None,
                model_class=ChatAnthropic,
            ),
            "google": ProviderConfig(
                env_key=GOOGLE_API_KEY,
                api_base=None,
                model_class=ChatGoogleGenerativeAI,
            ),
        }

        model_config_path = self.base_path / "model_configs.yaml"

        # Load model configurations from YAML file
        try:
            with open(model_config_path, "r") as f:
                model_configs_data = yaml.safe_load(f)
            self._model_configs = {}
            models_data = model_configs_data.get("models", {})
            for model_name, mc in models_data.items():
                self._model_configs[model_name] = ModelConfig(
                    max_number_of_tools=mc.get("max_number_of_tools", 0),
                    use_system_message=mc.get("use_system_message", False),
                    system_message_type=mc.get("system_message_type", None),
                    documents_chunk_size=self._get_chunk_size(mc, config),
                    documents_chunk_overlap=mc.get("documents_chunk_overlap", 0),
                    documents_context_window=self._get_context_window(mc, config),
                    tokenizer_model_name=mc.get("tokenizer_model_name", "gpt2"),
                    supports_structured_output=mc.get("supports_structured_output", False),
                    reasoning_effort=mc.get("reasoning_effort", None),
                )

            # Define default model configuration
            default_mc = model_configs_data.get("default", {})
            self._default_model_config = ModelConfig(
                max_number_of_tools=default_mc.get("max_number_of_tools", 1000),
                use_system_message=default_mc.get("use_system_message", True),
                system_message_type=default_mc.get("system_message_type", None),
                documents_chunk_size=self._get_chunk_size(default_mc, config),
                documents_chunk_overlap=default_mc.get("documents_chunk_overlap", 0),
                documents_context_window=self._get_context_window(default_mc, config),
                tokenizer_model_name=default_mc.get("tokenizer_model_name", "gpt2"),
                supports_structured_output=default_mc.get("supports_structured_output", False),
                reasoning_effort=default_mc.get("reasoning_effort", None),
            )
        except Exception as e:
            logger.error(f"Failed to load model configurations: {e}")
            sys.exit(1)

    def _get_llm_instance(self, llm_config: LLMConfig) -> LLM:
        provider_config = self._provider_configs.get(llm_config.provider)
        if not provider_config:
            raise ValueError(f"Unsupported provider: {llm_config.provider}")

        api_key = os.environ.get(provider_config.env_key)
        if not api_key:
            logger.error(f"{provider_config.env_key} not set in environment variables.")
            sys.exit(1)

        model_config = self._model_configs.get(llm_config.model, self._default_model_config)

        logger.debug(f"[{llm_config.provider}] model config: {model_config}")

        # Create kwargs based on provider type
        if provider_config.model_class == ChatOpenAI:
            kwargs: dict[str, Any] = {
                "temperature": llm_config.temperature,
                "model_name": llm_config.model,
                "openai_api_key": api_key,
                "reasoning_effort": model_config.reasoning_effort,
            }
            if provider_config.api_base:
                kwargs["openai_api_base"] = provider_config.api_base
        elif provider_config.model_class == ChatAnthropic:
            kwargs = {
                "temperature": llm_config.temperature,
                "model": llm_config.model,
                "anthropic_api_key": api_key,
            }
        elif provider_config.model_class == ChatGoogleGenerativeAI:
            kwargs = {
                "temperature": llm_config.temperature,
                "model": llm_config.model,
                "google_api_key": api_key,
            }
        elif provider_config.model_class == ParrotFakeChatModel:
            kwargs = {
                "temperature": llm_config.temperature,
                "model": llm_config.model,
            }
        else:
            raise ValueError(f"Unsupported model class: {provider_config.model_class}")

        # Create LLM instance
        llm_instance = provider_config.model_class(**kwargs)

        return LLM(
            llm=llm_instance,
            model_config=model_config,
            provider=llm_config.provider,
        )

    def create_agent_llm(self) -> LLM:
        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.agent_provider,
                model=self.config.agent_model,
                temperature=self.config.agent_temperature,
            )
        )

    def create_agent_llm_for_structured_queries(self) -> LLM:
        if self.config.agent_model in FIX_TEMPERATURE_MODELS:
            temperature = 1
        else:
            temperature = 0

        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.agent_provider,
                model=self.config.agent_model,
                temperature=temperature,
            )
        )
