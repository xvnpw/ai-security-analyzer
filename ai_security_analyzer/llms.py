import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Literal, Type, Optional, Dict, List, Union
from pathlib import Path

import yaml
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models.fake_chat_models import ParrotFakeChatModel
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage

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
    structured_output_supports_temperature: bool
    reasoning_effort: Optional[str] = None
    system_message_type: Optional[Literal["system", "developer"]] = None
    max_tokens: Optional[int] = None
    thinking: Optional[bool] = None
    thinking_budget_tokens: Optional[int] = None

    def __post_init__(self) -> None:
        if self.use_system_message and self.system_message_type is None:
            raise ValueError("system_message_type must be set when use_system_message is True")


class LLM:
    def __init__(self, llm: BaseChatModel, model_config: ModelConfig, provider: ProviderType):
        self.llm = llm
        self.model_config = model_config
        self.provider = provider

    def invoke(self, messages: list[Any]) -> BaseMessage:
        """
        Invokes the LLM with the given messages, applying message updates based on model config.
        """
        updated_messages: List[BaseMessage] = []
        for message in messages:
            if isinstance(message, SystemMessage):
                updated_message = self._update_system_message(message)
                updated_messages.append(updated_message)
            else:
                updated_messages.append(message)

        return self.llm.invoke(updated_messages)

    def _update_system_message(self, system_message: SystemMessage) -> Union[SystemMessage, HumanMessage]:
        """
        Updates a SystemMessage based on the model configuration.
        If use_system_message is False, it converts SystemMessage to HumanMessage.
        If system_message_type is 'developer', it adds additional kwargs.
        """
        prompt = system_message.content
        if not self.model_config.use_system_message:
            return HumanMessage(content=prompt)

        if self.model_config.system_message_type == "system":
            return SystemMessage(content=prompt)
        elif self.model_config.system_message_type == "developer" and self.provider in ["openai", "fake"]:
            updated_system_message = SystemMessage(content=f"Formatting re-enabled\n{prompt}")
            updated_system_message.additional_kwargs = {"__openai_role__": "developer"}
            return updated_system_message
        else:
            raise ValueError(f"Cannot create system message: {self.model_config}")


@dataclass(frozen=True)
class LLMConfig:
    provider: ProviderType
    model: str
    temperature: float
    for_structured_output: bool


@dataclass(frozen=True)
class ProviderConfig:
    env_key: str
    api_base: Optional[str]
    model_class: Type[BaseChatModel]


FIX_TEMPERATURE_MODELS = ["o1", "o1-preview"]
MAX_OUTPUT_TOKENS = 100000


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
                    structured_output_supports_temperature=mc.get("structured_output_supports_temperature", False),
                    max_tokens=mc.get("max_tokens", None),
                    thinking=mc.get("thinking", None),
                    thinking_budget_tokens=mc.get("thinking_budget_tokens", None),
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
                structured_output_supports_temperature=default_mc.get("structured_output_supports_temperature", False),
                max_tokens=default_mc.get("max_tokens", 100000),
                thinking=default_mc.get("thinking", False),
                thinking_budget_tokens=default_mc.get("thinking_budget_tokens", None),
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
                "max_tokens": model_config.max_tokens or MAX_OUTPUT_TOKENS,
            }
            if provider_config.api_base:
                kwargs["openai_api_base"] = provider_config.api_base

            if model_config.supports_structured_output and llm_config.for_structured_output:
                if not model_config.structured_output_supports_temperature:
                    kwargs["temperature"] = None
                kwargs["disabled_params"] = {"parallel_tool_calls": None}

        elif provider_config.model_class == ChatAnthropic:
            kwargs = {
                "temperature": llm_config.temperature,
                "model": llm_config.model,
                "anthropic_api_key": api_key,
                "max_tokens": model_config.max_tokens or MAX_OUTPUT_TOKENS,
            }

            if model_config.thinking and model_config.thinking_budget_tokens:
                kwargs["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": model_config.thinking_budget_tokens,
                }
        elif provider_config.model_class == ChatGoogleGenerativeAI:
            kwargs = {
                "temperature": llm_config.temperature,
                "model": llm_config.model,
                "google_api_key": api_key,
                "max_output_tokens": MAX_OUTPUT_TOKENS,
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
                for_structured_output=False,
            )
        )

    def create_secondary_agent_llm(self) -> LLM:
        if not all(
            [
                self.config.secondary_agent_provider,
                self.config.secondary_agent_model,
                self.config.secondary_agent_temperature,
            ]
        ):
            logger.debug("Secondary agent configuration is not set, using agent configuration")
            provider = self.config.agent_provider
            model = self.config.agent_model
            temperature = self.config.agent_temperature
        else:
            assert self.config.secondary_agent_provider is not None
            assert self.config.secondary_agent_model is not None
            assert self.config.secondary_agent_temperature is not None
            provider = self.config.secondary_agent_provider
            model = self.config.secondary_agent_model
            temperature = self.config.secondary_agent_temperature

        return self._get_llm_instance(
            LLMConfig(
                provider=provider,
                model=model,
                temperature=temperature,
                for_structured_output=False,
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
                for_structured_output=True,
            )
        )
