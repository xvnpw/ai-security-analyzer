import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Literal, Type, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

from ai_security_analyzer import constants
from ai_security_analyzer.config import AppConfig

logger = logging.getLogger(__name__)

ProviderType = Literal["openai", "openrouter", "anthropic", "google"]

DEFAULT_CONTEXT_WINDOW = 70000
DEFAULT_CHUNK_SIZE = 60000


@dataclass(frozen=True)
class ModelConfig:
    max_number_of_tools: int
    use_system_message: bool
    documents_chunk_size: int
    documents_chunk_overlap: int
    documents_context_window: int
    tokenizer_model_name: str


@dataclass(frozen=True)
class LLM:
    llm: BaseChatModel
    model_config: ModelConfig


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


class LLMProvider:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

        # Map provider to environment variables and model classes
        self._provider_configs: dict[str, ProviderConfig] = {
            "openai": ProviderConfig(
                env_key=constants.OPENAI_API_KEY,
                api_base=None,
                model_class=ChatOpenAI,
            ),
            "openrouter": ProviderConfig(
                env_key=constants.OPENROUTER_API_KEY,
                api_base=constants.OPENROUTER_API_BASE,
                model_class=ChatOpenAI,
            ),
            "anthropic": ProviderConfig(
                env_key=constants.ANTHROPIC_API_KEY,
                api_base=None,
                model_class=ChatAnthropic,
            ),
            "google": ProviderConfig(
                env_key=constants.GOOGLE_API_KEY,
                api_base=None,
                model_class=ChatGoogleGenerativeAI,
            ),
        }

        # Define model configurations
        self._model_configs: dict[str, ModelConfig] = {
            "gpt-4o": ModelConfig(
                max_number_of_tools=128,
                use_system_message=True,
                documents_chunk_size=config.files_chunk_size or DEFAULT_CHUNK_SIZE,
                documents_chunk_overlap=0,
                documents_context_window=config.files_context_window or DEFAULT_CONTEXT_WINDOW,
                tokenizer_model_name="gpt-4o",
            ),
            "o1-preview": ModelConfig(
                max_number_of_tools=0,
                use_system_message=False,
                documents_chunk_size=config.files_chunk_size or DEFAULT_CHUNK_SIZE,
                documents_chunk_overlap=0,
                documents_context_window=config.files_context_window or DEFAULT_CONTEXT_WINDOW,
                tokenizer_model_name="gpt-4",
            ),
        }

        self._default_model_config = ModelConfig(
            max_number_of_tools=1000,
            use_system_message=True,
            documents_chunk_size=config.files_chunk_size or DEFAULT_CHUNK_SIZE,
            documents_chunk_overlap=0,
            documents_context_window=config.files_context_window or DEFAULT_CONTEXT_WINDOW,
            tokenizer_model_name="gpt2",
        )

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
        else:
            raise ValueError(f"Unsupported model class: {provider_config.model_class}")

        # Create LLM instance
        llm_instance = provider_config.model_class(**kwargs)

        return LLM(
            llm=llm_instance,
            model_config=model_config,
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
        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.agent_provider,
                model=self.config.agent_model,
                temperature=0.0,
            )
        )

    def create_editor_llm(self) -> LLM:
        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.editor_provider,
                model=self.config.editor_model,
                temperature=self.config.editor_temperature,
            )
        )
