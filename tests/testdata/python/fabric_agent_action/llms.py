import logging
import os
import sys
from dataclasses import dataclass
from typing import Literal, Type, Optional, Any

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from fabric_agent_action import constants

logger = logging.getLogger(__name__)

ProviderType = Literal["openrouter", "openai", "anthropic"]


@dataclass(frozen=True)
class LLM:
    llm: BaseChatModel
    use_system_message: bool
    max_number_of_tools: int


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


@dataclass(frozen=True)
class ModelConfig:
    max_number_of_tools: int
    use_system_message: bool


class LLMProvider:
    def __init__(self, config: Any) -> None:
        self.config = config
        self._provider_configs: dict[str, ProviderConfig] = {
            "openrouter": ProviderConfig(
                env_key=constants.OPENROUTER_API_KEY,
                api_base=constants.OPENROUTER_API_BASE,
                model_class=ChatOpenAI,
            ),
            "openai": ProviderConfig(
                env_key=constants.OPENAI_API_KEY,
                api_base=None,
                model_class=ChatOpenAI,
            ),
            "anthropic": ProviderConfig(
                env_key=constants.ANTHROPIC_API_KEY,
                api_base=None,
                model_class=ChatAnthropic,
            ),
        }
        self._model_configs: dict[str, ModelConfig] = {
            "gpt-4o": ModelConfig(max_number_of_tools=128, use_system_message=True),
            "openai/o1-preview": ModelConfig(max_number_of_tools=256, use_system_message=False),
            "o1-preview": ModelConfig(max_number_of_tools=256, use_system_message=False),
        }
        self._default_model_config = ModelConfig(max_number_of_tools=1000, use_system_message=True)

    def _get_llm_instance(self, llm_config: LLMConfig) -> LLM:
        provider_config = self._provider_configs.get(llm_config.provider)
        if not provider_config:
            raise ValueError(f"Unsupported provider: {llm_config.provider}")

        # Check if API key is set
        api_key = os.environ.get(provider_config.env_key)
        if not api_key:
            print(f"{provider_config.env_key} not set in env")
            sys.exit(1)

        model_config = self._model_configs.get(llm_config.model, self._default_model_config)

        logger.debug(f"[{llm_config.provider}] model config: {model_config}")

        # Log configuration
        logger.debug(f"using {llm_config.provider} provider with model={llm_config.model}")

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
        else:
            raise ValueError(f"Unsupported model class: {provider_config.model_class}")

        # Create LLM instance
        llm_instance = provider_config.model_class(**kwargs)

        return LLM(
            llm=llm_instance,
            use_system_message=model_config.use_system_message,
            max_number_of_tools=model_config.max_number_of_tools,
        )

    def createAgentLLM(self) -> LLM:
        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.agent_provider,
                model=self.config.agent_model,
                temperature=self.config.agent_temperature,
            )
        )

    def createFabricLLM(self) -> LLM:
        return self._get_llm_instance(
            LLMConfig(
                provider=self.config.fabric_provider,
                model=self.config.fabric_model,
                temperature=self.config.fabric_temperature,
            )
        )
