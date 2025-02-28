from pathlib import Path
import yaml
from typing import List

from ai_security_analyzer.config import AppConfig

THREAT_ACTOR_DESCRIPTION = {
    "none": "",
    "external_web": "Assume that threat actor is external attacker that will try to trigger vulnerability in publicly available instance of application.",
    "vscode_extension": "Assume that threat actor is external attacker that will try to trigger vulnerability in VSCode extension.",
    "vscode_extension_malicious_repo": "Assume that threat actor will try to trigger vulnerability in VSCode extension by providing malicious repository to victim with manipulated content.",
}


class PromptManager:
    def __init__(self) -> None:
        self.base_path = Path(__file__).parent

    def _sanitize_model_name(self, model: str) -> str:
        """
        Sanitize model name to create a safe directory name.
        Replaces path-unsafe characters with underscores.

        Args:
            model: Model name that might contain unsafe characters

        Returns:
            Sanitized model name safe for directory usage
        """
        # Characters that are unsafe for directory names
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        sanitized = model
        for char in unsafe_chars:
            sanitized = sanitized.replace(char, "_")
        return sanitized

    def get_formatted_prompts(self, config: AppConfig) -> List[str]:
        raw_prompts = self.get_prompt(config.agent_provider, config.agent_model, config.mode, config.agent_prompt_type)

        if config.agent_prompt_type in ("vulnerabilities", "vulnerabilities-workflow-1"):
            return [self.format_for_vulnerabilities(raw_prompt, config) for raw_prompt in raw_prompts]
        else:
            return raw_prompts

    def format_for_vulnerabilities(self, agent_prompt: str, config: AppConfig) -> str:
        if config.excluded_classes_of_vulnerabilities:
            exclude_vulnerabilities = f"classes of vulnerabilities: {config.excluded_classes_of_vulnerabilities}"
        else:
            exclude_vulnerabilities = ""

        if config.included_classes_of_vulnerabilities:
            include_vulnerabilities = f"classes of vulnerabilities: {config.included_classes_of_vulnerabilities}"
        else:
            include_vulnerabilities = ""

        if config.vulnerabilities_severity_threshold:
            severity_threshold = f"has vulnerability rank at least: {config.vulnerabilities_severity_threshold}"
        else:
            severity_threshold = ""

        if config.vulnerabilities_threat_actor and config.vulnerabilities_threat_actor in THREAT_ACTOR_DESCRIPTION:
            threat_actor_description = THREAT_ACTOR_DESCRIPTION[config.vulnerabilities_threat_actor]
        else:
            threat_actor_description = ""

        return agent_prompt.format(
            include_vulnerabilities=include_vulnerabilities,
            exclude_vulnerabilities=exclude_vulnerabilities,
            severity_threshold=severity_threshold,
            threat_actor_description=threat_actor_description,
        )

    def get_prompt(self, provider: str, model: str, mode: str, prompt_type: str) -> List[str]:
        """
        Get prompts from YAML file based on provider, model, mode and prompt type.

        Args:
            provider: AI provider (e.g., 'google', 'openai')
            model: Model name (e.g., 'gemini-2.0-flash-thinking-exp')
            prompt_type: Type of prompt (e.g., 'threat-modeling')
            mode: Mode of operation (e.g., 'github')

        Returns:
            List of prompt texts from the template

        Raises:
            FileNotFoundError: If the YAML file doesn't exist
            KeyError: If the YAML file doesn't contain required structure
        """
        # Sanitize model name for safe directory usage
        safe_model = self._sanitize_model_name(model)

        # Try provider-specific prompt first
        yaml_path = self.base_path / provider / safe_model / mode / f"{prompt_type}.yaml"

        # If provider-specific doesn't exist, try default
        if not yaml_path.exists():
            yaml_path = self.base_path / "default" / mode / f"{prompt_type}-default.yaml"

        if not yaml_path.exists():
            raise FileNotFoundError(f"No prompt file found for {provider}/{safe_model}/{mode}/{prompt_type}")

        with open(yaml_path, "r", encoding="utf-8") as file:
            try:
                yaml_content = yaml.safe_load(file)
                templates = yaml_content.get("templates", [])
                return [template["text"] for template in templates]
            except (yaml.YAMLError, KeyError) as e:
                raise KeyError(f"Invalid YAML structure in {yaml_path}: {str(e)}")

    def get_doc_type_prompt(self, provider: str, model: str, mode: str, prompt_type: str) -> str:
        """
        Get document type prompt from YAML file based on provider, model and prompt type.

        Args:
            provider: AI provider (e.g., 'google', 'openai')
            model: Model name (e.g., 'gemini-2.0-flash-thinking-exp')
            prompt_type: Type of prompt (e.g., 'threat-modeling')

        Returns:
            Document type string from the template

        Raises:
            FileNotFoundError: If no YAML file is found
            KeyError: If the YAML structure is invalid or prompt_type not found
        """
        # Sanitize model name for safe directory usage
        safe_model = self._sanitize_model_name(model)

        # Try provider-specific doc types first
        yaml_path = self.base_path / provider / safe_model / mode / "doc-types.yaml"

        # If provider-specific doesn't exist, try default
        if not yaml_path.exists():
            yaml_path = self.base_path / "default" / mode / "doc-types-default.yaml"

        if not yaml_path.exists():
            raise FileNotFoundError(f"No doc-types file found for {provider}/{safe_model}/{mode}")

        with open(yaml_path, "r", encoding="utf-8") as file:
            try:
                yaml_content = yaml.safe_load(file)
                doc_types = yaml_content.get("doc-types", {})

                if prompt_type not in doc_types:
                    raise KeyError(f"Document type '{prompt_type}' not found in {yaml_path}")

                return str(doc_types[prompt_type])
            except yaml.YAMLError as e:
                raise KeyError(f"Invalid YAML structure in {yaml_path}: {str(e)}")

    def get_deep_analysis_prompt(self, provider: str, model: str, mode: str, prompt_type: str) -> str:
        """
        Get deep analysis prompt from YAML file based on provider, model and prompt type.
        Deep analysis is only available for GitHub mode.

        Args:
            provider: AI provider (e.g., 'google', 'openai')
            model: Model name (e.g., 'gemini-2.0-flash-thinking-exp')
            prompt_type: Type of prompt (e.g., 'threat-modeling')

        Returns:
            Deep analysis prompt template string

        Raises:
            FileNotFoundError: If the YAML file doesn't exist
            KeyError: If the prompt type is not found or YAML structure is invalid
        """
        if mode != "github":
            return ""

        # Sanitize model name for safe directory usage
        safe_model = self._sanitize_model_name(model)

        yaml_path = self.base_path / provider / safe_model / mode / "deep-analysis.yaml"

        # If provider-specific doesn't exist, try default
        if not yaml_path.exists():
            yaml_path = self.base_path / "default" / mode / "deep-analysis-default.yaml"

        if not yaml_path.exists():
            raise FileNotFoundError(f"No deep analysis prompt file found for {provider}/{safe_model}")

        with open(yaml_path, "r", encoding="utf-8") as file:
            try:
                yaml_content = yaml.safe_load(file)
                templates = yaml_content.get("templates", {})

                if prompt_type not in templates:
                    raise KeyError(f"Deep analysis template for '{prompt_type}' not found in {yaml_path}")

                return str(templates[prompt_type])
            except yaml.YAMLError as e:
                raise KeyError(f"Invalid YAML structure in {yaml_path}: {str(e)}")

    def get_format_prompt(self, provider: str, model: str, mode: str, prompt_type: str) -> str:
        """
        Get format prompt from YAML file based on provider, model and prompt type.
        Format prompts are only available for GitHub mode.

        Args:
            provider: AI provider (e.g., 'google', 'openai')
            model: Model name (e.g., 'gemini-2.0-flash-thinking-exp')
            prompt_type: Type of prompt (e.g., 'threat-modeling')
            mode: Mode of operation (e.g., 'github')

        Returns:
            Format prompt template string

        Raises:
            FileNotFoundError: If the YAML file doesn't exist
            KeyError: If the prompt type is not found or YAML structure is invalid
        """
        if mode != "github":
            return ""

        # Sanitize model name for safe directory usage
        safe_model = self._sanitize_model_name(model)

        yaml_path = self.base_path / provider / safe_model / mode / "deep-analysis-format.yaml"

        # If provider-specific doesn't exist, try default
        if not yaml_path.exists():
            yaml_path = self.base_path / "default" / mode / "deep-analysis-format-default.yaml"

        if not yaml_path.exists():
            raise FileNotFoundError(f"No format prompt file found for {provider}/{safe_model}")

        with open(yaml_path, "r", encoding="utf-8") as file:
            try:
                yaml_content = yaml.safe_load(file)
                templates = yaml_content.get("templates", {})

                if prompt_type not in templates:
                    raise KeyError(f"Format template for '{prompt_type}' not found in {yaml_path}")

                return str(templates[prompt_type])
            except yaml.YAMLError as e:
                raise KeyError(f"Invalid YAML structure in {yaml_path}: {str(e)}")
