import pytest
from ai_security_analyzer.prompts.prompt_manager import PromptManager
from pathlib import Path
import os

# Assuming your prompt_manager.py and prompts directory are in the same directory as tests,
# or adjust the path accordingly if not.
PROMPTS_DIR = Path(__file__).parent.parent / "ai_security_analyzer" / "prompts"
if not PROMPTS_DIR.exists():
    PROMPTS_DIR = Path(__file__).parent / "ai_security_analyzer" / "prompts"  # if running from inside tests directory


@pytest.fixture
def prompt_manager():
    return PromptManager()


class TestPromptManager:

    def test_sanitize_model_name(self, prompt_manager):
        assert prompt_manager._sanitize_model_name("gemini-2.0-flash-thinking-exp") == "gemini-2.0-flash-thinking-exp"
        assert prompt_manager._sanitize_model_name("model/with/slash") == "model_with_slash"
        assert prompt_manager._sanitize_model_name("model\\with\\backslash") == "model_with_backslash"
        assert prompt_manager._sanitize_model_name("model:with:colon") == "model_with_colon"
        assert prompt_manager._sanitize_model_name("model*with*asterisk") == "model_with_asterisk"
        assert prompt_manager._sanitize_model_name("model?with?question") == "model_with_question"
        assert prompt_manager._sanitize_model_name('model"with"quote') == "model_with_quote"
        assert prompt_manager._sanitize_model_name("model<with<less") == "model_with_less"
        assert prompt_manager._sanitize_model_name("model>with>greater") == "model_with_greater"
        assert prompt_manager._sanitize_model_name("model|with|pipe") == "model_with_pipe"
        assert prompt_manager._sanitize_model_name('model/\\:*?"<>|with/\\:*?"<>|') == "model_________with_________"

    def test_get_prompt_default(self, prompt_manager):
        prompts = prompt_manager.get_prompt(
            provider="default", model="default", mode="file", prompt_type="attack-surface"
        )
        assert isinstance(prompts, list)
        assert len(prompts) > 0

    def test_get_prompt_specific_provider(self, prompt_manager):
        prompts = prompt_manager.get_prompt(
            provider="google", model="gemini-2.0-flash-thinking-exp", mode="file", prompt_type="attack-surface"
        )
        assert isinstance(prompts, list)
        assert len(prompts) > 0

    def test_get_prompt_fallback_to_default(self, prompt_manager):
        prompts = prompt_manager.get_prompt(
            provider="openai",  # provider that doesn't have specific prompts, should fallback to default
            model="gpt-4",  # model that doesn't have specific prompts
            mode="file",
            prompt_type="attack-surface",
        )
        assert isinstance(prompts, list)
        assert len(prompts) > 0

    def test_get_prompt_file_not_found(self, prompt_manager):
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_prompt(
                provider="default", model="default", mode="file", prompt_type="non-existent-prompt"
            )

    def test_get_prompt_invalid_yaml_structure(self, prompt_manager, tmp_path):
        # Create a temporary invalid YAML file
        invalid_yaml_content = "invalid: yaml: structure"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "file", exist_ok=True)
        (tmp_path / "default" / "file" / "attack-surface-default.yaml").write_text(
            invalid_yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_prompt(provider="default", model="default", mode="file", prompt_type="attack-surface")
        assert "Invalid YAML structure" in str(excinfo.value)

    def test_get_doc_type_prompt_default(self, prompt_manager):
        doc_type = prompt_manager.get_doc_type_prompt(
            provider="default", model="default", mode="file", prompt_type="sec-design"
        )
        assert doc_type == "DESIGN DOCUMENT"

    def test_get_doc_type_prompt_specific_provider(self, prompt_manager):
        doc_type = prompt_manager.get_doc_type_prompt(
            provider="google", model="gemini-2.0-flash-thinking-exp", mode="file", prompt_type="sec-design"
        )
        assert doc_type == "DESIGN DOCUMENT"

    def test_get_doc_type_prompt_fallback_to_default(self, prompt_manager):
        doc_type = prompt_manager.get_doc_type_prompt(
            provider="openai",  # provider that doesn't have specific doc-types, should fallback to default
            model="gpt-4",  # model that doesn't have specific doc-types
            mode="file",
            prompt_type="sec-design",
        )
        assert doc_type == "DESIGN DOCUMENT"

    def test_get_doc_type_prompt_file_not_found(self, prompt_manager):
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_doc_type_prompt(
                provider="default", model="default", mode="non-existent-mode", prompt_type="sec-design"
            )

    def test_get_doc_type_prompt_invalid_yaml_structure(self, prompt_manager, tmp_path):
        # Create a temporary invalid YAML file
        invalid_yaml_content = "invalid: yaml: structure"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "file", exist_ok=True)
        (tmp_path / "default" / "file" / "doc-types-default.yaml").write_text(
            invalid_yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_doc_type_prompt(
                provider="default", model="default", mode="file", prompt_type="sec-design"
            )
        assert "Invalid YAML structure" in str(excinfo.value)

    def test_get_doc_type_prompt_type_not_found(self, prompt_manager, tmp_path):
        # Create a temporary YAML file without 'sec-design'
        yaml_content = "doc-types:\n  threat-modeling: 'THREAT MODEL'"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "file", exist_ok=True)
        (tmp_path / "default" / "file" / "doc-types-default.yaml").write_text(yaml_content)  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_doc_type_prompt(
                provider="default", model="default", mode="file", prompt_type="sec-design"
            )
        assert "Document type 'sec-design' not found" in str(excinfo.value)

    def test_get_deep_analysis_prompt_github_mode(self, prompt_manager):
        prompt = prompt_manager.get_deep_analysis_prompt(
            provider="google", model="gemini-2.0-flash-thinking-exp", mode="github", prompt_type="attack-surface"
        )
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_get_deep_analysis_prompt_non_github_mode(self, prompt_manager):
        prompt = prompt_manager.get_deep_analysis_prompt(
            provider="google",
            model="gemini-2.0-flash-thinking-exp",
            mode="file",  # not github mode
            prompt_type="attack-surface",
        )
        assert prompt == ""

    def test_get_deep_analysis_prompt_file_not_found(self, prompt_manager):
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_deep_analysis_prompt(
                provider="default", model="default", mode="github", prompt_type="non-existent-prompt"
            )
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_deep_analysis_prompt(
                provider="non-existent-provider",
                model="non-existent-model",
                mode="github",
                prompt_type="attack-surface",
            )

    def test_get_deep_analysis_prompt_invalid_yaml_structure(self, prompt_manager, tmp_path):
        # Create a temporary invalid YAML file
        invalid_yaml_content = "invalid: yaml: structure"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "github", exist_ok=True)
        (tmp_path / "default" / "github" / "deep-analysis-default.yaml").write_text(
            invalid_yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_deep_analysis_prompt(
                provider="default", model="default", mode="github", prompt_type="attack-surface"
            )
        assert "Invalid YAML structure" in str(excinfo.value)

    def test_get_deep_analysis_prompt_type_not_found(self, prompt_manager, tmp_path):
        # Create a temporary YAML file without 'attack-surface'
        yaml_content = "templates:\n  threat-modeling: 'Deep analysis for threat modeling'"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "github", exist_ok=True)
        (tmp_path / "default" / "github" / "deep-analysis-default.yaml").write_text(
            yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_deep_analysis_prompt(
                provider="default", model="default", mode="github", prompt_type="attack-surface"
            )
        assert "Deep analysis template for 'attack-surface' not found" in str(excinfo.value)

    def test_get_format_prompt_github_mode(self, prompt_manager):
        prompt = prompt_manager.get_format_prompt(
            provider="google", model="gemini-2.0-flash-thinking-exp", mode="github", prompt_type="attack-surface"
        )
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_get_format_prompt_non_github_mode(self, prompt_manager):
        prompt = prompt_manager.get_format_prompt(
            provider="google",
            model="gemini-2.0-flash-thinking-exp",
            mode="file",  # not github mode
            prompt_type="attack-surface",
        )
        assert prompt == ""

    def test_get_format_prompt_file_not_found(self, prompt_manager):
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_format_prompt(
                provider="default", model="default", mode="github", prompt_type="non-existent-prompt"
            )
        with pytest.raises(FileNotFoundError):
            prompt_manager.get_format_prompt(
                provider="non-existent-provider",
                model="non-existent-model",
                mode="github",
                prompt_type="attack-surface",
            )

    def test_get_format_prompt_invalid_yaml_structure(self, prompt_manager, tmp_path):
        # Create a temporary invalid YAML file
        invalid_yaml_content = "invalid: yaml: structure"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "github", exist_ok=True)
        (tmp_path / "default" / "github" / "deep-analysis-format-default.yaml").write_text(
            invalid_yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_format_prompt(
                provider="default", model="default", mode="github", prompt_type="attack-surface"
            )
        assert "Invalid YAML structure" in str(excinfo.value)

    def test_get_format_prompt_type_not_found(self, prompt_manager, tmp_path):
        # Create a temporary YAML file without 'attack-surface'
        yaml_content = "templates:\n  threat-modeling: 'Format for threat modeling'"

        # Mock the base_path to point to the temporary directory
        prompt_manager.base_path = tmp_path

        # Create necessary directory structure under tmp_path
        os.makedirs(tmp_path / "default" / "github", exist_ok=True)
        (tmp_path / "default" / "github" / "deep-analysis-format-default.yaml").write_text(
            yaml_content
        )  # directly write content

        with pytest.raises(KeyError) as excinfo:
            prompt_manager.get_format_prompt(
                provider="default", model="default", mode="github", prompt_type="attack-surface"
            )
        assert "Format template for 'attack-surface' not found" in str(excinfo.value)
