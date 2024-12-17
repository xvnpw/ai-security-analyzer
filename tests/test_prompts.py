import pytest
from ai_security_analyzer.prompts import DOC_TYPE_PROMPTS, get_agent_prompt, _TEMPLATE_PROMPTS

# Test data
VALID_PROMPT_TYPES = ["sec-design", "threat-modeling", "attack-surface", "attack-tree", "threat-scenarios"]

MODE_SPECIFIC_CONTENT = [
    ("dir", "PROJECT FILES", "GITHUB REPOSITORY"),
    ("github", "GITHUB REPOSITORY", "PROJECT FILES"),
]

DOC_TYPE_MAPPING = [
    ("sec-design", "DESIGN DOCUMENT"),
    ("threat-modeling", "THREAT MODEL"),
    ("attack-surface", "THREAT MODEL"),
    ("threat-scenarios", "THREAT MODEL"),
    ("attack-tree", "ATTACK TREE"),
]


@pytest.mark.parametrize("prompt_type", VALID_PROMPT_TYPES)
@pytest.mark.parametrize("mode", ["dir", "github"])
def test_get_agent_prompt_valid_inputs(prompt_type: str, mode: str):
    """Test valid combinations of prompt types and modes"""
    result = get_agent_prompt(prompt_type, mode)
    assert isinstance(result, str)
    assert len(result) > 0


@pytest.mark.parametrize("invalid_type", ["", "invalid", "random", None, "security-design"])
def test_get_agent_prompt_invalid_prompt_type(invalid_type):
    """Test invalid prompt types raise ValueError"""
    with pytest.raises(ValueError, match=f"No prompt template for prompt type: {invalid_type}"):
        get_agent_prompt(invalid_type, "dir")


@pytest.mark.parametrize("invalid_mode", ["", "invalid", "local", None, "directory"])
def test_get_agent_prompt_invalid_mode(invalid_mode):
    """Test invalid modes raise ValueError"""
    with pytest.raises(ValueError, match=f"Unknown mode: {invalid_mode}"):
        get_agent_prompt("sec-design", invalid_mode)


@pytest.mark.parametrize("mode,expected_content,unexpected_content", MODE_SPECIFIC_CONTENT)
def test_get_agent_prompt_mode_specific_content(mode: str, expected_content: str, unexpected_content: str):
    """Test mode-specific content is included in prompts"""
    for prompt_type in VALID_PROMPT_TYPES:
        result = get_agent_prompt(prompt_type, mode)
        assert expected_content in result
        assert unexpected_content not in result


@pytest.mark.parametrize("prompt_type,expected_doc_type", DOC_TYPE_MAPPING)
def test_get_agent_prompt_doc_type_mapping(prompt_type: str, expected_doc_type: str):
    """Test document type mapping for different prompt types"""
    result = get_agent_prompt(prompt_type, "dir")
    assert expected_doc_type in result


def test_prompt_templates_and_doc_types_match():
    """Test all prompt templates have corresponding doc types"""
    for prompt_type in _TEMPLATE_PROMPTS.keys():
        assert prompt_type in DOC_TYPE_PROMPTS


@pytest.mark.parametrize("prompt_type", ["sec-design", "threat-modeling"])
def test_get_agent_prompt_different_modes(prompt_type: str):
    """Test prompts are different for different modes but contain expected content"""
    dir_result = get_agent_prompt(prompt_type, "dir")
    github_result = get_agent_prompt(prompt_type, "github")

    # Results should be different for dir vs github
    assert dir_result != github_result

    # Each should contain mode-specific content
    assert "PROJECT FILES" in dir_result
    assert "GITHUB REPOSITORY" in github_result
