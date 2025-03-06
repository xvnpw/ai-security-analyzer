import io
import logging
from typing import List, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing_extensions import Literal


logger = logging.getLogger(__name__)


class AppConfig(BaseModel):
    """Configuration model with validation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    mode: Literal["dir", "github", "file"] = Field(default="dir")
    target: str
    output_file: io.TextIOWrapper
    project_type: Literal["python", "generic", "go", "java", "android", "javascript"] = Field(default="python")
    verbose: bool = Field(default=False)
    debug: bool = Field(default=False)

    agent_prompt_type: Literal[
        "sec-design",
        "threat-modeling",
        "attack-surface",
        "attack-tree",
        "mitigations",
        "vulnerabilities",
        "vulnerabilities-workflow-1",
        "vulnerabilities-workflow-2",
    ] = Field(default="sec-design")

    # fake: only for testing
    agent_provider: Literal["openai", "openrouter", "anthropic", "google", "fake"] = Field(default="openai")

    agent_model: str = Field(default="gpt-4o")
    agent_temperature: float = Field(default=0, ge=0, le=1)
    agent_preamble_enabled: bool = Field(default=False)
    agent_preamble: str = Field(default="##### (🤖 AI Generated)")
    deep_analysis: bool = Field(default=False)
    recursion_limit: int = Field(default=35)
    vulnerabilities_iterations: int = Field(default=5)

    exclude: Optional[List[str]] = Field(default=None)
    exclude_mode: Literal["add", "override"] = Field(default="add")
    include: Optional[List[str]] = Field(default=None)
    include_mode: Literal["add", "override"] = Field(default="add")
    filter_keywords: Optional[Set[str]] = Field(default=None)
    files_context_window: Optional[int] = Field(default=None)
    files_chunk_size: Optional[int] = Field(default=None)
    dry_run: bool = Field(default=False)
    refinement_count: int = Field(default=0)
    resume: bool = Field(default=False)
    clear_checkpoints: bool = Field(default=False)
    checkpoint_dir: str = Field(default=".checkpoints")
    reasoning_effort: Optional[str] = Field(default=None)

    # Secondary agent configuration
    secondary_agent_provider: Optional[Literal["openai", "openrouter", "anthropic", "google", "fake"]] = Field(
        default=None
    )
    secondary_agent_model: Optional[str] = Field(default=None)
    secondary_agent_temperature: Optional[float] = Field(default=None, ge=0, le=1)

    # Vulnerabilities workflow configuration
    vulnerabilities_severity_threshold: Literal["low", "medium", "high", "critical"] = Field(default="high")
    vulnerabilities_threat_actor: Literal[
        "none", "external_web", "vscode_extension", "vscode_extension_malicious_repo"
    ] = Field(default="external_web")
    vulnerabilities_output_dir: str = Field(default="vulnerabilities-workflow")
    included_classes_of_vulnerabilities: Optional[str] = Field(default=None)
    excluded_classes_of_vulnerabilities: Optional[str] = Field(default=None)
    vulnerabilities_github_repo_url: Optional[str] = Field(default=None)

    @field_validator("exclude", mode="before")
    def parse_exclude(cls, value: Union[str, List[str], None]) -> List[str]:
        if not value:
            return []
        if isinstance(value, list):
            return value
        return [s.strip() for s in value.split(",") if s.strip()]

    @field_validator("include", mode="before")
    def parse_include(cls, value: Union[str, List[str], None]) -> List[str]:
        if not value:
            return []
        if isinstance(value, list):
            return value
        return [s.strip() for s in value.split(",") if s.strip()]

    @field_validator("filter_keywords", mode="before")
    def parse_filter_keywords(cls, value: Union[str, Set[str], None]) -> Set[str]:
        if not value:
            return set()
        if isinstance(value, set):
            return value
        return {s.strip() for s in value.split(",") if s.strip()}
