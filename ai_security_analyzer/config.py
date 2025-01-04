import io
import logging
from typing import List, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing_extensions import Literal

from ai_security_analyzer.utils import find_node_binary

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

    agent_prompt_type: Literal["sec-design", "threat-modeling", "attack-surface", "threat-scenarios", "attack-tree"] = (
        Field(default="sec-design")
    )
    agent_provider: Literal["openai", "openrouter", "anthropic", "google"] = Field(default="openai")
    agent_model: str = Field(default="gpt-4o")
    agent_temperature: float = Field(default=0, ge=0, le=1)
    agent_preamble_enabled: bool = Field(default=False)
    agent_preamble: str = Field(default="##### (🤖 AI Generated)")
    deep_analysis: bool = Field(default=False)
    recursion_limit: int = Field(default=30)

    editor_provider: Literal["openai", "openrouter", "anthropic", "google"] = Field(default="openai")
    editor_model: str = Field(default="gpt-4o")
    editor_temperature: float = Field(default=0, ge=0, le=1)
    editor_max_turns_count: int = Field(default=3, ge=0)

    exclude: Optional[List[str]] = Field(default=None)
    exclude_mode: Literal["add", "override"] = Field(default="add")
    include: Optional[List[str]] = Field(default=None)
    include_mode: Literal["add", "override"] = Field(default="add")
    filter_keywords: Optional[Set[str]] = Field(default=None)
    files_context_window: Optional[int] = Field(default=None)
    files_chunk_size: Optional[int] = Field(default=None)
    dry_run: bool = Field(default=False)
    node_path: str
    refinement_count: int = Field(default=1)

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

    @field_validator("node_path", mode="before")
    def parse_node_path(cls, value: Union[str, None]) -> Union[str, None]:
        if not value:
            node_binary = find_node_binary()
            if not node_binary:
                logger.warning("Node.js binary not found. Editor will be disabled.")
            return node_binary
        return value
