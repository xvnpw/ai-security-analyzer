import argparse
import logging
import sys

from ai_security_analyzer.agent_builder import AgentBuilder
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.graphs import GraphExecutorFactory
from ai_security_analyzer.llms import LLMProvider

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool, debug: bool) -> None:
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    if debug:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
    elif verbose:
        logging.basicConfig(level=logging.INFO, format=log_format)
    else:
        logging.basicConfig(level=logging.WARNING)


def parse_arguments() -> AppConfig:
    """Parse command-line arguments and return an AppConfig instance."""
    parser = argparse.ArgumentParser(description="AI Create Security Repository Document")

    # Input/Output arguments
    io_group = parser.add_argument_group("Input/Output Options")
    io_group.add_argument(
        "-t",
        "--target-dir",
        required=True,
        help="Target directory containing the repository",
    )
    io_group.add_argument(
        "-p",
        "--project-type",
        choices=["python", "generic", "go", "java", "android"],
        default="python",
        help="Type of project (default: python)",
    )
    io_group.add_argument(
        "-o",
        "--output-file",
        type=argparse.FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="Output file for the security repository document (default: stdout)",
    )
    io_group.add_argument(
        "--exclude",
        help=(
            "Comma separated list of patterns that will be excluded from analysis. "
            "Pattern needs to be compatible with `fnmatch` (e.g. '**/prompts/**,LICENSE,*.png')"
        ),
    )
    io_group.add_argument(
        "--exclude-mode",
        choices=["add", "override"],
        default="add",
        help=(
            "Mode in which exclude argument will work. 'add' - provided exclude will be added to built-in list "
            "of excluded patterns. 'override' - provided exclude will override existing list of excluded patterns. "
            "(default: add)"
        ),
    )
    io_group.add_argument(
        "--include",
        help=(
            "Comma separated list of patterns that will be included from analysis. "
            "Pattern needs to be compatible with `glob` (e.g. '**/prompts/**,LICENSE,*.png')"
        ),
    )
    io_group.add_argument(
        "--include-mode",
        choices=["add", "override"],
        default="add",
        help=(
            "Mode in which include argument will work. 'add' - provided include will be added to built-in list "
            "of included patterns. 'override' - provided include will override existing list of included patterns. "
            "(default: add)"
        ),
    )
    io_group.add_argument(
        "--filter-keywords",
        help=(
            "Comma separated list of keywords. If used, only files that contain one of the keywords will be "
            "analyzed (default: not set)"
        ),
    )
    io_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run/ Will print configuration and list of files to analyze. No calls to LLMs",
    )

    # Logging arguments
    log_group = parser.add_argument_group("Logging Options")
    log_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    log_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    # Agent configuration
    agent_group = parser.add_argument_group("Agent Configuration")
    agent_group.add_argument(
        "--agent-provider",
        choices=["openai", "openrouter", "anthropic"],
        default="openai",
        help="LLM provider for the agent (default: openai)",
    )
    agent_group.add_argument(
        "--agent-model",
        default="gpt-4o",
        help="Model name for the agent (default: gpt-4o)",
    )
    agent_group.add_argument(
        "--agent-temperature",
        type=float,
        default=0,
        help="Sampling temperature for the agent model (default: 0)",
    )
    agent_group.add_argument(
        "--agent-preamble-enabled",
        action="store_true",
        help="Enable preamble in the output",
    )
    agent_group.add_argument(
        "--agent-preamble",
        default="##### (🤖 AI Generated)",
        help="Preamble added to the beginning of the output (default: '##### (🤖 AI Generated)')",
    )
    agent_group.add_argument(
        "--files-context-window",
        type=int,
        help=(
            "Size of window in tokens that can be used by files. By default, it's automatic and based on "
            "model context window"
        ),
    )
    agent_group.add_argument(
        "--files-chunk-size",
        type=int,
        help=(
            "Size of chunk in tokens that will be used to split files into chunks. By default, it's automatic "
            "and based on model context window"
        ),
    )
    agent_group.add_argument(
        "--agent-prompt-type",
        choices=["sec-design", "threat-modeling", "attack-surface", "threat-scenarios", "attack-tree"],
        default="sec-design",
        help="""Prompt to use in agent (default: sec-design):
 - sec-design - Security Design
 - threat-modeling - Threat Modeling
 - attack-surface - Attack Surface Analysis
 - threat-scenarios - Threat Scenarios
 - attack-tree - Attack Tree""",
    )

    # Editor configuration
    editor_group = parser.add_argument_group("Editor Configuration")
    editor_group.add_argument(
        "--editor-provider",
        choices=["openai", "openrouter", "anthropic"],
        default="openai",
        help="LLM provider for the editor (default: openai)",
    )
    editor_group.add_argument(
        "--editor-model",
        default="gpt-4o",
        help="Model name for the editor (default: gpt-4o)",
    )
    editor_group.add_argument(
        "--editor-temperature",
        type=float,
        default=0,
        help="Sampling temperature for the editor model (default: 0)",
    )
    editor_group.add_argument(
        "--editor-max-turns-count",
        type=int,
        default=3,
        help="Maximum number of turns in which the editor will try to fix broken markdown formatting (default: 3)",
    )
    editor_group.add_argument(
        "--node-path",
        help="Path to node binary (default: based on os)",
    )

    args = parser.parse_args()

    config = AppConfig(**vars(args))
    return config


def main() -> None:
    try:
        config = parse_arguments()
        setup_logging(config.verbose, config.debug)

        logger.info("Starting AI Security Analyzer")

        app(config)

        logger.info("AI Security Analyzer completed successfully")

    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)
    finally:
        # Ensure files are properly closed
        output_file = config.output_file if "config" in locals() else None
        if output_file and output_file is not sys.stdout and not output_file.closed:
            output_file.close()


def app(config: AppConfig) -> None:
    llm_provider = LLMProvider(config)
    agent_builder = AgentBuilder(llm_provider, config)
    agent = agent_builder.build()
    graph = agent.build_graph()

    executor = GraphExecutorFactory.create(config)
    executor.execute(graph, config.target_dir)


if __name__ == "__main__":
    main()
