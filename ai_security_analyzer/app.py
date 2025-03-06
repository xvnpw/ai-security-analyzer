import argparse
import logging
import sys
import os

from ai_security_analyzer.agent_builder import AgentBuilder
from ai_security_analyzer.config import AppConfig
from ai_security_analyzer.graphs import GraphExecutorFactory
from ai_security_analyzer.llms import LLMProvider
from ai_security_analyzer.checkpointing import CheckpointManager
from ai_security_analyzer.prompts.prompt_manager import PromptManager

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
    parser = argparse.ArgumentParser(
        description="AI Security Analyzer - A tool that leverages AI to automatically generate comprehensive security documentation for your projects"
    )

    parser.add_argument(
        "mode",
        choices=["dir", "github", "file"],
        help=(
            "Operation mode: "
            "'dir' to analyze a local directory (will send all files from directory to LLM), "
            "'github' to analyze a GitHub repository (will use model knowledge base to generate documentation), "
            "'file' to analyze a single file"
        ),
    )

    # Input/Output arguments
    io_group = parser.add_argument_group("Input/Output Options")
    io_group.add_argument(
        "-t",
        "--target",
        required=True,
        help=(
            "Target based on mode: "
            "Directory path for 'dir' mode, "
            "GitHub repository URL (must start with 'https://github.com/') for 'github' mode, "
            "or file path for 'file' mode"
        ),
    )
    io_group.add_argument(
        "-p",
        "--project-type",
        choices=["python", "generic", "go", "java", "android", "javascript"],
        default="python",
        help="Type of project (python, generic, go, java, android, javascript). Default is python",
    )
    io_group.add_argument(
        "-o",
        "--output-file",
        type=argparse.FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="Output file for the security documentation. Default is stdout",
    )
    io_group.add_argument(
        "--exclude",
        help=(
            "Comma-separated list of patterns to exclude from analysis using python glob patterns "
            "(e.g., 'LICENSE,**/tests/**')"
        ),
    )
    io_group.add_argument(
        "--exclude-mode",
        choices=["add", "override"],
        default="add",
        help=(
            "How to handle the exclude patterns ('add' to add to default excludes, "
            "'override' to replace). Default is add"
        ),
    )
    io_group.add_argument(
        "--include",
        help=(
            "Comma-separated list of patterns to include in the analysis using python glob patterns "
            "(e.g., '**/*.java')"
        ),
    )
    io_group.add_argument(
        "--include-mode",
        choices=["add", "override"],
        default="add",
        help=(
            "How to handle the include patterns ('add' to add to default includes, "
            "'override' to replace). Default is add"
        ),
    )
    io_group.add_argument(
        "--filter-keywords",
        help="Comma-separated list of keywords. Only files containing these keywords will be analyzed",
    )
    io_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run. Prints configuration and list of files to analyze without making API calls",
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
        choices=["openai", "openrouter", "anthropic", "google"],
        default="openai",
        help="LLM provider for the agent (openai, openrouter, anthropic, google). Default is openai",
    )
    agent_group.add_argument(
        "--agent-model",
        default="gpt-4o",
        help="Model name for the agent. Default is gpt-4o",
    )
    agent_group.add_argument(
        "--agent-temperature",
        type=float,
        default=0,
        help="Sampling temperature for the agent model (between 0 and 1). Default is 0",
    )
    agent_group.add_argument(
        "--secondary-agent-provider",
        choices=["openai", "openrouter", "anthropic", "google"],
        default=None,
        help="LLM provider for the secondary agent (openai, openrouter, anthropic, google). Default is None",
    )
    agent_group.add_argument(
        "--secondary-agent-model",
        default=None,
        help="Model name for the secondary agent. Default is None",
    )
    agent_group.add_argument(
        "--secondary-agent-temperature",
        type=float,
        default=None,
        help="Sampling temperature for the secondary agent model (between 0 and 1). Default is None",
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
        "--agent-prompt-type",
        choices=[
            "sec-design",
            "threat-modeling",
            "attack-surface",
            "attack-tree",
            "mitigations",
            "vulnerabilities",
            "vulnerabilities-workflow-1",
            "vulnerabilities-workflow-2",
        ],
        default="sec-design",
        help=(
            "Prompt to use in agent (default: sec-design):\n"
            " - sec-design: Generate a security design document for the project\n"
            " - threat-modeling: Perform threat modeling for the project\n"
            " - attack-surface: Perform attack surface analysis for the project\n"
            " - attack-tree: Perform attack tree analysis for the project\n"
            " - mitigations: Perform mitigation strategies analysis for the project\n"
            " - vulnerabilities: Perform vulnerabilities analysis for the project (read more about this mode in README.md)\n"
            " - vulnerabilities-workflow-1: Perform vulnerabilities analysis for the project using a workflow-based approach\n"
            " - vulnerabilities-workflow-2: Perform vulnerabilities analysis for the project using a workflow-based approach\n"
        ),
    )
    agent_group.add_argument(
        "--refinement-count",
        type=int,
        default=0,
        help=(
            "Number of iterations to refine the generated documentation (default: 0). "
            "Higher values may produce more detailed and polished output but will increase token usage. "
            "For 'file' mode only"
        ),
    )
    agent_group.add_argument(
        "--files-context-window",
        type=int,
        help="Maximum token size for LLM context window. Automatically determined if not set",
    )
    agent_group.add_argument(
        "--files-chunk-size",
        type=int,
        help="Chunk size in tokens for splitting files. Automatically determined if not set",
    )
    agent_group.add_argument(
        "--deep-analysis",
        action="store_true",
        help="Enable experimental deep analysis for 'github' modIe (only supported by Gemini 2.0 Flash Thinking Experimental model)",
    )
    agent_group.add_argument(
        "--recursion-limit",
        type=int,
        default=35,
        help="Graph recursion limit. Default is 35",
    )
    agent_group.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high"],
        help="Reasoning effort for the agent (only for reasoning models, e.g. o1). Default is None",
    )

    vulnerabilities_group = parser.add_argument_group("Vulnerabilities Workflows Options")
    vulnerabilities_group.add_argument(
        "--vulnerabilities-iterations",
        type=int,
        default=3,
        help="Number of iterations to perform for vulnerabilities workflow (default: 3)",
    )
    vulnerabilities_group.add_argument(
        "--vulnerabilities-severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Severity threshold for vulnerabilities workflow (default: high)",
    )
    vulnerabilities_group.add_argument(
        "--vulnerabilities-threat-actor",
        choices=["none", "external_web", "vscode_extension", "vscode_extension_malicious_repo"],
        default="external_web",
        help="Threat actor for vulnerabilities workflow (default: external_web)",
    )
    vulnerabilities_group.add_argument(
        "--vulnerabilities-output-dir",
        default="vulnerabilities-workflow",
        help="Directory to store intermediate data for vulnerabilities workflow. Default is `vulnerabilities-workflow`",
    )
    vulnerabilities_group.add_argument(
        "--included-classes-of-vulnerabilities",
        help="Comma-separated list of classes of vulnerabilities to include in the vulnerabilities workflow. Default is all classes of vulnerabilities. Cannot be used with --excluded-classes-of-vulnerabilities",
    )
    vulnerabilities_group.add_argument(
        "--excluded-classes-of-vulnerabilities",
        help="Comma-separated list of classes of vulnerabilities to exclude in the vulnerabilities workflow. Default is empty. Cannot be used with --included-classes-of-vulnerabilities",
    )
    vulnerabilities_group.add_argument(
        "--vulnerabilities-github-repo-url",
        help="GitHub repository URL to use for vulnerabilities workflow. Default is None",
    )

    # Checkpointing arguments
    checkpoint_group = parser.add_argument_group("Checkpointing Options")
    checkpoint_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last checkpoint if available",
    )
    checkpoint_group.add_argument(
        "--clear-checkpoints",
        action="store_true",
        help="Clear existing checkpoints before starting",
    )
    checkpoint_group.add_argument(
        "--checkpoint-dir",
        default=".checkpoints",
        help="Directory to store checkpoints. Default is .checkpoints",
    )

    args = parser.parse_args()

    # Validate secondary agent arguments
    secondary_agent_args = [args.secondary_agent_provider, args.secondary_agent_model, args.secondary_agent_temperature]
    if any(secondary_agent_args) and not all(secondary_agent_args):
        parser.error(
            "If any secondary agent argument is provided (--secondary-agent-provider, "
            "--secondary-agent-model, --secondary-agent-temperature), all must be provided"
        )

    # Validate target based on mode
    if args.mode == "dir" and not os.path.isdir(args.target):
        parser.error("In 'dir' mode, target must be a valid directory path")
    elif args.mode == "file" and not os.path.isfile(args.target):
        parser.error("In 'file' mode, target must be a valid file path")
    elif args.mode == "github" and not args.target.startswith("https://github.com/"):
        parser.error(
            "In 'github' mode, target must be a valid GitHub repository URL starting with 'https://github.com/'"
        )

    # Mode-specific argument validations
    if args.deep_analysis and args.mode != "github":
        parser.error("--deep-analysis is only available in 'github' mode")

    if args.dry_run and args.mode not in ("dir"):
        parser.error("--dry-run is only available in 'dir' mode")

    # Validate vulnerabilities workflow arguments
    if args.included_classes_of_vulnerabilities and args.excluded_classes_of_vulnerabilities:
        parser.error(
            "--included-classes-of-vulnerabilities and --excluded-classes-of-vulnerabilities cannot be used together"
        )

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
        logger.error(f"Application error: {e}. You can try to run with --resume to resume from last checkpoint.")
        sys.exit(1)
    finally:
        # Ensure files are properly closed
        output_file = config.output_file if "config" in locals() else None
        if output_file and output_file is not sys.stdout and not output_file.closed:
            output_file.close()


def app(config: AppConfig) -> None:
    llm_provider = LLMProvider(config)

    with CheckpointManager(config) as checkpoint_manager:
        checkpoint_manager.check_resume()

        prompt_manager = PromptManager()
        agent_builder = AgentBuilder(llm_provider, checkpoint_manager, config, prompt_manager)
        agent = agent_builder.build()
        graph = agent.build_graph()

        executor = GraphExecutorFactory.create(config)
        executor.execute(graph, config.target)
        checkpoint_manager.clear_current_checkpoint()


if __name__ == "__main__":
    main()
