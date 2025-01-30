import argparse
import logging
import sys
from typing import TextIO

from fabric_agent_action.agents import AgentBuilder
from fabric_agent_action.config import AppConfig
from fabric_agent_action.fabric_tools import FabricTools
from fabric_agent_action.graphs import GraphExecutorFactory
from fabric_agent_action.llms import LLMProvider

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool, debug: bool) -> None:
    """Configure logging based on verbosity levels"""
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    elif verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    else:
        logging.basicConfig(level=logging.WARNING)


def read_input(input_file: TextIO) -> str:
    """Read input from file or stdin with proper error handling"""
    try:
        return input_file.read()
    except (KeyboardInterrupt, EOFError):
        logger.error("Input reading interrupted")
        raise SystemExit("No input provided. Exiting.")
    except Exception as e:
        logger.error(f"Error reading input: {e}")
        raise


def parse_arguments() -> AppConfig:
    """Parse command line arguments and return AppConfig"""
    logger.debug("Setting up argument parser...")

    parser = argparse.ArgumentParser(description="Fabric Agent Action CLI")

    # Input/Output arguments
    io_group = parser.add_argument_group("Input/Output Options")
    io_group.add_argument(
        "-i",
        "--input-file",
        type=argparse.FileType("r"),
        required=True,
        help="Input file",
    )
    io_group.add_argument(
        "-o",
        "--output-file",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="Output file (default: stdout)",
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
        type=str,
        choices=["openai", "openrouter", "anthropic"],
        default="openai",
        help="LLM provider for agent (default: openai)",
    )
    agent_group.add_argument(
        "--agent-model",
        type=str,
        default="gpt-4o",
        help="Model name for agent (default: gpt-4o)",
    )
    agent_group.add_argument(
        "--agent-temperature",
        type=float,
        default=0,
        help="Sampling temperature for agent model (default: 0)",
    )
    agent_group.add_argument(
        "--agent-type",
        type=str,
        choices=["router", "react", "react_issue", "react_pr"],
        default="router",
        help="Type of agent (default: router)",
    )
    agent_group.add_argument(
        "--agent-preamble-enabled",
        action="store_true",
        help="Enable preamble in output",
    )
    agent_group.add_argument(
        "--agent-preamble",
        type=str,
        default="##### (🤖 AI Generated)",
        help="Preamble added to the beginning of output (default: ##### (🤖 AI Generated)",
    )

    # Fabric configuration
    fabric_group = parser.add_argument_group("Fabric Configuration")
    fabric_group.add_argument(
        "--fabric-provider",
        type=str,
        choices=["openai", "openrouter", "anthropic"],
        default="openai",
        help="LLM provider for fabric (default: openai)",
    )
    fabric_group.add_argument(
        "--fabric-model",
        type=str,
        default="gpt-4o",
        help="Model name for fabric (default: gpt-4o)",
    )
    fabric_group.add_argument(
        "--fabric-temperature",
        type=float,
        default=0,
        help="Sampling temperature for fabric model (default: 0)",
    )
    fabric_group.add_argument(
        "--fabric-patterns-included",
        type=str,
        default="",
        help="Comma separated list of fabric patterns to include in agent",
    )
    fabric_group.add_argument(
        "--fabric-patterns-excluded",
        type=str,
        default="",
        help="Comma separated list of fabric patterns to exclude in agent",
    )
    fabric_group.add_argument(
        "--fabric-max-num-turns",
        type=int,
        default=10,
        help="Maximum number of turns to LLM when running fabric patterns (default: 10)",
    )

    args = parser.parse_args()

    config = AppConfig(**vars(args))

    return config


def main() -> None:
    try:
        config = parse_arguments()
        setup_logging(config.verbose, config.debug)

        logger.info("Starting Fabric Agent Action")

        app(config)

        logger.info("Fabric Agent Action completed successfully")

    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)
    finally:
        # Ensure files are properly closed
        if "config" in locals():
            if config.input_file and config.input_file is not sys.stdin:
                config.input_file.close()
            if config.output_file and config.output_file is not sys.stdout:
                config.output_file.close()


def app(config: AppConfig) -> None:
    input_str = read_input(config.input_file)

    llm_provider = LLMProvider(config)
    fabric_llm = llm_provider.createFabricLLM()
    fabric_tools = FabricTools(
        fabric_llm.llm,
        fabric_llm.use_system_message,
        fabric_llm.max_number_of_tools,
        config.fabric_patterns_included,
        config.fabric_patterns_excluded,
    )

    agent_builder = AgentBuilder(config.agent_type, llm_provider, fabric_tools)
    graph = agent_builder.build()

    executor = GraphExecutorFactory.create(config)
    executor.execute(graph, input_str)


if __name__ == "__main__":
    main()
