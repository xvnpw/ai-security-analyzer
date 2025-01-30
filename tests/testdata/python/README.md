<div align="center">

# Fabric Agent Action

[![CI](https://github.com/xvnpw/fabric-agent-action/actions/workflows/ci.yaml/badge.svg)](https://github.com/xvnpw/fabric-agent-action/actions/workflows/ci.yaml)
[![GitHub release](https://img.shields.io/github/release/xvnpw/fabric-agent-action.svg)](https://github.com/xvnpw/fabric-agent-action/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<img src="./images/logo.webp" alt="logo" width="200" height="200"/>

🤖 **Fabric Agent Action** is a GitHub Action that leverages [Fabric Patterns](https://github.com/danielmiessler/fabric/tree/main/patterns) to automate complex workflows using an agent-based approach. Built with [LangGraph](https://www.langchain.com/langgraph), it intelligently selects and executes patterns using Large Language Models (LLMs).

**🎥 Demo:**

<img src="./images/demo.gif" alt="demo" />

▶️ Watch full demo on [Loom](https://www.loom.com/share/a205012295de4b2b93e3ea2503763c8d?sid=c117b055-0bd6-41e4-84be-d5fc1b71f28d)

</div>

## Features

✨ **Key Capabilities:**

- **Seamless Integration:** Easily incorporate the action into your existing workflows without additional setup.
- **Multi-Provider Support:** Choose between OpenAI, OpenRouter, or Anthropic based on your preference and availability.
- **Configurable Agent Behavior:** Select agent types (`router`, `react`, `react_issue`, or `react_pr`) and customize their behavior to suit your workflow needs.
- **Flexible Pattern Management:** Include or exclude specific Fabric Patterns to optimize performance and comply with model limitations.

## Quick Start

To add the Fabric Agent Action to your workflow, reference it in your workflow `.yaml` file:

```yaml
- name: Execute Fabric Agent Action
  uses: xvnpw/fabric-agent-action@v1  # or docker://ghcr.io/xvnpw/fabric-agent-action:v1 to avoid action rebuild on each run
  with:
    input_file: path/to/input.md
    output_file: path/to/output.md
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

**Set Environment Variables:** Ensure you set the required API keys in your repository's secrets.

## Configuration

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `input_file` | **Required** Source file containing input and agent instructions | |
| `output_file` | **Required** Destination file for pattern results | |
| `verbose` | Enable INFO level logging | `false` |
| `debug` | Enable DEBUG level logging | `false` |
| `agent_type` | Agent behavior model (`router`/`react`/`react_issue`/`react_pr`) | `router` |
| `agent_provider` | LLM provider for agent (`openai`/`openrouter`/`anthropic`) | `openai` |
| `agent_model` | Model name for agent | `gpt-4o` |
| `agent_temperature` | Model creativity (0-1) for agent | `0` |
| `agent_preamble_enabled` | Enable preamble in output | `false` |
| `agent_preamble` | Preamble added to the beginning of output | `##### (🤖 AI Generated)` |
| `fabric_provider` | Pattern execution LLM provider | `openai` |
| `fabric_model` | Pattern execution LLM model | `gpt-4o` |
| `fabric_temperature` | Pattern execution creativity (0-1) | `0` |
| `fabric-patterns-included` | Patterns to include (comma-separated). **Required for models with pattern limits (e.g., `gpt-4o`).** | |
| `fabric-patterns-excluded` | Patterns to exclude (comma-separated) | |
| `fabric_max_num_turns` | Maximum number of turns to LLM when running fabric patterns | 10 |

> **Note:** Models like `gpt-4o` have a limit on the number of tools (128), while Fabric currently includes 175 patterns (as of November 2024). Use `fabric_patterns_included` or `fabric_patterns_excluded` to tailor the patterns used. For access to all patterns without tool limits, consider using `claude-3-5-sonnet-20240620`.

Find the list of available Fabric Patterns [here](https://github.com/danielmiessler/fabric/tree/main/patterns).

### Required Environment Variables

Set one of the following API keys:

- `OPENAI_API_KEY`
- `OPENROUTER_API_KEY`
- `ANTHROPIC_API_KEY`

## Usage Examples

This action is flexible in workflow integration and can be used on issues, pushes, pull requests, etc.

### Issue Comments - Created or Edited

Below is an example of how to integrate the Fabric Agent Action into a GitHub Actions workflow that reacts to issue comments.

**Github Workflow:**

```yaml
name: Fabric Pattern Processing using ReAct Issue Agent
on:
  issue_comment:
    types: [created, edited]

jobs:
  process_fabric:
    if: >
      github.event.comment.user.login == github.event.repository.owner.login &&
      startsWith(github.event.comment.body, '/fabric') &&
      !github.event.issue.pull_request
    runs-on: ubuntu-latest
    permissions:
      issues: write
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Prepare Input
        uses: actions/github-script@v7
        id: prepare-input
        with:
          script: |
            const issue = await github.rest.issues.get({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo
            });

            const comment = await github.rest.issues.getComment({
              comment_id: context.payload.comment.id,
              owner: context.repo.owner,
              repo: context.repo.repo
            });

            // Get all comments for this issue to include in the output
            const comments = await github.rest.issues.listComments({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo
            });

            // Extract command from the triggering comment
            const command = comment.data.body;

            let output = `INSTRUCTION:\n${command}\n\n`;

            // Add issue information
            output += `GITHUB ISSUE, NR: ${issue.data.number}, AUTHOR: ${issue.data.user.login}, TITLE: ${issue.data.title}\n`;
            output += `${issue.data.body}\n\n`;

            // Add all comments
            for (const c of comments.data) {
              if (c.id === comment.data.id) {
                break;
              }
              output += `ISSUE COMMENT, ID: ${c.id}, AUTHOR: ${c.user.login}\n`;
              output += `${c.body}\n\n`;
            }

            require('fs').writeFileSync('fabric_input.md', output);

            return output;

      - name: Execute Fabric Patterns
        uses: docker://ghcr.io/xvnpw/fabric-agent-action:v1
        with:
          input_file: "fabric_input.md"
          output_file: "fabric_output.md"
          agent_type: "react_issue"
          fabric_temperature: 0.2
          fabric_patterns_included: "clean_text,create_stride_threat_model,create_design_document,review_design,refine_design_document,create_threat_scenarios,improve_writing,create_quiz,create_summary"
          debug: true
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}

      - name: Post Results
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: ${{ github.event.issue.number }}
          body-path: fabric_output.md
```

In this workflow:

- The job runs only when:
  - The comment starts with `/fabric`.
  - The comment author is the repository owner.
  - The issue is not a pull request.
- This prevents unauthorized users from triggering the action, avoiding excessive API usage or costs.

## License

This project is licensed under the [MIT License](LICENSE).
