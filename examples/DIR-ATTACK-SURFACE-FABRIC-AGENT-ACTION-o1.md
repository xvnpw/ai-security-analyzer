# Attack Surface Analysis for "fabric-agent-action"

## Attack Surface Identification

1. GitHub Action Workflow Interface
   • The action is triggered by GitHub events (push, pull_request, issue_comment, etc.) and relies on YAML workflow configuration.
   • Inputs and environment variables (e.g., “input_file,” “output_file,” “agent_type,” “agent_model,” “OPENAI_API_KEY,” etc.) are passed to the Action.
   • Potential Vulnerability: Improper validation or sanitization of inputs in the YAML file or event payloads could allow malicious data processing.

2. Docker Container (ghcr.io/xvnpw/fabric-agent-action)
   • The action runs inside a Docker container.
   • No explicit networking instructions or EXPOSE directives are in the Dockerfile, so the container does not listen on a public port by default.
   • Potential Vulnerability: Unpatched system packages or Python dependencies could introduce remote code execution or local privilege escalation vulnerabilities within the container.

3. Environment Variables and Repository Secrets
   • “OPENAI_API_KEY,” “OPENROUTER_API_KEY,” “ANTHROPIC_API_KEY,” and optional “LANGCHAIN_API_KEY” (for LangSmith) are used for external LLM providers.
   • GitHub repository secrets are used to supply these tokens.
   • Potential Vulnerability: Accidental logging or exposure of secrets if debug logs are not carefully handled or if a misconfiguration occurs.

4. External LLM Provider Integrations
   • The system makes outgoing calls to the configured provider’s API (OpenAI, OpenRouter, Anthropic) using the provided API keys.
   • Potential Vulnerability: An attacker controlling the input could issue calls that leak sensitive data via prompt injection, or exploit errors in how request data is assembled.

5. Python Code and Dependencies
   • The system uses Python 3.11, Poetry, and various language-model libraries (langchain, anthropic, openai).
   • Potential Vulnerability: Dependencies may have unresolved security advisories (e.g., SSRF or RCE in one of the transitive dependencies), or supply-chain attacks in pinned/unpinned packages.

6. File-Based Input and Output
   • The Action reads from “INPUT_INPUT_FILE” and writes results to “INPUT_OUTPUT_FILE.”
   • Potential Vulnerability: Malicious content in the input file might trigger unexpected processing or injection attacks, especially if not sanitized before sending to an LLM or before writing the output file.

7. Logging / Debug Output
   • If debug mode is enabled, the application might print intermediate states.
   • Potential Vulnerability: Sensitive environment variables or partial API keys could be logged unintentionally and become visible in the GitHub Actions log.

Reference Implementation Details:
• action.yml (defines inputs, environment variables)
• entrypoint.sh (parses environment variables and executes app.py)
• fabric_agent_action/app.py (entry point, sets up configuration, logs data, orchestrates processing)
• fabric_agent_action/llms.py (provider logic for OpenAI/OpenRouter/Anthropic, references environment variables)
• Dockerfile (defines the container environment).

## Threat Enumeration

Below follows a sample enumeration using STRIDE:

1. Spoofing
   • An attacker might spoof GitHub event data or pretend to be the “repo.owner.”
   • Attack Vector: Malicious pull requests from forked repos or manipulated event payloads.
   • Target Component: Action logic checking “github.event.”
   • Condition Required: GitHub’s default permissions allow some workflow runs from forks if not explicitly restricted.

2. Tampering
   • Malicious modification of environment variables or external calls to LLM providers.
   • Attack Vector: If environment variables are overwritten in the workflow or if an attacker modifies code in the Docker image.
   • Target Component: Docker container’s runtime environment or the “entrypoint.sh” environment parser.

3. Repudiation
   • Insufficient logging of LLM calls could hamper auditing.
   • Attack Vector: An attacker triggers the Action in a way that logs are incomplete or manipulated.
   • Target Component: The logging framework (basic logging calls in app.py).

4. Information Disclosure
   • Sensitive secrets (API keys) might be leaked via debug logs or in LLM prompts.
   • Attack Vector: Debug logs or logs in GitHub Actions that store partial environment variables.
   • Target Component: Logging pipeline in the Docker container; the GitHub Action logs.

5. Denial of Service (DoS)
   • Excessive or malformed inputs (huge data, continuous triggers) could cause the Action to exceed GitHub runner resource limits or LLM usage quotas.
   • Attack Vector: Repeated triggers (pull requests, comments) or intentionally large input files to cause memory/time exhaustion.
   • Target Component: The container during Action execution; external LLM usage limits.

6. Elevation of Privilege
   • Arbitrary code execution inside the container if Python code or dependencies are exploited.
   • Attack Vector: Malicious input that triggers a vulnerability in the libraries, or prompt injection leading to unplanned code paths.
   • Target Component: The “fabric_tools” calls that pass user data to LLMs.

## Impact Assessment

• Confidentiality:
  – Exposure of environment variables (API keys) is critical.
  – Logging or returning keys within the LLM’s output would severely impact confidentiality.

• Integrity:
  – Tampered inputs or unauthorized merges could disrupt normal pipeline operation or produce incorrect design or threat modeling outputs.

• Availability:
  – Large input or repeated triggers could exhaust GitHub runner CPU/time or LLM API usage budgets.
  – Over-limit usage on external LLM providers can temporarily disrupt the Action.

• Severity Level
  – High/Critical: Database of secrets or an exploit that can run malicious code in the container.
  – Medium: Prompt injection or pipeline disruptions that cause erroneous or partial responses.
  – Low: Minor leaking of partial logs or non-sensitive data.

• Existing Controls
  – GitHub secrets store and environment scoping help prevent direct secrets exposure.
  – The code uses pinned dependencies in Poetry; Bandit, MyPy, Ruff checks help detect some vulnerabilities.
  – Access controls in GitHub workflows (conditions for PR from forks, comment author checks) reduce unauthorized runs.

## Threat Ranking

1. Disclosure of LLM API keys in Action logs — High
   – Frequent risk with debug logs or if returned in an LLM message.
   – Mitigation Priority: High

2. Prompt Injection or Malicious Input That Escalates to RCE in Dependencies — High
   – LLM tool calls might pass user content to Python code in unexpected ways.
   – Mitigation Priority: High

3. DoS from Overuse or Overly Large Inputs — Medium
   – Could run up usage costs or block the workflow.
   – Mitigation Priority: Medium

4. Manipulated Workflow Auth Checks (Fork PR not restricted) — Medium
   – Could allow unauthorized usage or partial secrets exposure.
   – Mitigation Priority: Medium

5. Minor Logging Leaks (e.g., partial environment variables) — Low
   – Typically partial, might not fully compromise the secret.
   – Mitigation Priority: Low

## Mitigation Recommendations

1. Enforce Strict Logged Data Policies
   – Avoid printing environment variables or secrets.
   – Run with debug mode disabled in production unless needed, and ensure logs do not include full API keys or sensitive data.

2. Validate/Restrict Input from External Events
   – Implement rigorous checks on PR sources (fork vs. same-repo) as recommended in the README.
   – Use conditions (e.g., “if: github.actor == 'authorized-username'”) and carefully structure the workflows to limit the possibility of injection or abuse from public forks.

3. Prompt Injection Protections
   – Consider sanitizing or bounding user-supplied input before passing it to LLM calls.
   – Log the presence of suspicious tokens or patterns that might instruct the system to reveal secrets.

4. Dependency Vulnerability Management
   – Keep Poetry dependencies, Docker base image, and system packages updated.
   – Periodically scan for CVEs in pinned versions.

5. Resource and Rate Limit Protective Measures
   – Set maximum input file size and usage constraints on the LLM calls.
   – Configure GitHub Action concurrency or usage limits to prevent runaway usage.

6. Workflow Security Hardening
   – Use GitHub recommended patterns for PR-based triggers, ensuring that external contributors cannot trigger cost-intensive steps by default.
   – Maintain separate workflows for authorized maintainers and external forks.

## QUESTIONS & ASSUMPTIONS

• Are any environment variables or partial logs redacted by default in debug mode? (Assumption: Possibly no; must sanitize manually.)
• Does the Docker container run with any elevated privileges or does it run as a non-root user? (Assumption: No explicit mention, likely root in official Alpine, but no open ports.)
• Is user input thoroughly sanitized before LLM usage? (Assumption: Currently minimal sanitization; risk of prompt injection remains.)
• Do we rely on any WAF or API gateway for external LLM calls? (Assumption: No, direct calls to provider endpoints.)
