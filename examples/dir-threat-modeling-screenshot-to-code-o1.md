APPLICATION THREAT MODEL

ASSETS
- User-provided images and videos (screenshots, screen recordings). These contain potentially sensitive or proprietary design information.
- Generated code (HTML, CSS, React, Vue, etc.). This is the primary output that users want to protect from tampering or unauthorized access.
- API keys (OpenAI, Anthropic, Replicate, etc.). Stored in environment variables or provided by users; they must be protected from leaks or theft.
- User credentials or tokens (e.g. if user authentication is implemented, or if stored in the front-end for future expansions).
- System logs and debug information (including possible references to user data or partial codes).

TRUST BOUNDARIES
- User browser to front-end application.
- Front-end application to FastAPI backend.
- Backend to external AI/LLM services (OpenAI, Anthropic, Replicate).
- Docker container boundary (when using Docker for local or production).
- Environment variable boundary, where sensitive keys are stored separate from code.

DATA FLOWS
- User uploads image or video from the browser to the front-end.
- Front-end sends uploaded files (or data URLs) to the backend for processing.
- Backend calls external LLM APIs (OpenAI, Anthropic) to generate code or interpret images if needed.
- Backend optionally calls an image generation service (Replicate or OpenAI DALL-E) for placeholders or additional outputs.
- Code outputs are returned from the LLM to the backend and then streamed to the front-end.
- Front-end displays or downloads the generated code for the user.
- Environment variables with API keys are read at backend startup or assigned interactively in the front-end’s settings (and passed to the backend).

APPLICATION THREATS
- Threat: Injection of malicious code through user-supplied screenshots or text prompts.
  Description: An attacker could embed malicious payloads in images (e.g. specially crafted metadata) or in text fields. If the system fails to sanitize or handle them securely, it could lead to code injection, XSS, or app compromise.
  Impact: Potential unauthorized code execution, defacing the generated code, or harming internal systems.
  Affected Component: Image/file handling functions, user prompt processing modules.
  Current Mitigations: The code uses Python libraries (Pillow, moviepy) that likely parse images safely. No direct code execution from user text is apparent.
  Missing Mitigations: Add thorough validation of user-supplied data. Scan metadata in images, ensure text prompts do not directly inject into the final code without escaping.
  Risk Severity: High

- Threat: Unauthorized access or tampering with API keys in environment variables.
  Description: If environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY) are leaked (e.g. through logs or misconfiguration), attackers can make calls to LLMs at the project’s expense or with the project’s privileges.
  Impact: Unauthorized usage of services, financial cost to the project owners, or data leakage if the keys allow sensitive functionality.
  Affected Component: Environment variables, config.py, .env files.
  Current Mitigations: The code does store them in .env, which is typically not stored in version control.
  Missing Mitigations: Enforce environment variable encryption or secrets management (Vault, Docker secrets, etc.). Restrict logging of environment variables.
  Risk Severity: High

- Threat: Sensitive user content stored in logs or error messages.
  Description: The app’s debug or logs might store base64 data from images or partial code. If logs are shared or not properly protected, sensitive user design data could be exposed.
  Impact: Disclosure of user’s private design or system code.
  Affected Component: Debug logging (DEBUG_DIR usage), logs in fs_logging, debug mode in config.
  Current Mitigations: Debug logs are stored locally, optional toggles for debug mode.
  Missing Mitigations: Clarify retention policies, restrict logging of user data, provide user notice.
  Risk Severity: Medium

- Threat: Unauthenticated or unvalidated requests.
  Description: Backend routes (e.g. /generate-code) may be open to all. Attackers can flood requests or attempt to exploit endpoints.
  Impact: Possible DoS or misuse leading to large bills or system overutilization.
  Affected Component: FastAPI backend routes for code generation, image generation, evaluation endpoints.
  Current Mitigations: None apparent aside from standard Python web server function. There is no mention of rate limiting or authentication for these endpoints.
  Missing Mitigations: Implement rate limiting or require API tokens for certain endpoints.
  Risk Severity: Medium

- Threat: Malicious or oversized videos for video processing.
  Description: Attackers could upload large or corrupted videos, leading to resource exhaustion or security vulnerabilities in video libraries.
  Impact: Potential DoS, local file system exhaustion, or memory issues.
  Affected Component: video_to_app.py, moviepy usage.
  Current Mitigations: Partial checks for file dimension or size in code (resizing images for Claude).
  Missing Mitigations: Implement file size checks, timeouts, dedicated scanning, or sandboxing.
  Risk Severity: Medium

- Threat: Cross-Origin Resource Sharing misconfiguration.
  Description: The backend includes CORS middleware that allows "*" for allow_origins. Arbitrary hosts could interact with the backend.
  Impact: Potential unauthorized usage of the backend from unknown domains.
  Affected Component: main.py (CORS middleware).
  Current Mitigations: The code sets allow_origins=["*"], simplifying cross-domain usage.
  Missing Mitigations: If more access control is needed, the list of allowed origins should be restricted.
  Risk Severity: Low

DEPLOYMENT THREAT MODEL

ASSETS
- Docker containers and images that run the front-end and backend.
- Deployment environment variables and .env files in production.
- Container registry or build artifacts (if pushing images to a public or private registry).
- Host system or cloud environment where containers run.

TRUST BOUNDARIES
- The Docker daemon boundary on the host system.
- The interface between containers (backend, frontend, possibly separate for load balancers).
- The external cloud environment vs. local environment (in case of cloud hosting).
- The external environment where environment variables and .env files live.

DEPLOYMENT THREATS
- Threat: Insecure Docker container configuration.
  Description: If containers run as root, or no resource limitations are set, an attacker that compromises the container can escalate privileges or move to the host.
  Impact: Container breakout, compromise of host.
  Affected Component: Dockerfiles, docker-compose.yml.
  Current Mitigations: Minimal base images (python:3.12.3-slim, node:22-bullseye-slim) are used.
  Missing Mitigations: Drop privileges in the container, set read-only filesystems, use Docker user.
  Risk Severity: High

- Threat: Networking misconfiguration.
  Description: If ports are exposed publicly without firewall rules, malicious actors can directly interact with services.
  Impact: Unauthorized usage, scanning, possible exploit of known endpoints.
  Affected Component: docker-compose.yml port mappings.
  Current Mitigations: Default using "ports", might rely on local usage or an external firewall.
  Missing Mitigations: Strict firewall rules or restricted port mappings if deploying to production.
  Risk Severity: Medium

- Threat: Credentials or .env left in Docker images.
  Description: Hard-coded environment variables might remain in final container images if not properly excluded.
  Impact: Exposure of secrets if the built image is published.
  Affected Component: Dockerfiles, .env, environment variables.
  Current Mitigations: The instructions mention ignoring .env, but no explicit mention of scanning final images.
  Missing Mitigations: Check final images, ensure secrets are not baked in.
  Risk Severity: High

- Threat: Logs and debug artifacts in production container.
  Description: Debug logs or large logs can fill containers, or leak data if accessible.
  Impact: Container or host disk exhaustion, data leaks.
  Affected Component: Docker containers.
  Current Mitigations: None specifically in the Docker config.
  Missing Mitigations: Regular log rotation or minimal logging in production.
  Risk Severity: Medium

BUILD THREAT MODEL

ASSETS
- Source code repository (local or remote).
- Dockerfiles, docker-compose.yml used for building.
- CI/CD secrets if using an automated pipeline (GitHub Actions, Jenkins, etc.).
- Test data, including images and scripts in the evals folder.

TRUST BOUNDARIES
- Source code repository boundary (potentially multiple contributors).
- CI environment or local build environment, which pulls code and dependencies.
- External package registries (PyPI, npm) from which dependencies are installed.
- Docker registry (if images are pushed or pulled).

BUILD THREATS
- Threat: Supply chain attacks on dependencies (PyPI, npm).
  Description: Malicious package versions could escalate or inject code in the build pipeline.
  Impact: System compromise, malicious code injection.
  Affected Component: Poetry dependencies in pyproject.toml, yarn dependencies in frontend.
  Current Mitigations: No mention of lockfile scanning or pinned dependencies.
  Missing Mitigations: Regular scanning with SCA tools, pin major versions, use well-known mirrors or pinned artifacts.
  Risk Severity: High

- Threat: Unauthorized commits or merges in the repository.
  Description: Attackers or malicious insiders push tampered code that exfiltrates API keys or manipulates build.
  Impact: Compromise of the entire application.
  Affected Component: Source code repo.
  Current Mitigations: None described beyond typical GitHub collaboration.
  Missing Mitigations: Enforce branch protection, code review, role-based access.
  Risk Severity: Medium

- Threat: Insecure build configuration with Docker.
  Description: Docker build steps might expose environment variables or inject them insecurely.
  Impact: Potential secrets leak, accidental logging of sensitive data.
  Affected Component: Dockerfiles, build environment.
  Current Mitigations: Using separate .env files is recommended, but possibly not enforced.
  Missing Mitigations: Clear separation of stages, scanning final images for secrets, restricting environment variable usage.
  Risk Severity: Medium

- Threat: Lack of SAST/DAST or linting in build pipeline.
  Description: Security bugs can persist if no automated scanning or linting is performed.
  Impact: Potential release of vulnerable code.
  Affected Component: Build pipeline or CI (poetry run pyright, pytest).
  Current Mitigations: There is a mention of pyright, pytest.
  Missing Mitigations: Automated security scans (SAST), container scanning for vulnerabilities.
  Risk Severity: Low

QUESTIONS & ASSUMPTIONS
- Does the application intend to allow unauthenticated usage? Assumed yes, which exposes it to potential abuse.
- Are environment variables stored securely outside of the source repo in all deployment scenarios? Assumed best practice.
- No mention of encryption at rest for logs or user data. We assume ephemeral usage, but if needed, encryption might be mandatory.
- Are rate limits or usage monitoring used for the code generation endpoints? Not clearly stated.
- We assume users are not storing or retrieving replays of previously uploaded images after the generation is complete.
- We assume that build is performed in a controlled environment (local or private CI) that is restricted to trusted contributors.

This concludes the threat model for the current state of the screenshot-to-code system and its build/deployment. The above threats may be refined or expanded based on additional context about runtime environment, hosting location, or user authentication requirements.
