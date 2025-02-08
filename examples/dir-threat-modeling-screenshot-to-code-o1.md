# APPLICATION THREAT MODEL

## ASSETS
- User-provided images and videos (input data for conversion)
- User-provided prompts or text descriptions sent to the backend
- Generated code artifacts returned to the user
- API keys for third-party services (OpenAI, Anthropic, Replicate) stored in environment variables or `.env` files
- Logs containing partial or full prompt/response data (including potential user data or system messages)

## TRUST BOUNDARIES
- User Client (untrusted) to Frontend (semi-trusted)
- Frontend (semi-trusted) to Backend (trusted boundary)
- Backend (trusted) to External AI services (untrusted boundary: OpenAI, Anthropic, Replicate)
- Backend (trusted) to External screenshot service (untrusted boundary: screenshotone API)
- Local environment secrets (trusted) vs. container or repository environment (outside actors untrusted)

## DATA FLOWS
- Flow 1: User provides screenshot or video → Frontend → Backend → (Potentially LLM) → Generated code → Frontend → User. (Crosses user-to-backend boundary and backend-to-LLM boundary)
- Flow 2: User triggers screenshot route → Backend calls external service screenshotone.com → returns image → stored/relayed to user. (Crosses backend-to-external-service boundary)
- Flow 3: User requests additional image generation → Backend calls Replicate or DALL-E → returns generated image → appended to final code or returned to user. (Crosses backend-to-third-party boundary)

## APPLICATION THREATS

- Threat: Malicious or malformed user image uploads
  - Description: Attackers could upload specially crafted images or videos (e.g. huge images, corrupt metadata) to exploit library parsing vulnerabilities or cause resource exhaustion.
  - Impact: May lead to server crashes, denial of service, or potential RCE if vulnerabilities in image parsing libraries are present.
  - Affected Component: Backend image/video processing (moviepy, PIL, etc.).
  - Current Mitigations: Limited checks for size constraints in some places (e.g. for Claude input), but not comprehensive.
  - Missing Mitigations: Strict file type validation, robust image sanitization, bounding resource usage for large images.
  - Risk Severity: Medium

- Threat: User-driven SSRF (Server-Side Request Forgery) via screenshot route
  - Description: Users can supply URLs that the backend tries to screenshot, potentially reaching internal endpoints or private services if not restricted.
  - Impact: Could expose internal services/data or pivot for internal network attacks.
  - Affected Component: screenshot route (screenshot.py) calling external screenshot API with user-supplied URLs.
  - Current Mitigations: None evident in code. The code calls external API directly with user URL.
  - Missing Mitigations: Strong URL validation or explicit blocklisting of internal IP ranges.
  - Risk Severity: High

- Threat: Malicious code generation prompt
  - Description: Attackers provide carefully crafted instructions that produce harmful or malicious code upon generation (e.g., XSS-laden HTML).
  - Impact: Generated code could cause security issues in other environments if the user or the system automatically deploys or executes it.
  - Affected Component: Code generation pipeline in the backend (llm.py, generate_code.py).
  - Current Mitigations: None explicitly. The system merely returns code to the user.
  - Missing Mitigations: Warning or safe rendering for returned code, disclaimers before usage, or optional code scanning in the pipeline.
  - Risk Severity: Medium

- Threat: Leakage of environment secrets
  - Description: If logs or error messages containing environment variables are exposed, attackers could retrieve API keys, leading to misuse of paid or sensitive services.
  - Impact: Attackers can exfiltrate keys, run up costs, or pivot for further compromise of user data.
  - Affected Component: Logging system, environment variable usage in Docker/.env.
  - Current Mitigations: Minimal references to logging in code, but no explicit redaction.
  - Missing Mitigations: Secret redaction in logs or environment. Possibly restricting logs or removing them from public images.
  - Risk Severity: High

- Threat: Unvalidated text input in open textual parameters
  - Description: The system does not appear to sanitize textual input that might be used or displayed in logs or code generation steps.
  - Impact: Potential injection into logs or stored contexts.
  - Affected Component: routes/generate_code, the data flows to LLM calls.
  - Current Mitigations: None identified.
  - Missing Mitigations: Basic content checks or sanitization for unusual control characters and bounding input length.
  - Risk Severity: Low


# DEPLOYMENT THREAT MODEL

## ASSETS
- Running containers on host (frontend, backend)
- .env secrets in Docker environment
- Deployed environment logs

## TRUST BOUNDARIES
- Docker host (trusted) vs. external networks
- Container boundary (could be compromised if not restricted properly)
- Docker networking bridging frontend, backend, and external services

## DEPLOYMENT THREATS

- Threat: Container breakout via poorly isolated Docker configuration
  - Description: Attackers might exploit a container vulnerability to escape into the host if the Docker configuration is too permissive.
  - Impact: Could compromise entire host, read environment secrets, pivot to other containers.
  - Affected Component: Docker Compose config, Dockerfile trust boundary.
  - Current Mitigations: Docker best practices are implied, but no mention of restricted capabilities or additional isolation in the Compose file.
  - Missing Mitigations: Hardening containers, dropping privileges, ensuring minimal base images.
  - Risk Severity: Medium

- Threat: Hardcoded or leftover secrets in images
  - Description: The `.env` may be copied into container layers, or logs could remain in the final image if not carefully excluded.
  - Impact: Attackers with access to the built images might retrieve secrets or tokens.
  - Affected Component: Docker build steps, environment usage in Docker Compose.
  - Current Mitigations: `.env` is not in .dockerignore, but it’s only partially used in references.
  - Missing Mitigations: Enhanced Docker ignore usage, or secure secrets injection at runtime.
  - Risk Severity: Medium

- Threat: Exposed ports misconfiguration
  - Description: The Docker Compose sets ports 5173 and 7001. If not properly behind a firewall, these might be publicly accessible.
  - Impact: Potential unauthorized external access to backend or developer endpoints.
  - Affected Component: docker-compose.yml
  - Current Mitigations: None specifically mentioned.
  - Missing Mitigations: Firewalls or restricted inbound traffic rules.
  - Risk Severity: Low


# BUILD THREAT MODEL

## ASSETS
- Source code in repository (Python, Node code)
- Poetry dependencies and Node dependencies (unpinned or externally fetched)
- Docker images produced by the build

## TRUST BOUNDARIES
- Source control environment vs. local build environment
- External dependency registries vs. local build environment
- Build output vs. release artifact

## BUILD THREATS

- Threat: Malicious or unverified dependencies
  - Description: Third-party packages (PyPI, npm) or code in the repository might be compromised. The project’s pyproject.toml lacks pinned versions for all packages, so a malicious update could slip in.
  - Impact: Could lead to supply chain compromise at build time.
  - Affected Component: Poetry-based Python dependencies, Node yarn dependencies.
  - Current Mitigations: None specific to verifying dependencies.
  - Missing Mitigations: Dependency integrity verification or hashing, pinned versions, or a private registry.
  - Risk Severity: Medium

- Threat: Unauthorized modifications to Docker build
  - Description: Attackers could inject malicious code in Dockerfiles or Docker images if build scripts are tampered with.
  - Impact: Could allow supply chain or production environment compromise.
  - Affected Component: Dockerfile (backend/frontend).
  - Current Mitigations: The Dockerfiles appear straightforward, but no mention of signature checks for base images.
  - Missing Mitigations: Trusted base image references, content trust for Docker images.
  - Risk Severity: Medium

- Threat: Logging or artifact injection during CI (if used)
  - Description: If a continuous integration environment is used, an attacker with partial access could append malicious code or credentials in build logs or artifacts.
  - Impact: Potential credential leakage or code injection made public.
  - Affected Component: Potential or future CI pipeline (no direct mention in the repository).
  - Current Mitigations: Not applicable in the code.
  - Missing Mitigations: Minimal references to CI security in the docs. Could add restricted environment scope or build secrets usage.
  - Risk Severity: Low


# QUESTIONS & ASSUMPTIONS
- Is the screenshot route restricted from reaching internal-only addresses or protected endpoints? We assume not, leading to SSRF risk.
- Assumption that typical Docker best practices (like non-root containers) are not fully implemented or tested.
- Assumption that the user’s environment (local or server) protects the .env file from external reading.
- No mention of encryption or storage policies for generated code. We assume ephemeral in-memory usage.
- Unclear if or how the system sanitizes images beyond Claude-specific resizing. This might be incomplete for all usage scenarios.
- Assumption that code generation is used in a sandbox or purely downloaded by the user and not auto-deployed.
