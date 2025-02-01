APPLICATION THREAT MODEL

ASSETS
- Source code including backend code (FastAPI application, Dockerfiles, build scripts) and frontend code (React/Vite application)
- User input data such as screenshots, video recordings, and any text provided via the settings dialog
- Sensitive API keys (OpenAI, Anthropic, Gemini, Replicate, ScreenshotOne) supplied via environment variables or client settings
- Generated code produced by AI models and evaluation output used for testing and further model improvements
- Logs and debug artifacts written to the file system (prompt messages, completion data)
- Dependency manifests and configuration files (pyproject.toml, package.json, docker-compose.yml)

TRUST BOUNDARIES
- Boundary between external (internet) users and the backend API endpoints (HTTP/WebSocket)
- Separation between the client (browser application) and the backend server that processes API requests
- Boundary between the backend and third‐party AI services (OpenAI, Anthropic, Gemini, Replicate, ScreenshotOne)
- Isolation boundaries provided by containerization (Docker containers) versus the host operating system

DATA FLOWS
- User uploads input data (screenshots, videos) and provides API keys via the frontend settings; these are forwarded to the backend
- Backend (FastAPI) receives requests over HTTP/websocket, assembles prompts, and sends requests to external AI services for code generation
- AI service responses stream back from third parties to the backend, which then relays chunks via web-socket to the client
- Logs and debug artifacts are written to disk as files for offline analysis
- Environment variables (containing sensitive API keys and configuration settings) flow into Docker containers during deployment

APPLICATION THREATS
- API Key Leakage
  - Description: Sensitive third-party API keys may be intercepted if transmitted insecurely or inadvertently exposed through misconfigured settings or logs.
  - Impact: Unauthorized use of keys could result in financial loss, overuse quotas, or compromise of associated accounts.
  - Affected Component: Backend configuration and environment variable management; settings dialog inputs.
  - Current Mitigations: API keys are injected via environment variables and keys entered in the frontend are stored only on the client.
  - Missing Mitigations: Enforcement of TLS on all communications, strict access control for configuration data, key rotation and audit logging.
  - Risk Severity: High

- Denial of Service (DoS)
  - Description: Attackers may flood API endpoints or the websocket with excessive requests or malformed data.
  - Impact: Exhaustion of server resources, unavailability of service to legitimate users.
  - Affected Component: Backend server endpoints (FastAPI and websocket handlers).
  - Current Mitigations: None explicitly implemented.
  - Missing Mitigations: Input rate limiting, resource throttling, and robust input validation.
  - Risk Severity: High

- Injection Attacks or Malicious Input
  - Description: Crafted malicious inputs (in image data, video payloads, or text prompts) could alter prompt structure or trigger unintended responses.
  - Impact: Generation of incorrect or harmful code that may later be rendered or executed in client browsers.
  - Affected Component: Prompt assembly logic and API request processing.
  - Current Mitigations: Use of structured message formats to communicate with AI models.
  - Missing Mitigations: Stringent validation and sanitization of user-provided data.
  - Risk Severity: Medium

- Information Disclosure via Logs
  - Description: Debug logs and file system logging of prompt messages and completions may contain sensitive information.
  - Impact: Leakage of sensitive API keys, detailed internal functioning of the application, or confidential user inputs.
  - Affected Component: Logging modules (DebugFileWriter, write_logs) and stored log files.
  - Current Mitigations: Logging controlled by a debug flag.
  - Missing Mitigations: Secure log storage practices, access controls on log directories, and sanitization of logged data.
  - Risk Severity: High

- Dependency and Supply Chain Vulnerabilities
  - Description: The extensive use of third-party libraries (FastAPI, OpenAI SDK, Poetry, Yarn, etc.) could be exploited if any dependency is compromised.
  - Impact: Introduction of vulnerabilities into the application, leading to potential exploitation of the build or runtime environment.
  - Affected Component: Build process and runtime modules.
  - Current Mitigations: Use of lock files (poetry.lock, yarn.lock) to pin dependency versions.
  - Missing Mitigations: Regular dependency audits, SAST scanning, and integration of dependency vulnerability scanners.
  - Risk Severity: Medium

- Misconfiguration and Exposure of Services
  - Description: Inadequate configuration of deployment (Docker, .env files) might expose sensitive endpoints and data.
  - Impact: Unauthorized access to administrative functions, exposure of API keys, unintended public access.
  - Affected Component: Server and container configuration settings.
  - Current Mitigations: Provided instructions and Docker-compose files for local deployment.
  - Missing Mitigations: Hardened configuration with minimal exposure, firewall rules, and network segmentation.
  - Risk Severity: High

DEPLOYMENT THREAT MODEL

ASSETS
- Docker images for backend and frontend applications
- Environment variables stored in .env files containing sensitive keys and configuration details
- Network endpoints exposed by containers (default ports 7001 for backend and 5173 for frontend)
- Deployment configuration files (docker-compose.yml, Dockerfiles)
- Sensitive deployment scripts and configuration artifacts

TRUST BOUNDARIES
- Boundary between the publicly exposed network (internet) and the containerized environment running the application
- Isolation between frontend and backend containers within the deployment configuration
- Separation between containers and the underlying host operating system
- Boundary between the internal container network and third-party API endpoints reached by the system

DEPLOYMENT THREATS
- Network Exposure
  - Description: Deployed services may be exposed over the public internet without proper encryption or access restrictions.
  - Impact: Interception of sensitive data in transit, unauthorized access to API endpoints.
  - Affected Component: Backend and frontend network endpoints.
  - Current Mitigations: Use of Docker and specified port mappings.
  - Missing Mitigations: Enforcement of HTTPS, firewall configurations, and use of reverse proxy with proper access controls.
  - Risk Severity: High

- Container Breakout
  - Description: Vulnerabilities in container isolation could allow an attacker to escape the containerized environment.
  - Impact: Compromise of the host system, access to sensitive configuration files and environment variables.
  - Affected Component: Docker container runtime.
  - Current Mitigations: Default Docker isolation mechanisms.
  - Missing Mitigations: Adoption of security-hardened base images, resource limiting, and regular security updates to container runtimes.
  - Risk Severity: Medium

- Misconfiguration of Environment Variables and Secrets
  - Description: Improper handling or exposure of environment variables may disclose sensitive API keys.
  - Impact: Leakage of credentials leading to unauthorized access to third-party services.
  - Affected Component: Environment variable configuration in Docker and orchestration systems.
  - Current Mitigations: Use of .env files.
  - Missing Mitigations: Integration of secret management solutions and strict access controls on configuration data.
  - Risk Severity: High

BUILD THREAT MODEL

ASSETS
- Source repository containing the full codebase and build scripts
- Build artifacts including compiled assets and Docker images
- Dependency manifests such as poetry.lock and package.json
- CI/CD configuration files and build logs detailing the build process

TRUST BOUNDARIES
- Boundary between the trusted source code maintained in version control and the external dependency ecosystem (PyPI, NPM)
- Isolation of the build environment (CI/CD servers) from untrusted external inputs or contributions
- Separation between code signing and build artifact distribution channels

BUILD THREATS
- Supply Chain Attacks
  - Description: Malicious code may be introduced via compromised third-party dependencies or tampered package repositories.
  - Impact: Infected build artifacts leading to runtime compromise.
  - Affected Component: Package management systems (Poetry, Yarn) and dependency repositories.
  - Current Mitigations: Use of lock files to pin dependency versions.
  - Missing Mitigations: Automated dependency vulnerability scanning and integration of SAST tools in the CI/CD workflow.
  - Risk Severity: Medium

- Build Process Tampering
  - Description: Unauthorized modifications to build scripts or CI/CD pipeline configurations could result in compromised artifacts.
  - Impact: Delivery of malicious software to production environments.
  - Affected Component: Build automation pipelines, configuration scripts.
  - Current Mitigations: Version control management.
  - Missing Mitigations: Implementation of code signing, secure CI/CD practices, and strict access controls on build systems.
  - Risk Severity: Medium

QUESTIONS & ASSUMPTIONS

Questions
- How are API keys for third-party services managed, rotated, and secured across different environments?
- Are all communications between the client, backend, and third-party services encrypted (e.g., via HTTPS)?
- What specific access controls are in place for the debug logs and file system logging artifacts?
- Has rate limiting or other DoS mitigation been implemented on both API endpoints and websocket connections?
- Are dependency vulnerability assessments performed regularly as part of the build and deployment process?
- How is the container host environment secured and monitored, especially in a production deployment?
- What authentication and authorization mechanisms protect access to the backend API endpoints?

Assumptions
- The system is designed to be deployed in environments that may face public internet exposure.
- API keys provided by users through frontend settings are not persisted on the server side.
- The application operates as a stateless service without long-term storage of user data.
- Docker and container-based deployment are used with standard configurations, with further hardening left to each deployment scenario.
- The current build process uses manual triggers or a basic CI/CD system that does not yet incorporate advanced security scanning.
- The threat model prioritizes realistic, high-probability threats that impact confidentiality, integrity, and availability rather than theoretical attack vectors.
- The open-source nature of the code assumes that deployments may vary and that additional site-specific security measures may be required in production.
