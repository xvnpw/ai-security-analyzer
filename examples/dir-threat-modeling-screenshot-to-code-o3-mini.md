# APPLICATION THREAT MODEL

## ASSETS
- The source code for both frontend and backend including all configuration files, Dockerfiles, and scripts.
- Sensitive API credentials submitted and used for OpenAI, Anthropic, Gemini, and Replicate integrations.
- User-supplied inputs such as screenshots, video recordings, and design uploads.
- Generated outputs including AI-generated code, screenshots and evaluation outputs.
- Logging data and debug artifacts that may contain prompt details and model responses.
- Evaluation datasets and test inputs stored in the evals_data folder.
- The AI prompt templates and system messages that drive the code generation process.

## TRUST BOUNDARIES
- Border between the frontend (React/Vite client) and the backend (FastAPI server) via HTTP and WebSocket connections.
- Communication links between the backend and external APIs (OpenAI, Anthropic, Gemini, Replicate, and screenshot services).
- Separation between public (internet-facing) endpoints and internal server infrastructure.
- Boundary between Docker containers and the host system during deployment.
- Segregation of build environments (CI/CD systems) from source code repositories and production environments.

## DATA FLOWS
- User uploads images or videos on the frontend which are transmitted via HTTP/WebSocket to the backend.
- Backend reads environment variables (API keys) and constructs structured prompts that are sent to external AI APIs.
- AI model responses are streamed back to the backend over secure API channels and relayed to the frontend.
- Generated HTML/CSS/JS (code replicas) flow from the AI completion functions through post‐processing functions (e.g. image generation) before being sent to the client.
- Logging data, including prompts and responses, are written to disk for debugging.
- Docker and CI/CD pipelines pull dependencies and configuration files from the repository, then build deployable artifacts.

## APPLICATION THREATS
- Threat: API Key Leakage
  Description: An attacker might intercept or exfiltrate API keys from insecure transmission, browser storage, or debug logs.
  Impact: Unauthorized use of external services, incurring unexpected costs and service abuse.
  Affected Component: Frontend settings dialog (where keys are entered), .env files in backend, logging modules.
  Current Mitigations: The hosted version claims that keys entered in the frontend settings dialog are stored only in the browser; environment variables are used in backend.
  Missing Mitigations: Enforced HTTPS everywhere; stricter sanitization of logs; proper encryption and storage of sensitive key material; rate limiting or monitoring for anomalous API key use.
  Risk Severity: Critical

- Threat: Injection Attacks
  Description: Malicious users could inject unexpected input or code into prompts or input fields that are forwarded to the AI models without proper sanitization.
  Impact: Generation of unsafe or exploitable code snippets; potential cross-site scripting (XSS) vulnerabilities in the generated output.
  Affected Component: Prompt assembly routines in the backend and endpoints such as /generate-code.
  Current Mitigations: Use of fixed prompt templates minimizes free-form user input; use of predetermined message formats.
  Missing Mitigations: Comprehensive input validation, sanitization, and content security policies on both client and server; output encoding measures to prevent XSS.
  Risk Severity: High

- Threat: Denial of Service (DoS) via Expensive AI Calls
  Description: An adversary might flood the system with repeated requests to trigger multiple expensive LLM queries leading to resource exhaustion.
  Impact: Financial cost due to excessive API usage and potential service downtime for legitimate users.
  Affected Component: Backend endpoints (HTTP and WebSocket) for code generation and screenshot capture.
  Current Mitigations: Minimal controls as per available configuration; some endpoints employ standard CORS settings.
  Missing Mitigations: Implementation of rate limiting, request quotas, and possibly authentication mechanisms to restrict abuse.
  Risk Severity: Critical

- Threat: Insufficient Authorization/Access Control
  Description: Publicly accessible endpoints (e.g. /evals) may enable unauthorized access to sensitive evaluation data or internal functionalities.
  Impact: Leakage of evaluation datasets and potential information disclosure about internal system behavior.
  Affected Component: Evaluation endpoints and other open API routes.
  Current Mitigations: The open source nature of the system assumes self-hosting and public access.
  Missing Mitigations: Access control mechanisms such as authentication, API keys, or IP whitelisting for sensitive functions.
  Risk Severity: Medium to High

- Threat: Dependency Supply Chain Attacks
  Description: The use of numerous third-party libraries and containers may expose the project to vulnerabilities in dependencies or malicious package updates.
  Impact: Compromise of application integrity; possible remote code execution; container breakout.
  Affected Component: All backend components, build scripts, and Docker images.
  Current Mitigations: Use of Poetry lock files and version pinning helps reduce risk.
  Missing Mitigations: Continuous monitoring of dependency vulnerabilities, regular updates, and use of dependency scanning tools.
  Risk Severity: High

- Threat: Logging of Sensitive Information
  Description: The debugging and logging mechanisms may inadvertently capture and store sensitive user inputs and API responses.
  Impact: Exposure of confidential prompt details, API keys, or generated code that could be exploited if logs are accessed by unauthorized parties.
  Affected Component: FS Logging module and any log files written to disk.
  Current Mitigations: Basic logging is implemented without aggressive sanitization.
  Missing Mitigations: Policies for minimum log retention, redaction of sensitive data, and secure storage with restricted access.
  Risk Severity: High

- Threat: Video Processing Overload / Resource Exhaustion
  Description: Maliciously crafted video input could force the video processing module to extract excessive frames or consume disproportionate resources.
  Impact: System slowdown or crash due to exhaustion of compute or memory resources.
  Affected Component: Video processing utilities (e.g. video_to_app.py using moviepy and PIL).
  Current Mitigations: A target maximum number of screenshots is enforced.
  Missing Mitigations: Additional input validation on video length and resolution; resource usage monitoring.
  Risk Severity: Medium

- Threat: Cross-Site Scripting (XSS) in Generated Code
  Description: If AI-generated code is rendered without proper output encoding, it might embed malicious scripts that can execute in the user’s browser.
  Impact: Client-side code execution leading to session hijacking, data theft, or other client-side exploits.
  Affected Component: The generated HTML/CSS/JS pages that are served to users.
  Current Mitigations: Fixed prompt templates reduce variability, but there is no explicit output sanitization.
  Missing Mitigations: Implementation of strict Content Security Policy headers and thorough output sanitization before rendering in the browser.
  Risk Severity: High

# DEPLOYMENT THREAT MODEL

## ASSETS
- Docker images for the backend and frontend containers.
- Environment variable files (.env) containing sensitive API keys and configuration settings.
- Server infrastructure hosting the containers (virtual machines, cloud instances).
- Network endpoints exposed externally (ports mapped in Docker, public URLs).
- Cloud or hosting account credentials and domain management settings.

## TRUST BOUNDARIES
- The isolation boundary between containers and the host operating system.
- The network segregation between public internet exposure and internal container networks.
- The boundary between external API service providers and the private backend.
- The division between the secure build/deployment pipeline and the runtime environment.

## DEPLOYMENT THREATS
- Threat: Unauthorized Access to Exposed Endpoints
  Description: Attackers could exploit publicly exposed endpoints (HTTP and WebSocket) if not properly firewalled or secured.
  Impact: Data exfiltration or control over the application.
  Current Mitigations: Standard middleware such as CORSMiddleware is used; however, authentication is minimal.
  Missing Mitigations: Implementation of authentication, IP filtering, and firewall rules at the network level.
  Risk Severity: High

- Threat: Container Misconfiguration and Escape
  Description: Vulnerabilities in Docker configurations (e.g. running as root, overly permissive mounts) may allow attackers to break out of container boundaries.
  Impact: Compromise of the host system and other containers.
  Current Mitigations: Basic containerization using Dockerfiles and docker-compose; no advanced runtime restrictions noted.
  Missing Mitigations: Use of non-root container users, minimal privileges, and runtime security scanners.
  Risk Severity: Medium

- Threat: Secrets Leakage in Deployment
  Description: Sensitive environment variables stored in .env files or passed insecurely to containers may be exposed.
  Impact: Unauthorized access to external API services and the underlying infrastructure.
  Current Mitigations: Use of environment variables; instructions warn users not to store keys on servers in certain flows.
  Missing Mitigations: Encryption of secrets at rest and in transit; secret management systems instead of plain .env files.
  Risk Severity: High

- Threat: Denial of Service (DoS) Attacks Against Public Services
  Description: Attackers may flood the public endpoints with excessive requests leading to resource exhaustion.
  Impact: Disruption of service availability impacting all users.
  Current Mitigations: The project may rely on external infrastructure resilience; no explicit rate limiting is implemented.
  Missing Mitigations: Rate limiting, traffic filtering, and use of DDoS protection services.
  Risk Severity: Critical

# BUILD THREAT MODEL

## ASSETS
- The source repository containing the complete project code and configuration.
- Build scripts and automation pipelines such as poetry commands, Docker build scripts, and CI/CD configuration.
- Dependency definition files (poetry.lock, pyproject.toml, package.json, yarn.lock).
- Build output artifacts including Docker images.
- Build environment credentials (if any, e.g. tokens for dependency servers).

## TRUST BOUNDARIES
- The boundary between the developer’s local environment and the build server or CI/CD system.
- The isolation between the build environment and external dependency registries.
- The trust relationship between the source code repository and the final build artifacts.

## BUILD THREATS
- Threat: Dependency Supply Chain Attacks
  Description: Malicious packages or compromised dependencies could be introduced into the build process via package registries.
  Impact: Compromise of the built artifacts and eventual exploitation in production.
  Current Mitigations: Version pinning via poetry.lock and use of known registries; however, continuous monitoring is not explicitly mentioned.
  Missing Mitigations: Regular dependency vulnerability scans, use of secure supply chain tools, and code signing of build artifacts.
  Risk Severity: High

- Threat: CI/CD Pipeline Misconfiguration
  Description: Inadequate security in the build servers or CI/CD pipelines could allow attackers to inject malicious code during the build process.
  Impact: Production artifacts may be compromised, leading to remote code execution or other breaches.
  Affected Component: Build scripts and CI/CD environment (if used).
  Current Mitigations: Use of reproducible builds and containerized environments; details are minimal.
  Missing Mitigations: Strong access controls on CI/CD systems, environment isolation, and build artifact signing.
  Risk Severity: High

- Threat: Unauthorized Access to Build Environment Credentials
  Description: Leaked or mismanaged credentials used in the build process can compromise the build pipeline.
  Impact: Attackers might manipulate builds or access downstream systems.
  Current Mitigations: Limited by use of environment variables; no advanced secret management is mentioned.
  Missing Mitigations: Implementation of secure secret management systems and minimization of credentials in build logs.
  Risk Severity: Medium

# QUESTIONS & ASSUMPTIONS
- Are all communications between the frontend, backend, and external APIs enforced over secure channels (HTTPS, WSS)?
- Does the deployed environment implement proper rate limiting and request throttling on public endpoints?
- How are API keys and secrets managed in production and are they protected using dedicated secret management services?
- Is the Docker runtime configured to run containers with least privileges (non-root users, minimal capabilities)?
- Are logs monitored and sanitized to prevent leakage of sensitive information such as API keys or prompt details?
- It is assumed that the system will be deployed in a controlled environment where HTTPS is enforced and proper network segmentation is applied.
- It is assumed that end users will manage their own API credentials and that the open source nature of the project implies self-hosting.
- Additional questions include whether a formal security review of generated code is performed before deployment and if dependency vulnerability scanning is integrated into the CI/CD pipeline.
