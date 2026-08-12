# APPLICATION THREAT MODEL

## ASSETS

- User API Keys (OpenAI, Anthropic, Gemini, Replicate) - stored in environment variables or provided via settings dialog
- Generated Code - HTML/CSS/JavaScript code generated from screenshots/videos
- User Input Images/Screenshots - uploaded by users for code generation
- User Input Videos - uploaded by users for video-to-code conversion
- Code Generation History - conversation history between user and AI
- Evaluation Data - test datasets stored in `backend/evals_data/inputs` and `backend/evals_data/outputs`
- Configuration Data - stack preferences, model selections, generation settings
- WebSocket Session Data - active generation sessions and their state
- Image Cache - mapping of alt text to generated image URLs
- Logs - prompt messages and completions written to filesystem
- Video Frames - extracted frames from user-uploaded videos stored temporarily in filesystem

## TRUST BOUNDARIES

- Frontend ↔ Backend WebSocket Connection - user-controlled frontend communicates with backend over WebSocket
- Backend ↔ External AI APIs (OpenAI, Anthropic, Gemini) - backend sends prompts containing user data to third-party APIs
- Backend ↔ Image Generation Services (DALL-E 3, Flux via Replicate) - backend sends image generation prompts to external services
- Backend ↔ Screenshot Service (ScreenshotOne API) - backend requests screenshots of user-provided URLs
- User Browser ↔ Generated Code Preview - user views and interacts with AI-generated code in browser
- Backend ↔ Filesystem - backend reads/writes evaluation data, logs, debug files, and temporary video frames
- Environment Variables ↔ Backend Configuration - API keys and settings loaded from .env files

## DATA FLOWS

- User uploads screenshot/video → Frontend → WebSocket → Backend (crosses trust boundary)
- User provides API keys → Frontend settings dialog → WebSocket → Backend runtime configuration (crosses trust boundary)
- Backend constructs prompt with user image → External AI API (OpenAI/Anthropic/Gemini) (crosses trust boundary)
- AI API returns generated code → Backend → WebSocket → Frontend display (crosses trust boundary)
- Backend sends image generation prompts → External image service (DALL-E/Replicate) (crosses trust boundary)
- User provides URL → Backend → ScreenshotOne API → Screenshot returned (crosses trust boundary)
- Backend writes logs → Filesystem (writes prompt and completion data)
- Backend reads evaluation inputs → Processes with AI → Writes outputs to filesystem
- User starts code generation → Backend creates WebSocket session → Manages multiple variant generations in parallel
- User uploads video → Backend extracts frames → Temporary storage in filesystem → Frames sent to AI API (crosses trust boundary)

## APPLICATION THREATS

### Threat: API Key Exposure via WebSocket
**Description:** Attacker could intercept WebSocket traffic to capture API keys sent from frontend settings dialog. Keys are transmitted over WebSocket connection when user configures them in the UI rather than environment variables.

**Impact:** Stolen API keys could be used to generate code at victim's expense, exhaust API quotas, or access victim's AI service accounts.

**Affected Component:** `backend/routes/generate_code.py` (ParameterExtractionStage), WebSocket message handling

**Current Mitigations:** Keys can be configured via environment variables instead of settings dialog. No explicit encryption on WebSocket layer mentioned in code.

**Missing Mitigations:** Enforce WSS (WebSocket Secure) for all connections, encrypt sensitive parameters in WebSocket messages, implement key rotation mechanisms, add rate limiting per API key.

**Risk Severity:** High

### Threat: Prompt Injection via User Input
**Description:** Attacker crafts malicious text prompts, image alt texts, or history items that manipulate AI model behavior to generate harmful code (XSS payloads, malicious scripts, credential harvesting forms).

**Impact:** Generated code could contain XSS attacks, phishing forms, cryptocurrency miners, or other malicious functionality that executes when users preview the code.

**Affected Component:** `backend/prompts/__init__.py` (create_prompt, assemble_prompt), all system prompt files in `backend/prompts/`, `backend/tests/test_prompts.py` (demonstrates prompt assembly logic)

**Current Mitigations:** None identified - prompts are assembled directly from user input without sanitization. Test files show prompts constructed from user-provided text and images with special markers but no validation.

**Missing Mitigations:** Implement input validation and sanitization for user prompts, add content security policies for code preview, scan generated code for known malicious patterns, implement output filtering.

**Risk Severity:** High

### Threat: Server-Side Request Forgery (SSRF) via Screenshot Feature
**Description:** Attacker provides internal URLs (localhost, 127.0.0.1, internal IP ranges, cloud metadata endpoints) to screenshot endpoint. Backend fetches these URLs via ScreenshotOne API, potentially accessing internal services.

**Impact:** Exposure of internal services, cloud metadata (AWS credentials, Azure tokens), internal network mapping, potential data exfiltration from internal systems.

**Affected Component:** `backend/routes/screenshot.py` (app_screenshot endpoint, normalize_url function), `backend/tests/test_screenshot.py` (demonstrates URL handling)

**Current Mitigations:** URL normalization ensures proper protocol (http/https), raises ValueError for unsupported protocols (ftp, file). Tests show localhost and IP addresses are allowed.

**Missing Mitigations:** Implement URL allowlist/blocklist, block private IP ranges (RFC1918, loopback, link-local), validate against cloud metadata endpoints, use network-level restrictions. Current implementation allows localhost and private IPs which enables SSRF.

**Risk Severity:** High

### Threat: Arbitrary File Read via Evaluation Endpoints
**Description:** Attacker manipulates folder paths in evaluation endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) to read arbitrary files from filesystem using path traversal (../).

**Impact:** Exposure of sensitive files (API keys from .env, source code, system files), information disclosure about system structure.

**Affected Component:** `backend/routes/evals.py` (get_evals, get_pairwise_evals, get_best_of_n_evals endpoints)

**Current Mitigations:** Basic path existence checks, but no validation against path traversal.

**Missing Mitigations:** Implement strict path validation, restrict file access to specific directories, use allowlists for permitted paths, validate and sanitize folder parameters.

**Risk Severity:** Critical

### Threat: Denial of Service via Resource Exhaustion
**Description:** Attacker sends multiple concurrent code generation requests with large images/videos or triggers parallel variant generation to exhaust backend resources (CPU, memory, API quotas).

**Impact:** Service unavailability, increased costs from API usage, degraded performance for legitimate users.

**Affected Component:** `backend/routes/generate_code.py` (ParallelGenerationStage, WebSocket endpoint), variant generation with NUM_VARIANTS=4

**Current Mitigations:** Some timeout settings (600s for OpenAI), but no rate limiting, request queuing, or resource quotas.

**Missing Mitigations:** Implement per-user/IP rate limiting, request queue with size limits, maximum concurrent WebSocket connections, resource usage monitoring, implement backpressure mechanisms.

**Risk Severity:** Medium

### Threat: Image Generation Prompt Injection
**Description:** Attacker crafts image alt text in screenshots to inject harmful prompts into DALL-E 3 or Flux image generation requests, potentially generating inappropriate, copyrighted, or harmful images.

**Impact:** Generation of NSFW content, copyright violations, abuse of image generation services, potential legal liability.

**Affected Component:** `backend/image_generation/core.py` (generate_images, extract alt texts from HTML)

**Current Mitigations:** None identified - alt text is passed directly to image generation APIs.

**Missing Mitigations:** Content filtering for image prompts, validation against prohibited content policies, implement prompt sanitization, add content moderation for generated images.

**Risk Severity:** Medium

### Threat: Information Disclosure via Debug Logs
**Description:** Debug mode writes sensitive data (full prompts with images, API responses, generated code) to filesystem. Attacker gaining filesystem access could retrieve user data and API interactions.

**Impact:** Exposure of user input images, conversation history, generated code, internal system behavior.

**Affected Component:** `backend/debug/DebugFileWriter.py`, `backend/fs_logging/core.py`, IS_DEBUG_ENABLED flag

**Current Mitigations:** Debug mode controlled by environment variable, writes to user-configured DEBUG_DIR.

**Missing Mitigations:** Ensure debug mode is disabled in production, implement secure log storage with encryption, add access controls to log directories, implement log rotation and automatic cleanup.

**Risk Severity:** Medium

### Threat: Insecure Deserialization via WebSocket
**Description:** Attacker sends malformed JSON payloads over WebSocket that could exploit JSON parsing vulnerabilities or inject unexpected data types into parameter handling.

**Impact:** Potential code execution, application crash, unexpected behavior in code generation pipeline.

**Affected Component:** `backend/routes/generate_code.py` (WebSocketCommunicator.receive_params), FastAPI WebSocket JSON parsing

**Current Mitigations:** Pydantic models for some request validation, but WebSocket params received as generic Dict[str, str].

**Missing Mitigations:** Implement strict schema validation for WebSocket messages, add input type checking, implement message size limits, validate all parameter types before processing.

**Risk Severity:** Medium

### Threat: Insufficient Authentication/Authorization
**Description:** API endpoints lack authentication mechanisms. Anyone with network access can trigger code generation, run evaluations, access evaluation results, or capture screenshots.

**Impact:** Unauthorized API usage, resource abuse, data exposure, potential cost exhaustion from AI API calls.

**Affected Component:** All routes in `backend/routes/` (no authentication middleware visible)

**Current Mitigations:** None identified - endpoints appear to be publicly accessible.

**Missing Mitigations:** Implement API authentication (API keys, OAuth, JWT), add authorization checks for sensitive operations, implement user session management, add IP-based access controls.

**Risk Severity:** High

### Threat: Code Injection in Generated Output
**Description:** AI models could be manipulated (via prompt injection or training data) to generate code with backdoors, malicious imports, or hidden functionality that executes when users run the code.

**Impact:** Code execution on user systems, data theft from user environments, supply chain attacks if generated code is distributed.

**Affected Component:** All model interaction code in `backend/models/`, generated code output

**Current Mitigations:** None identified - generated code is returned as-is without validation.

**Missing Mitigations:** Implement static code analysis on generated output, scan for suspicious patterns (eval, exec, obfuscated code), validate external dependencies, add warnings for potentially dangerous code patterns.

**Risk Severity:** High

### Threat: Cross-Site Scripting (XSS) in Code Preview
**Description:** Generated code containing malicious JavaScript is previewed in user's browser without proper sandboxing, allowing script execution in the context of the application.

**Impact:** Session hijacking, credential theft, further attacks against users, access to localStorage/cookies.

**Affected Component:** Frontend code preview functionality (files not in current batch, but referenced in README)

**Current Mitigations:** Unknown - frontend code not included in current analysis.

**Missing Mitigations:** Implement iframe sandboxing with restrictive permissions, use Content Security Policy, implement output encoding, run preview in isolated context.

**Risk Severity:** High

### Threat: Temporary Video Frame File Exposure
**Description:** Video processing creates temporary JPEG files in system temp directory with predictable UUID-based naming. Files may persist after processing failures or not be cleaned up properly, exposing user video content.

**Impact:** Exposure of sensitive video content uploaded by users, information disclosure, privacy violation.

**Affected Component:** `backend/video/utils.py` (save_images_to_tmp function, split_video_into_screenshots function)

**Current Mitigations:** Uses UUID for directory naming to reduce predictability. NamedTemporaryFile with delete=True for video file, but extracted frames are saved to persistent tmp directory when DEBUG is enabled.

**Missing Mitigations:** Ensure temporary directories are cleaned up after processing, implement proper exception handling to guarantee cleanup, disable DEBUG mode in production, use secure temporary file permissions (0600), implement automatic cleanup of old temp files.

**Risk Severity:** Medium

### Threat: Video Frame Count Validation Bypass
**Description:** Video processing limits frames to 20 but validation occurs after extraction. Malicious user could upload video that generates more than 20 frames, causing ValueError after resources already consumed.

**Impact:** Resource exhaustion during frame extraction, wasted processing time, potential DoS before validation triggers.

**Affected Component:** `backend/video/utils.py` (split_video_into_screenshots function)

**Current Mitigations:** Raises ValueError if more than 20 frames extracted, uses frame skipping to target 20 frames.

**Missing Mitigations:** Validate video duration and frame count before extraction, implement streaming frame extraction with early termination, add resource limits for video processing operations.

**Risk Severity:** Low

### Threat: Base64 Video Data Processing Memory Exhaustion
**Description:** Large base64-encoded videos are decoded into memory before processing. Attacker could upload extremely large video files causing out-of-memory conditions.

**Impact:** Application crash, denial of service, impact on other users sharing the same backend instance.

**Affected Component:** `backend/video/utils.py` (split_video_into_screenshots function - base64.b64decode operation)

**Current Mitigations:** None identified - entire base64 video is decoded at once into memory.

**Missing Mitigations:** Implement video size limits before decoding, validate base64 data size, use streaming decoding if possible, implement memory usage monitoring and limits.

**Risk Severity:** Medium

### Threat: Prompt Assembly with Multiple Images in History
**Description:** Test code demonstrates that user messages in conversation history can contain multiple images. This expands attack surface for image-based prompt injection where attacker could provide multiple malicious images in a single update request.

**Impact:** Enhanced prompt injection capabilities through multiple images, potential for more sophisticated attacks combining multiple visual inputs.

**Affected Component:** `backend/prompts/__init__.py` (create_prompt function), `backend/tests/test_prompts.py` and `backend/tests/test_prompts_additional.py` (demonstrate multi-image support)

**Current Mitigations:** None - images from history are passed directly to AI APIs without validation.

**Missing Mitigations:** Implement limits on number of images per message, validate image content and size, implement image scanning for malicious content, add rate limiting on image uploads.

**Risk Severity:** Medium

### Threat: WebSocket Close Code Information Disclosure
**Description:** Custom WebSocket close code (4332) defined in constants may leak application-specific error information to attackers, helping them understand error conditions and application behavior.

**Impact:** Information disclosure about application errors, aids in reconnaissance for further attacks.

**Affected Component:** `backend/ws/constants.py` (APP_ERROR_WEB_SOCKET_CODE)

**Current Mitigations:** Uses valid custom close code range (4000-4999) per RFC 6455.

**Missing Mitigations:** Avoid using specific error codes that reveal internal application state, use generic error messages to clients, log detailed errors server-side only.

**Risk Severity:** Low

## DEPLOYMENT THREAT MODEL

**Deployment Architecture:** Based on docker-compose.yml and Dockerfiles, the application is deployed as two containerized services - a FastAPI backend (Python) and a Vite frontend (Node.js), with backend on port 7001 and frontend on port 5173.

## ASSETS

- Docker Container Images - contains application code, dependencies
- Environment Variables File (.env) - contains API keys for OpenAI, Anthropic, Gemini, Replicate
- Docker Network - internal communication between frontend and backend containers
- Exposed Ports - 7001 (backend), 5173 (frontend) exposed to host network
- Container Runtime - Docker daemon with access to host resources
- Mounted Volumes - potential volume mounts for logs, evaluation data
- Temporary File Storage - system temp directory used by video processing

## TRUST BOUNDARIES

- Host Network ↔ Container Ports - external traffic can reach exposed container ports
- Frontend Container ↔ Backend Container - containers communicate over Docker network
- Container ↔ Host Filesystem - containers may mount host directories and access host temp directory
- Docker Daemon ↔ Containers - daemon manages container lifecycle with elevated privileges
- Internet ↔ External Services - containers make outbound requests to AI APIs

## DEPLOYMENT THREATS

### Threat: Exposed Docker Daemon Socket
**Description:** If Docker socket is mounted into containers (not shown in current compose file, but common practice), attacker escaping container could gain root access to host via Docker API.

**Impact:** Full host compromise, container escape, access to all containers on host, ability to create privileged containers.

**Affected Component:** Docker deployment, potential volume mounts

**Current Mitigations:** Socket mount not present in provided docker-compose.yml.

**Missing Mitigations:** Never mount Docker socket into application containers, use Docker API over TCP with TLS if remote management needed, implement minimal container capabilities.

**Risk Severity:** Critical

### Threat: Plaintext API Keys in Environment Variables
**Description:** API keys stored in .env file in plaintext. Compromise of host filesystem or container escape exposes all API credentials.

**Impact:** Unauthorized API usage, financial loss from API abuse, data access in connected AI services.

**Affected Component:** .env file, docker-compose.yml environment configuration

**Current Mitigations:** None - keys stored as plaintext in .env file.

**Missing Mitigations:** Use secrets management (Docker secrets, HashiCorp Vault, cloud provider secrets), encrypt .env file at rest, implement key rotation, use short-lived tokens where possible.

**Risk Severity:** High

### Threat: Container Running as Root
**Description:** Dockerfiles don't specify USER directive, likely running processes as root inside containers. Vulnerability in application could lead to container escape.

**Impact:** Easier container escape, increased attack surface, potential host compromise.

**Affected Component:** backend/Dockerfile, frontend/Dockerfile

**Current Mitigations:** None visible - no USER directive in Dockerfiles.

**Missing Mitigations:** Run containers as non-root user, add USER directive to Dockerfiles, implement read-only root filesystem, drop unnecessary Linux capabilities.

**Risk Severity:** High

### Threat: Unrestricted Outbound Network Access
**Description:** Containers have unrestricted outbound network access to reach AI APIs. Compromised container could be used for data exfiltration, C2 communication, or attacks on external systems.

**Impact:** Data exfiltration, participation in botnets, attacks originating from deployment, reputational damage.

**Affected Component:** Docker network configuration, no network policies defined

**Current Mitigations:** None - default Docker networking allows all outbound traffic.

**Missing Mitigations:** Implement egress filtering with allowlist for required APIs, use network policies to restrict container communication, implement DNS filtering, monitor outbound connections.

**Risk Severity:** Medium

### Threat: Exposed Service Ports to Public Network
**Description:** Backend (7001) and frontend (5173) ports exposed directly to host network without reverse proxy or firewall. Services accessible to anyone who can reach the host.

**Impact:** Direct access to unauthenticated services, easier reconnaissance, increased attack surface.

**Affected Component:** docker-compose.yml port mappings, deployment architecture

**Current Mitigations:** None - ports directly exposed in docker-compose.yml.

**Missing Mitigations:** Use reverse proxy (nginx, Traefik) with TLS termination, implement network firewall rules, restrict access by IP/network, use VPN for administrative access.

**Risk Severity:** High

### Threat: No Resource Limits on Containers
**Description:** Docker compose file doesn't define CPU/memory limits for containers. Runaway process or DoS attack could exhaust host resources.

**Impact:** Host system crash, denial of service, impact on other containers/services on same host.

**Affected Component:** docker-compose.yml, missing resource constraints

**Current Mitigations:** None - no resource limits defined.

**Missing Mitigations:** Add CPU and memory limits to docker-compose.yml, implement PID limits, use Docker's --memory and --cpus flags, monitor resource usage.

**Risk Severity:** Medium

### Threat: Unencrypted Inter-Container Communication
**Description:** Frontend and backend communicate over unencrypted Docker network. Container compromise could allow traffic interception.

**Impact:** Exposure of API keys transmitted via WebSocket, session hijacking, data interception.

**Affected Component:** Docker network between frontend and backend

**Current Mitigations:** None - default Docker bridge network without encryption.

**Missing Mitigations:** Use overlay network with encryption enabled, implement TLS for backend API, use service mesh with mTLS, deploy containers on isolated networks.

**Risk Severity:** Medium

### Threat: Vulnerable Base Images
**Description:** Dockerfiles use specific base image versions (python:3.12.3-slim-bullseye, node:22-bullseye-slim) that may contain known vulnerabilities over time.

**Impact:** Container compromise through known CVEs, privilege escalation, application vulnerabilities.

**Affected Component:** backend/Dockerfile, frontend/Dockerfile base images

**Current Mitigations:** Using slim images reduces attack surface somewhat.

**Missing Mitigations:** Implement regular base image updates, scan images for vulnerabilities (Trivy, Snyk), use distroless images where possible, implement automated image rebuilds, pin images by digest not tag.

**Risk Severity:** High

### Threat: Shared Host Temp Directory Access
**Description:** Containers access host system temp directory for video frame storage. Multiple containers or host processes share this space, potentially allowing cross-container information disclosure or temp file conflicts.

**Impact:** Exposure of video frames to other processes, potential file collisions, information leakage between containers.

**Affected Component:** `backend/video/utils.py` using tempfile.gettempdir(), container filesystem mounting

**Current Mitigations:** UUID-based directory naming reduces collision risk.

**Missing Mitigations:** Mount dedicated volume for temp storage, isolate temp directories per container, implement proper file permissions, use container-specific temp directories.

**Risk Severity:** Medium

## BUILD THREAT MODEL

**Build Process:** Project uses Poetry for Python backend dependency management and Yarn for frontend. No CI/CD configuration files visible in current batch (e.g., GitHub Actions, Jenkins), suggesting manual or undefined build process.

## ASSETS

- Source Code - Python backend and TypeScript/JavaScript frontend code
- Dependency Lock Files - poetry.lock, yarn.lock defining exact versions
- Package Registries - PyPI for Python packages, npm registry for JavaScript packages
- Build Artifacts - Docker images, compiled JavaScript bundles
- Development Dependencies - testing frameworks (pytest), linters, type checkers
- Test Code - unit tests that may contain sensitive logic or test data

## TRUST BOUNDARIES

- Developer Workstation ↔ Package Registries - developers install dependencies from public registries
- CI System ↔ Package Registries - build system fetches dependencies (if CI exists)
- Local Build ↔ Docker Registry - built images may be pushed to registry
- Source Repository ↔ Build System - code pulled from git repository
- Test Environment ↔ Production Code - test code imports and exercises production functionality

## BUILD THREATS

### Threat: Dependency Confusion Attack
**Description:** Attacker publishes malicious package with same name as internal package to public PyPI or npm registry. Build system installs malicious public package instead of intended dependency.

**Impact:** Code execution during build, backdoored application artifacts, compromised dependencies in production.

**Affected Component:** Poetry dependency resolution, Yarn dependency resolution, package installation

**Current Mitigations:** Lock files (poetry.lock, yarn.lock) pin exact versions, reducing risk of version substitution.

**Missing Mitigations:** Use private package registry for internal dependencies, configure registry priority, implement package signature verification, use dependency hash verification.

**Risk Severity:** High

### Threat: Compromised Dependencies
**Description:** Legitimate packages in PyPI or npm are compromised (account takeover, malicious maintainer). Application installs backdoored or malicious dependency.

**Impact:** Supply chain compromise, backdoored application, data theft, malicious functionality in production.

**Affected Component:** All dependencies in pyproject.toml and package.json, including test dependencies like pytest, moviepy, PIL

**Current Mitigations:** Lock files ensure consistent versions, but don't prevent installing initially malicious package.

**Missing Mitigations:** Implement Software Bill of Materials (SBOM), use dependency scanning tools (Dependabot, Snyk), audit dependency changes, implement package hash verification, use minimal dependencies.

**Risk Severity:** Critical

### Threat: Missing Dependency Vulnerability Scanning
**Description:** No automated scanning for known vulnerabilities in dependencies. Vulnerable packages may be used in production.

**Impact:** Exploitation of known CVEs in dependencies, application compromise, data breaches.

**Affected Component:** Build process, dependency management

**Current Mitigations:** None visible - no mention of vulnerability scanning in configuration.

**Missing Mitigations:** Implement automated dependency scanning in CI, use tools like Safety (Python), npm audit (JavaScript), fail builds on high-severity vulnerabilities, implement regular dependency updates.

**Risk Severity:** High

### Threat: Unsigned Container Images
**Description:** Built Docker images are not signed, allowing potential tampering or substitution in registry.

**Impact:** Deployment of malicious container images, man-in-the-middle attacks on image distribution, unauthorized code execution.

**Affected Component:** Docker image build and distribution

**Current Mitigations:** None visible - no image signing mentioned.

**Missing Mitigations:** Implement Docker Content Trust, sign images with Notary, use image digest pinning instead of tags, implement image provenance verification.

**Risk Severity:** Medium

### Threat: Exposed Secrets in Build Process
**Description:** API keys or credentials could be accidentally included in Docker layers, git commits, or build artifacts.

**Impact:** Credential exposure, unauthorized API access, potential compromise of connected services.

**Affected Component:** Docker build process, git repository

**Current Mitigations:** .env file in .gitignore (assumed but not verified in current batch).

**Missing Mitigations:** Implement pre-commit hooks to scan for secrets, use secret scanning tools (git-secrets, TruffleHog), implement multi-stage Docker builds, scan built images for secrets.

**Risk Severity:** High

### Threat: No Build Provenance
**Description:** No mechanism to verify where and how application was built. Can't verify build integrity or trace artifacts to source.

**Impact:** Difficult to audit builds, can't verify supply chain integrity, hard to detect compromised builds.

**Affected Component:** Build system, artifact distribution

**Current Mitigations:** None - no CI/CD or provenance system visible.

**Missing Mitigations:** Implement CI/CD with build provenance (GitHub Actions attestations, SLSA), sign build artifacts, implement reproducible builds, maintain build logs.

**Risk Severity:** Medium

### Threat: Lack of Code Quality Gates
**Description:** No automated linting, SAST, or security checks in build process. Security issues and code quality problems may reach production.

**Impact:** Vulnerabilities in production code, code quality issues, potential security flaws.

**Affected Component:** Build/CI process

**Current Mitigations:** Mentions of pre-commit (in pyproject.toml), pyright for type checking, pytest for tests, but no evidence of enforcement.

**Missing Mitigations:** Implement mandatory pre-commit hooks, add SAST scanners (Bandit, Semgrep), enforce type checking in CI, require passing tests before merge, implement code coverage thresholds.

**Risk Severity:** Medium

### Threat: Puppeteer Skipping Downloads (ENV PUPPETEER_SKIP_DOWNLOAD=true)
**Description:** Frontend Dockerfile skips Puppeteer chromium download. If application later needs browser automation, it may download untrusted binaries at runtime.

**Impact:** Potential download of compromised binaries at runtime, application malfunction if browser needed.

**Affected Component:** frontend/Dockerfile

**Current Mitigations:** None - download skipped to save space/time.

**Missing Mitigations:** If browser automation needed, include verified chromium binary in image, use official chromium Docker images, verify binary signatures.

**Risk Severity:** Low

### Threat: Test Code Exposure in Production Images
**Description:** Test files containing mock data, test patterns, and application logic may be included in production Docker images if not properly excluded during build.

**Impact:** Information disclosure about application structure, exposure of test credentials or mock data, increased image size.

**Affected Component:** Docker build process, test files in `backend/tests/`

**Current Mitigations:** None visible - no .dockerignore or explicit test exclusion seen.

**Missing Mitigations:** Implement .dockerignore to exclude test files, use multi-stage Docker builds to separate test and production artifacts, verify final image contents, minimize production image size.

**Risk Severity:** Low

### Threat: Malicious Test Dependencies
**Description:** Test-specific dependencies (pytest, unittest.mock, etc.) could be compromised and execute malicious code during test runs on developer machines or CI systems.

**Impact:** Compromise of development environments, injection of backdoors during testing, exfiltration of source code or credentials from dev/CI environments.

**Affected Component:** Test dependencies in pyproject.toml, test files importing external packages

**Current Mitigations:** Lock files pin test dependency versions.

**Missing Mitigations:** Isolate test execution in sandboxed environments, scan test dependencies separately, minimize test-only dependencies, use dedicated test environments isolated from production secrets.

**Risk Severity:** Medium

## QUESTIONS & ASSUMPTIONS

### Questions

1. Is there a CI/CD pipeline that wasn't included in this batch of files?
2. How are Docker images distributed - public registry, private registry, or manual builds?
3. Are there any network security controls (firewalls, WAF) in the deployment environment?
4. How are API keys rotated and managed in production?
5. Is the application intended for public internet deployment or private/internal use?
6. Are there any authentication mechanisms implemented in frontend code not yet reviewed?
7. What is the intended production deployment platform (cloud, on-premise, etc.)?
8. Is DEBUG mode in video processing enabled in production deployments?
9. Are there cleanup mechanisms for temporary video frames that weren't visible in the code?
10. How are WebSocket connections authenticated and authorized?
11. Are there size limits enforced on video uploads before processing?

### Assumptions

- Application is intended for deployment with internet access to reach AI APIs
- Frontend code not yet reviewed may contain additional security controls
- No CI/CD pipeline is currently implemented based on absence of workflow files
- Application handles sensitive data through API keys and user-uploaded content
- Default deployment uses provided Docker Compose configuration
- Debug mode is disabled in production (IS_DEBUG_ENABLED=False and DEBUG=False in video utils)
- Application is deployed behind some form of network security in production
- Environment variables (.env file) is the primary secrets management mechanism
- Temporary video frame files are cleaned up after processing (though cleanup code not visible)
- Test files are excluded from production builds (though no explicit exclusion mechanism seen)
- Video processing is intended for production use despite DEBUG flag in utils.py