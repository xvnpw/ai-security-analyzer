# APPLICATION THREAT MODEL

## ASSETS
- API Keys (OpenAI, Anthropic, Gemini)
- User-uploaded images/videos
- Generated code output
- AI model configurations/prompts
- Session data between frontend/backend
- Third-party CDN resources (Tailwind/Bootstrap scripts, Google Fonts, Font Awesome)

## TRUST BOUNDARIES
- Between user browser (frontend) and backend API
- Between backend and external AI providers (OpenAI/Anthropic/Gemini)
- Between user-uploaded content and processing system
- Between Docker containers in production deployment
- Between third-party CDN providers and client browsers

## DATA FLOWS
1. User upload -> Frontend -> Backend (crosses boundary)
2. Backend -> OpenAI/Anthropic/Gemini APIs (crosses boundary)
3. AI Response -> Backend -> Frontend -> User
4. Env vars (API keys) -> Backend configuration
5. Docker internal network communication
6. Client browser -> Third-party CDNs (crosses boundary)

## APPLICATION THREATS
- **Third-party CDN Compromise**
  - Description: Generated code includes scripts from external CDNs (Tailwind, Bootstrap, Font Awesome) that could be modified to serve malicious content
  - Impact: Client-side XSS attacks, data exfiltration
  - Affected: All code generation modules using CDN resources
  - Current Mitigations: None evident in prompt configurations
  - Missing: Subresource Integrity (SRI) hashes, self-hosting critical resources
  - Severity: High

- **Video Frame Processing Attacks**
  - Description: Malicious video files could exploit vulnerabilities in moviepy/PIL image processing
  - Impact: Remote code execution via malformed video frames
  - Affected: video/utils.py split_video_into_screenshots
  - Current Mitigations: Temporary file cleanup
  - Missing: Sandboxed processing environment, strict file validation
  - Severity: Medium

- **WebSocket Session Hijacking**
  - Description: Lack of WebSocket authentication allows attackers to intercept generation sessions
  - Impact: Theft of API keys/IP through unauthenticated WS connections
  - Affected: routes/generate_code.py WebSocket handler
  - Current Mitigations: None mentioned
  - Missing: Session tokens, origin validation
  - Severity: Medium

- **Prompt Injection via Base64 Images**
  - Description: Hidden text in images could alter system prompts through vision models
  - Impact: Bypass of output sanitization controls
  - Affected: backend/prompts/test_prompts.py
  - Current Mitigations: None
  - Missing: Image content analysis pre-processing
  - Severity: Medium

- **Eval File Path Traversal**
  - Description: User-controlled folder paths could access sensitive system directories
  - Impact: Arbitrary file read through path manipulation
  - Affected: routes/evals.py get_evals endpoint
  - Current Mitigations: Basic path existence checks
  - Missing: Strict path validation, sandboxed directory access
  - Severity: Medium

# DEPLOYMENT THREAT MODEL

## ASSETS
- Docker host environment
- Container orchestration
- Internal API endpoints
- Build pipeline artifacts

## TRUST BOUNDARIES
- Between Docker containers and host system
- Between development and production environments
- Between CI/CD pipelines and artifact repositories

## DEPLOYMENT THREATS
- **Exposed Backend Ports**
  - Description: Backend port 7001 exposed without auth
  - Impact: Direct API access
  - Affected: docker-compose.yml
  - Current Mitigations: None
  - Missing: Authentication layer
  - Severity: High

- **Insecure Docker Configuration**
  - Description: Potential privilege escalation in containers
  - Impact: Host system compromise
  - Affected: frontend/Dockerfile, backend/Dockerfile
  - Current Mitigations: Non-root users
  - Missing: Seccomp profiles, read-only filesystems
  - Severity: Medium

- **CI/CD Secret Exposure**
  - Description: API keys in build scripts
  - Impact: Credential leakage
  - Affected: docker-compose.yml env_file
  - Current Mitigations: .env file exclusion
  - Missing: Secret management system
  - Severity: Critical

# BUILD THREAT MODEL

## ASSETS
- Third-party dependencies
- CI/CD pipelines
- Docker build cache
- Testing environments

## TRUST BOUNDARIES
- Between development workstations and CI systems
- Between npm/PyPI repositories and build process
- Between Docker Hub and image pulls

## BUILD THREATS
- **Compromised Dependencies**
  - Description: Malicious packages in 300+ dependencies
  - Impact: Build chain compromise
  - Affected: package.json, pyproject.toml
  - Current Mitigations: Version pinning
  - Missing: SBOM analysis, sigstore verification
  - Severity: High

- **Debug Artifact Leakage**
  - Description: Debug files left in production images
  - Impact: Sensitive data exposure
  - Affected: backend/DebugFileWriter.py
  - Current Mitigations: IS_DEBUG_ENABLED flag
  - Missing: Build-time exclusion
  - Severity: Medium

- **Insecure Base Images**
  - Description: Outdated python:3.12.3-slim-bullseye
  - Impact: Known vulnerabilities
  - Affected: backend/Dockerfile
  - Current Mitigations: None
  - Missing: Regular updates
  - Severity: High

# QUESTIONS & ASSUMPTIONS
1. Are third-party CDN resources monitored for integrity violations?
2. Is there validation of video file formats before processing?
3. How are temporary video processing files secured and cleaned?
4. What mechanisms prevent path traversal in eval file handling?

**Default Assumptions**
- Client browsers implement standard CSP protections
- Video processing libraries receive regular security updates
- WebSocket connections originate from trusted frontend
- CDN providers maintain HTTPS integrity
- Development environments are isolated from production
