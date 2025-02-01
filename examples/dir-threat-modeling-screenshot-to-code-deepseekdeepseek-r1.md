# THREAT MODEL

## APPLICATION THREAT MODEL

### ASSETS
- AI-generated code: Valuable intellectual property and core functionality
- User-provided screenshots/designs: Potential sensitive information in uploaded images
- Video input data: User-uploaded video content containing potential sensitive visual information
- API keys (OpenAI/Anthropic/Gemini): Financial and access credentials
- User session data: Potential tracking of user interactions
- Configuration files (.env): Contains sensitive API keys and settings
- Evaluation datasets: Proprietary test data for AI model validation

### TRUST BOUNDARIES
- Frontend (React) <-> Backend (FastAPI)
- Backend <-> External AI APIs (OpenAI/Anthropic/Gemini)
- User browser <-> Third-party CDNs (Tailwind, Google Fonts, Font Awesome, Vue/React scripts)
- Application <-> Image processing services (Replicate/Flux)
- Backend <-> Video processing services (MoviePy/Claude video analysis)
- Application <-> ScreenshotOne API

### DATA FLOWS
1. User uploads image -> Backend (crosses trust boundary)
2. Backend -> AI API (crosses trust boundary)
3. AI API -> Generated code -> User (crosses trust boundary)
4. Frontend <-> Backend via WebSocket (within trust boundary)
5. Backend <-> Image hosting services (crosses trust boundary)
6. User uploads video -> Backend video processing (crosses trust boundary)
7. Backend <-> ScreenshotOne API for website captures (crosses trust boundary)
8. Video frames -> Claude API for analysis (crosses trust boundary)

### APPLICATION THREATS
- Malicious video uploads
  - Attacker uploads exploit-containing video files
  - Impact: Server compromise via video processing vulnerabilities
  - Affects: backend/video/utils.py
  - Current mitigations: Temporary file storage during processing
  - Missing: Video format validation, sandboxed processing
  - Severity: Medium

- Third-party script integrity
  - Compromised CDN serving Vue/React/Tailwind scripts
  - Impact: XSS attacks through malicious library versions
  - Affects: All generated HTML outputs using CDN resources
  - Current mitigations: None evident in code
  - Missing: Subresource Integrity (SRI) hashes for external scripts
  - Severity: High

- Video data leakage
  - Exposure of sensitive information in video frames
  - Impact: Privacy violations from unprocessed video data
  - Affects: video/utils.py split_video_into_screenshots()
  - Current mitigations: Temporary storage during processing
  - Missing: Encryption of video data at rest
  - Severity: Medium

- Prompt injection via video frames
  - Hidden visual prompts in video content manipulating AI output
  - Impact: Code injection in generated HTML
  - Affects: backend/llm.py video processing path
  - Current mitigations: None evident
  - Missing: Visual content sanitization
  - Severity: Medium

- Screenshot API abuse
  - Attacker abuses ScreenshotOne API through stolen credentials
  - Impact: Financial loss from API overuse
  - Affects: routes/screenshot.py
  - Current mitigations: API key passed through client
  - Missing: Rate limiting, key rotation
  - Severity: High

## DEPLOYMENT THREAT MODEL

### ASSETS
- Docker configurations
- Environment variables with secrets
- CI/CD pipeline integrity
- Container registry contents

### TRUST BOUNDARIES
- Docker host <-> Container runtime
- Internal network <-> Public internet
- Build servers <-> Docker registries

### DEPLOYMENT THREATS
- Compromised Docker images
  - Attacker injects malware into built images
  - Impact: Containerized environment compromise
  - Affects: docker-compose.yml, Dockerfiles
  - Current mitigations: Official base images
  - Missing: Image signing/verification
  - Severity: High

- Exposed environment variables
  - Attacker reads .env files through misconfiguration
  - Impact: API key leakage
  - Affects: Docker deployment setup
  - Current mitigations: File-based configuration
  - Missing: Runtime secret injection
  - Severity: Critical

## BUILD THREAT MODEL

### ASSETS
- Source code repository
- Third-party dependencies
- Build artifacts
- CI/CD configuration

### TRUST BOUNDARIES
- CI/CD system <-> Package repositories
- Developer machines <-> Version control
- Build pipelines <-> External services

### BUILD THREATS
- Compromised dependencies
  - Attacker poisons PyPI/npm packages
  - Impact: Build chain compromise
  - Affects: poetry.lock, package.json
  - Current mitigations: Lock files
  - Missing: Dependency auditing
  - Severity: High

- Malicious CI scripts
  - Attacker modifies GitHub Actions workflows
  - Impact: Backdoor insertion
  - Affects: .github/workflows
  - Current mitigations: None shown
  - Missing: Workflow signing
  - Severity: Medium

## QUESTIONS & ASSUMPTIONS
1. How are video files cleaned up after processing?
   - Assumption: Temporary files deleted after processing
2. Is there validation for maximum video upload size?
   - Assumption: No size limits implemented
3. Are third-party CDNs reviewed for security compliance?
   - Assumption: CDN providers considered trustworthy
4. How often are dependency audits performed?
   - Assumption: Manual audit process
5. Is there monitoring for abnormal video processing times?
   - Assumption: No performance monitoring

### DEFAULT ASSUMPTIONS
- Video processing occurs in memory without persistent storage
- All third-party script providers maintain integrity
- ScreenshotOne API credentials are properly rotated
- MoviePy dependencies are kept up-to-date
- Video frame extraction doesn't expose sensitive system information

### UNLIKELY THREATS
- Compromise of all CDN providers simultaneously
- Zero-day in video processing library (MoviePy)
- Physical tampering with screenshot API infrastructure
- Quantum computing breaking TLS during video transmission
