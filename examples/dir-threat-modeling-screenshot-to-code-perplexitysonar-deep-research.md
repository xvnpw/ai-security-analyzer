# Threat Model for Screenshot-to-Code Project

## APPLICATION THREAT MODEL

### ASSETS
1. **AI API Credentials**
   OpenAI and Anthropic API keys stored in frontend settings/local storage and backend .env files
   Critical for accessing paid AI services and billing management

2. **User-Uploaded Media**
   Images/videos containing sensitive mockups or proprietary UI designs submitted through frontend
   Potential PII exposure in video frames

3. Generated Code Repository
   HTML/CSS/JS outputs preserving branding elements from original designs
   Intellectual property protection requirements

4. Model Configuration
   pyproject.toml and package.lock defining AI library versions
   Supply chain attack surface through vulnerable dependencies

### TRUST BOUNDARIES
1. Browser UI ↔ FastAPI Backend
   Boundary enforced through CORS policies and port segregation

2. Backend Server ↔ External AI Providers
   API key authentication boundary for Claude/GPT-4 services

3. Local Development ↔ Production
   Environment variable handling differences between dev mock modes and live keys

### DATA FLOWS
1. Image Upload → Frontend → Backend (crosses boundary 1)
   File validation occurs only at UI layer in screenshot router

2. Backend → OpenAI API (crosses boundary 2)
   Keys transmitted through HTTP headers without encryption

3. Code Output → Browser DOM
   Generated HTML executes untrusted third-party scripts (Tailwind, FontAwesome)

### APPLICATION THREATS

**Threat: API Key Leakage Through Client-Side Storage**
- **Description**: Frontend stores API keys in localStorage vulnerable to XSS
- **Impact**: Financial loss via key abuse, unauthorized AI model access
- **Component**: frontend/src/SettingsDialog
- **Current Mitigations**: Keys only stored in browser memory
- **Missing**: Key rotation schedule, usage monitoring
- **Severity**: Critical

**Threat: Malicious Image Payloads**
- **Description**: Uploaded PNGs could contain exploit code for image processing libraries
- **Impact**: RCE via vulnerable PIL/moviepy dependencies
- **Component**: backend/image_processing/utils.py
- **Current Mitigations**: Basic MIME type checking
- **Missing**: Sandboxed conversion environment
- **Severity**: High

**Threat: Code Injection in Generated Output**
- **Description**: AI models could be prompted to include XSS payloads in HTML
- **Impact**: DOM-based attacks against end users
- **Component**: backend/llm.py streaming logic
- **Current Mitigations**: None in mock_llm.py test cases
- **Missing**: Output sanitization with BeautifulSoup
- **Severity**: Medium

**Threat: Training Data Poisoning**
- **Description**: Adversarial examples in eval dataset could degrade model accuracy
- **Impact**: Reduced code generation quality over time
- **Component**: backend/evals_data/inputs
- **Current Mitigations**: Manual screenshot curation
- **Missing**: Dataset integrity checks
- **Severity**: Low

## DEPLOYMENT THREAT MODEL

### ASSETS
1. Docker Compose Configuration
   Exposed ports and volume mounts in docker-compose.yml

2. Cloud Credentials
   AWS/GCP keys if deploying hosted version

3. TLS Certificates
   SSL termination configuration for frontend/backend

### TRUST BOUNDARIES
1. Container Network ↔ Host System
   Docker socket access and capabilities

2. Reverse Proxy ↔ Application Containers
   Traffic encryption and rate limiting

### DEPLOYMENT THREATS

**Threat: Privilege Escalation via Docker Socket**
- **Description**: docker-compose.yml maps /var/run/docker.sock without user namespace
- **Impact**: Container breakout to host
- **Component**: docker-compose.yml backend service
- **Current Mitigations**: Non-root user in Dockerfile
- **Missing**: Read-only root filesystem
- **Severity**: High

**Threat: Unencrypted Model Traffic**
- **Description**: Anthropic API calls use HTTP instead of HTTPS
- **Impact**: API key interception
- **Component**: backend/llm.py stream_claude_response
- **Current Mitigations**: None in code
- **Missing**: Certificate pinning
- **Severity**: Critical

**Threat: Exposed Debug Endpoints**
- **Description**: /evals route remains accessible in production
- **Impact**: Leakage of test cases and model metrics
- **Component**: backend/routes/evals.py
- **Current Mitigations**: IS_PROD flag exists
- **Missing**: AuthZ checks
- **Severity**: Medium

## BUILD THREAT MODEL

### ASSETS
1. CI/CD Pipelines
   GitHub Actions workflows for testing and deployment

2. Third-Party Dependencies
   poetry.lock and yarn.lock defining exact package versions

3. Build Artifacts
   Docker images pushed to container registry

### TRUST BOUNDARIES
1. Developer Workstation ↔ CI Environment
   Secret management in GitHub Actions

2. Public Package Repositories ↔ Build Process
   PyPI/npm package integrity verification

### BUILD THREATS

**Threat: Compromised Python Dependencies**
- **Description**: Malicious code in anthropic or openai packages
- **Impact**: Backdoor in model communication
- **Component**: backend/pyproject.toml
- **Current Mitigations**: Pinned versions
- **Missing**: Sigstore verification
- **Severity**: High

**Threat: Secrets in Build Logs**
- **Description**: echo commands expose API keys in CI output
- **Impact**: Credential leakage
- **Component**: backend/README.md setup instructions
- **Current Mitigations**: .env file usage
- **Missing**: Pre-commit hooks preventing secrets
- **Severity**: Medium

**Threat: Immutable Build Process**
- **Description**: Docker image tags not pinned to SHA256 hashes
- **Impact**: Supply chain attacks via updated base images
- **Component**: frontend/Dockerfile FROM node:22-bullseye-slim
- **Current Mitigations**: None
- **Missing**: Content trust enforcement
- **Severity**: Low

## QUESTIONS & ASSUMPTIONS

1. **Assumption**: OpenAI/Anthropic API keys are considered short-lived
   **Question**: Are keys automatically rotated after 90 days?

2. **Assumption**: Generated code doesn't process sensitive user data
   **Question**: Should output sanitization be mandatory for all use cases?

3. **Assumption**: Local development uses mock credentials
   **Question**: Are production credentials ever present in dev environments?

4. **Assumption**: Docker networking defaults are secure
   **Question**: Should frontend/backend communication use mutual TLS?

5. **Assumption**: Third-party CDN scripts are trustworthy
   **Question**: Should implement Subresource Integrity hashes?

**Risk Acceptance Notes**:
- Dependency on unverified PyPI packages deemed acceptable due to pinned versions
- No multi-factor auth for API keys considered tolerable for initial MVP
- Public Docker Hub base images used for faster iteration over self-built
