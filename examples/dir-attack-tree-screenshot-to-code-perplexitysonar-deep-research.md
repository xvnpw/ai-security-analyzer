# Threat Modeling Analysis for the screenshot-to-code Project Using Attack Trees

## 1. Understand the Project

### Overview
The screenshot-to-code project is an AI-powered tool that converts visual inputs (screenshots, Figma designs, videos) into functional code across multiple stacks including HTML/Tailwind, React, Vue, and Bootstrap. It leverages cutting-edge AI models like Claude 3.7 Sonnet and GPT-4o for code generation, with a distributed architecture comprising a React/Vite frontend and FastAPI backend. The system supports Docker deployment and integrates with third-party APIs for image generation and payment processing in its hosted version.

### Key Components
- **AI Code Generation Core**: Handled by `backend/llm.py`, interfaces with Claude/GPT-4 via API
- **Image Processing Pipeline**: `backend/image_processing/utils.py` optimizes images for AI model constraints
- **Evaluation Framework**: `backend/evals/runner.py` enables quantitative model comparison
- **Video-to-Code Subsystem**: `backend/video/utils.py` processes screen recordings
- **Multi-Container Deployment**: Docker setup in `docker-compose.yml` with isolated frontend/backend services

### Critical Dependencies
- Anthropic/OpenAI API keys for AI model access
- Replicate API for image generation alternatives
- WebSockets for real-time code streaming
- Poetry for Python dependency management
- Tailwind CSS CDN in generated code outputs

## 2. Root Goal of the Attack Tree
**Compromise systems using screenshot-to-code by exploiting weaknesses in:**
1. AI model integration points
2. Code generation trust boundaries
3. Third-party dependency chains
4. Deployment configuration surfaces
5. User-supplied input handling

```
Root Goal: Compromise systems using screenshot-to-code by exploiting project weaknesses
[OR]
+-- 1. Inject malicious code via AI model outputs
    [OR]
    +-- 1.1 Poison training data/evals
    +-- 1.2 Manipulate model API responses
    +-- 1.3 Exploit prompt injection vulnerabilities

+-- 2. Exploit code generation vulnerabilities
    [OR]
    +-- 2.1 Insert XSS payloads in generated HTML
    +-- 2.2 Bypass CSP in template outputs
    +-- 2.3 Inject malicious npm/CDN dependencies

+-- 3. Compromise deployment infrastructure
    [AND]
    +-- 3.1 Exploit Docker misconfigurations
        [OR]
        +-- 3.1.1 Privilege escalation in containers
        +-- 3.1.2 Vulnerable base images
    +-- 3.2 Steal API keys from .env/memory

+-- 4. Abuse image/video processing
    [OR]
    +-- 4.1 RCE via malicious image metadata
    +-- 4.2 DoS through oversized media inputs
    +-- 4.3 Steal credentials via EXIF data

+-- 5. Exploit evaluation subsystem
    [AND]
    +-- 5.1 Tamper with evals_data/inputs
    +-- 5.2 Manipulate rating metrics
```

## 3. Attack Tree Visualization

```
Root Goal: Compromise systems using screenshot-to-code
[OR]
+-- 1. AI Model Exploitation
    [OR]
    +-- 1.1 API Key Compromise
        [OR]
        +-- 1.1.1 Leak via .env exposure [Likelihood: High]
        +-- 1.1.2 Intercept in browser storage [Medium]
    +-- 1.2 Malicious Output Generation
        [AND]
        +-- 1.2.1 Bypass AI content filters [High Skill]
        +-- 1.2.2 Disable HTML sanitization [Medium]

+-- 2. Code Generation Risks
    [OR]
    +-- 2.1 Insecure Dependencies
        +-- 2.1.1 Outdated Tailwind CDN [High Impact]
    +-- 2.2 XSS Injection Vectors
        [OR]
        +-- 2.2.1 Unsanitized {{variables}} [High]
        +-- 2.2.2 Malicious SVG content [Medium]

+-- 3. Deployment Attacks
    [AND]
    +-- 3.1 Docker Privilege Escalation
        +-- 3.1.1 Host PID namespace exposure [Critical]
    +-- 3.2 Poisoned Package
        +-- 3.2.1 Compromised poetry.lock [High Effort]

+-- 4. Media Processing Exploits
    [OR]
    +-- 4.1 ImageTragick-style RCE
        +-- 4.1.1 Via image_processing/utils.py [High Skill]
    +-- 4.2 Memory Exhaustion
        +-- 4.2.1 4K video input processing [Medium]
```

## 4. Risk Analysis Matrix

| Attack Path                | Likelihood | Impact | Effort | Skill  | Detection | Justification
|----------------------------|------------|--------|--------|--------|-----------|-------------
| 1.1.1 .env Key Exposure     | High       | Critical | Low    | Low    | Medium    | Common misconfiguration
| 2.2.1 XSS via Templates     | Medium     | High    | Medium | Medium | Hard      | AI may bypass sanitization
| 3.1.1 Docker PrivEsc        | Low        | Critical | High   | High   | Easy      | Container breakout critical
| 4.1.1 ImageMagick RCE       | Low        | Critical | High   | High   | Hard      | Difficult but high payoff

## 5. Mitigation Strategies

### AI Model Security
- Implement output validation with **Semgrep rules** against generated code
- Use **separate API keys** for generation vs. eval modes
- Add **AI output signing** with HMAC when possible

### Code Generation Hardening
- Enforce **Content Security Policy** in template headers
- **Sandbox** generated code in iframes during preview
- Use **Subresource Integrity** for CDN dependencies

### Infrastructure Protections
- Rotate API keys **hourly** using Vault dynamic secrets
- Implement **eBPF-based runtime security** for containers
- Restrict container capabilities with **seccomp profiles**

### Media Processing Safety
- Use **libvips** instead of Pillow for image processing
- Implement **frame rate limits** for video inputs
- Add **EXIF stripping** pipeline stage

## 6. Critical Findings

1. **Unrestricted AI Code Execution**
Generated code includes unguarded script tags and third-party CDN dependencies without SRI. An attacker could craft inputs that produce XSS payloads.

2. **Ephemeral Key Management**
API keys persist in browser localStorage without rotation. Compromise allows unlimited model access.

3. **Container Privilege Escalation**
Docker deployment runs with `--privileged` flags, allowing host filesystem access through volume mounts.

## 7. Recommended Actions

1. Immediate:
- Implement output sanitization with **DOMPurify** for generated HTML
- Add **key rotation** workflow for Anthropic/OpenAI credentials

2. Short-term (1-3 months):
- Deploy **Sigstore** for AI output provenance tracking
- Transition to **OWASP ZAP** for automated code screening

3. Long-term:
- Develop **ML-based anomaly detection** for generated code patterns
- Implement **TEE-based** model inference using AWS Nitro

## 8. Assumptions & Questions

- Assumed Claude 3.7 has adequate guardrails against prompt injection
- Are video processing jobs isolated in firecracker microVMs?
- Is there audit logging for code generation requests?

This analysis demonstrates that while screenshot-to-code enables powerful capabilities, its integration of multiple AI models and code generation pipelines creates a complex attack surface requiring defense-in-depth measures. The highest risks stem from the combination of untrusted inputs, powerful model capabilities, and deployment configuration choices.
