# Threat Modeling Analysis for "screenshot-to-code" Using Attack Trees

---

## 1. Understand the Project

### Overview
The application converts screenshots, mockups, and Figma designs into functional code using AI (GPT-4 Vision, Claude). It runs on a React/Vite frontend and FastAPI backend, with Docker support.

### Key Components
- **Backend**: FastAPI for API endpoints, LLM interaction (OpenAI, Anthropic).
- **Frontend**: React/Vite for user interface.
- **LLM Integration**: Handles API keys for models like GPT-4 and Claude.
- **Image/Video Processing**: Uses libraries like `moviepy` and `PIL`.
- **Docker**: Containerization of backend/frontend.

---

## 2. Define Root Goal
**Attacker's Goal**:
Exploit weaknesses in the application's code, API key management, or input processing to compromise systems using the tool.

---

## 3. High-Level Attack Paths

### Sub-Goal 1: Exploit API Key Management Vulnerabilities
**Attack Path**: Steal or misuse API keys to gain unauthorized access to paid models.

---

### Sub-Goal 2: Inject Malicious Inputs to Generate Harmful Code
**Attack Path**: Manipulate input (images/videos) to trick AI into generating malicious code (e.g., phishing scripts).

---

### Sub-Goal 3: Exploit CORS Misconfiguration
**Attack Path**: Exploit `Access-Control-Allow-Origin: *` to perform cross-site attacks.

---

### Sub-Goal 4: Exploit Insecure Docker Configuration
**Attack Path**: Exploit misconfigured Docker settings to gain unauthorized access to backend services.

---

### Sub-Goal 5: Bypass Image/Video Processing Sanitization
**Attack Path**: Upload malicious files (e.g., hidden scripts in images) to exploit server-side vulnerabilities.

---

### Sub-Goal 6: Exploit Outdated Dependencies
**Attack Path**: Exploit vulnerabilities in outdated packages like FastAPI or Uvicorn.

---

### Sub-Goal 7: Leverage Unsecured Evaluation Endpoints
**Attack Path**: Access evaluation dataset or endpoints to harvest model outputs or credentials.

---

## 4. Attack Tree Visualization

```
Root Goal: Compromise systems using "screenshot-to-code"

[OR]
├── 1. Exploit API Key Management Vulnerabilities
│   [OR]
│   ├── 1.1 Extract API keys from misconfigured .env files
│   │   [AND]
│   │   ├── 1.1.1 Application exposes .env files via misconfigured routing (e.g., /backend/.env accessible)
│   │   └── 1.1.2 Docker compose leaks environment variables in logs
│   └── 1.2 Steal API keys via exposed logs or debug endpoints
│       [AND]
│       ├── 1.2.1 Logs contain API keys (e.g., via unfiltered logging in config.py)
│       └── 1.2.2 Attacker accesses logging endpoints (e.g., /logs)
│
├── 2. Inject Malicious Inputs to Generate Harmful Code
│   [OR]
│   ├── 2.1 Trick AI into generating malicious HTML/JS code
│   │   [AND]
│   │   ├── 2.1.1 Upload crafted image prompting phishing links or XSS
│   │   └── 2.1.2 Exploit prompt injection via frontend inputs
│   └── 2.2 Exploit inadequate sanitization in code display
│       [AND]
│       ├── 2.2.1 User executes generated code without review
│       └── 2.2.2 Code contains malicious scripts (e.g., cryptojacking)
│
├── 3. Exploit CORS Misconfiguration
│   [OR]
│   ├── 3.1 Perform Cross-Site Request Forgery (CSRF) to execute code generation
│   └── 3.2 Steal user session cookies via cross-domain requests
│
├── 4. Exploit Insecure Docker Configuration
│   [OR]
│   ├── 4.1 Run arbitrary code via exposed Docker API
│   │   [AND]
│   │   ├── 4.1.1 Docker API is publicly accessible
│   │   └── 4.1.2 Default privileged mode exposes host system
│   └── 4.2 Extract secrets from Docker volumes
│       [AND]
│       ├── 4.2.1 Volume mounts include sensitive files
│       └── 4.2.2 Attacker gains container access (e.g., via misconfigured /etc/passwd)
│
├── 5. Bypass Image/Video Processing Sanitization
│   [OR]
│   ├── 5.1 Upload malicious image with hidden payloads
│   │   [AND]
│   │   ├── 5.1.1 Image contains EXIF scripts (e.g., PHP payloads)
│   │   └── 5.1.2 Server processes image without sanitization
│   └── 5.2 Exploit video processing to trigger DoS
│       [AND]
│       ├── 5.2.1 Submit extremely large video files
│       └── 5.2.2 Overload server resources during processing
│
├── 6. Exploit Outdated Dependencies
│   [OR]
│   ├── 6.1 Exploit known FastAPI vulnerability (CVE-XXXX-XXXX)
│   └── 6.2 Exploit insecure Uvicorn configuration
│
└── 7. Leverage Unsecured Evaluation Endpoints
    [OR]
    ├── 7.1 Access evaluation dataset to mine sensitive user data
    └── 7.2 Abuse model outputs for credential harvesting
```

---

## 5. Threat Assessment Table

| Threat Path                                                                 | Likelihood | Impact  | Effort  | Skill Level | Detection Difficulty |
|-----------------------------------------------------------------------------|------------|---------|---------|-------------|----------------------|
| 1.1 Extract API keys from misconfigured .env files                          | High       | Critical| Low     | Low         | Easy                 |
| 1.2 Steal API keys via exposed logs                                          | Medium     | Critical| Medium  | Medium      | Medium               |
| 2.1 Trick AI into generating malicious code                                  | Medium     | High    | Medium  | High        | Hard                 |
| 3.1 Exploit CORS to steal session cookies                                    | High       | Critical| Low     | Low         | Easy                 |
| 4.1 Run arbitrary code via exposed Docker API                                | High       | Critical| Medium  | High        | Medium               |
| 5.1 Exploit malicious images for remote code execution                       | Medium     | High    | Medium  | High        | Hard                 |
| 6.1 Exploit outdated FastAPI dependencies                                    | Low        | Critical| Medium  | High        | Medium               |
| 7.1 Access unsecured evaluation data                                          | Medium     | Medium  | Low     | Low         | Easy                 |

---

## 6. Priority Threats

### High-Risk Paths
1. **API Key Exposure (Path 1)**:
   - **Why**: Misconfigured .env files or logs expose credentials, enabling unauthorized LLM access.
   - **Mitigation**: Use secure secret management (e.g., AWS Secrets Manager) and restrict .env file permissions.

2. **CORS Misconfiguration (Path 3)**:
   - **Why**: `Access-Control-Allow-Origin: *` allows any site to perform requests.
   - **Mitigation**: Restrict allowed origins to trusted domains.

3. **Malicious Code Generation (Path 2.1)**:
   - **Why**: Users may execute AI-generated code without review, leading to XSS or RCE.
   - **Mitigation**: Sanitize outputs, add warnings, and implement code previews.

---

## 7. Mitigation Strategies

### 1. Secure API Key Management:
- **Action**: Enforce environment variable best practices and use secrets management tools.
- **Code Fix**:
  ```python
  # config.py
  # Validate API keys are not exposed in logs
  def should_log_api_keys():
      return False  # Disable logging sensitive data
  ```

### 2. Harden CORS Configuration:
- **Action**: Restrict `Access-Control-Allow-Origin` to specific domains.
- **Code Fix**:
  ```python
  # main.py
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["https://trusted-domain.com"],
      allow_methods=["GET", "POST"],
      allow_headers=["Content-Type"],
  )
  ```

### 3. Sanitize Generated Code:
- **Action**: Escape HTML in code previews and add warnings.
- **Code Fix**:
  ```javascript
  // frontend/src/components/CodePreview.js
  const sanitizedCode = code.replace(/</g, "&lt;");
  return <pre>{sanitizedCode}</pre>;
  ```

### 4. Docker Security:
- **Action**: Use non-privileged containers and restrict exposed ports.
- **Dockerfile Fix**:
  ```dockerfile
  # backend/Dockerfile
  USER nobody  # Existing, but ensure no other privileges
  EXPOSE 7001
  ```

### 5. Input Validation:
- **Action**: Validate image/video formats and size limits.
- **Code Fix**:
  ```python
  # routes/screenshot.py
  def validate_image(file):
      if file.size > 10 * 1024 * 1024:  # 10MB limit
          raise ValueError("File too large")
  ```

---

## 8. Summary of Findings

### Key Risks
- Exposed API keys due to misconfigured secrets.
- CORS misconfiguration enabling cross-site attacks.
- Lack of input sanitization for AI-generated code.

### Recommended Actions
1. **Immediate**: Audit and secure API key handling.
2. **High Priority**: Restrict CORS origins and sanitize outputs.
3. **Medium Priority**: Validate image/video uploads and update dependencies.

---

## 9. Questions & Assumptions
- **Questions**:
  - Are `.env` files properly restricted in production deployments?
  - Are Docker environments isolated from host systems?
- **Assumptions**:
  - The application runs in a cloud environment with default network configurations.
  - Users are technically capable to review generated code before execution.
