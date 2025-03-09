# Attack Surface Analysis for Screenshot-to-Code Application

## Critical Attack Surfaces

### **1. Exposure of Sensitive API Keys**
- **Description**: The application relies on API keys for services like OpenAI, Anthropic, and Replicate. These keys are stored in environment files (e.g., `.env` in `backend/.env`).
- **How it contributes**: API keys are handled via environment variables but may be exposed through misconfigured deployments, logs, or insecure file storage.
- **Example**: If the `.env` file is accidentally committed to a public repository or exposed via logs, attackers can misuse the keys, leading to unauthorized API calls, financial loss, or abuse of AI models.
- **Impact**: Critical – exposure of API keys could lead to unauthorized resource use or model poisoning.
- **Current Mitigations**: Keys are loaded via environment variables, which is standard practice, but no mention of secrets management tools (e.g., Vault) or rotation policies. `.env` files are excluded from version control but may still be leaked in other ways.
- **Missing Mitigations**:
  - Use of secrets management solutions (e.g., AWS Secrets Manager, Hashicorp Vault).
  - Regular rotation of API keys and monitoring for unauthorized API access.
  - Ensuring `.env` files are not exposed in CI/CD pipelines or logs.

---

### **2. Unvalidated User-Provided Prompts Leading to Code Injection**
- **Description**: The backend processes user-provided inputs (e.g., prompts, image URLs) to generate code.
- **How it contributes**: Malicious users can manipulate prompts to generate harmful code or extract sensitive information from the AI models.
- **Example**: A user could craft a prompt to generate a malicious JavaScript snippet that steals session tokens when executed. Alternatively, prompts could include commands to extract API keys from the backend's context.
- **Impact**: Critical – generated code could directly compromise users' systems or lead to data exfiltration from the AI model's training data.
- **Current Mitigations**: The code includes some validation (e.g., `assemble_prompt` checks for valid `Stack` types), but there’s no explicit input sanitization or rate limiting for generated code content.
- **Missing Mitigations**:
  - Input sanitization and validation for dangerous patterns in prompts.
  - Rate limiting on API endpoints to prevent abuse.
  - Output filtering to block known malicious code patterns.

---

### **3. Insecure Docker Container Configuration**
- **Description**: The Docker setup (`backend/Dockerfile`, `docker-compose.yml`) exposes critical ports (e.g., 7001) without proper access controls.
- **How it contributes**: Misconfigured Docker services might expose the backend to unauthorized access, allowing attackers to interact with the API directly.
- **Example**: If Docker is run on a public-facing server without a firewall, attackers could trigger code generation or access internal endpoints.
- **Impact**: Critical – direct access to backend APIs could lead to key exposure, resource exhaustion, or code generation abuse.
- **Current Mitigations**: No explicit security measures like network restrictions or secrets scanning in Docker builds.
- **Missing Mitigations**:
  - Network policies to restrict container exposure (e.g., using `--network` in Docker compose).
  - Use of read-only containers and minimal base images to reduce attack surface.
  - Scanning Docker images for vulnerabilities using tools like `trivy`.

---

### **4. Data Leakage via Logs or Debugging**
- **Description**: The backend writes logs (via `fs_logging.core.write_logs`) containing AI prompt interactions and generated code.
- **How it contributes**: If logs include sensitive user data (e.g., API keys, personal info in prompts), they could be exposed to unauthorized personnel or due to misconfigured storage.
- **Example**: A user’s prompt includes a password, and the log file is exposed via misconfigured cloud storage.
- **Impact**: Critical – sensitive user data exposure could lead to privacy violations.
- **Current Mitigations**: Logging is done to files but no redaction or encryption is mentioned.
- **Missing Mitigations**:
  - Log redaction for sensitive data (e.g., API keys, user inputs).
  - Secure log storage and access controls.

---

### **5. Dependency Vulnerabilities**
- **Description**: The project uses third-party libraries listed in `backend/pyproject.toml` (e.g., FastAPI, Poetry).
- **How it contributes**: Outdated or vulnerable dependencies could introduce known exploits (e.g., path traversal in FastAPI).
- **Example**: A vulnerability in `fastapi` could allow unauthorized access to backend endpoints.
- **Impact**: Critical – exploitation of library vulnerabilities could lead to full system compromise.
- **Current Mitigations**: No mention of dependency management tools or vulnerability scanning.
- **Missing Mitigations**:
  - Regular dependency updates and scanning tools (e.g., `safety`, `bandit`).
  - Use of a `poetry.lock` file to pin secure versions.

---

## High Attack Surfaces

### **1. Unauthenticated API Access**
- **Description**: The backend exposes endpoints like `/generate-code` and `/evals` without authentication.
- **How it contributes**: Attackers could exploit these endpoints to generate malicious code or deplete API quotas.
- **Example**: A bot repeatedly triggers code generation to exhaust paid API credits.
- **Impact**: High – financial loss and denial of service for legitimate users.
- **Current Mitigations**: No authentication or rate limiting mentioned in the code.
- **Missing Mitigations**:
  - Token-based authentication (JWT) for API access.
  - Rate limiting using tools like `fastapi-limiter`.
  - IP blocking for abusive traffic.

---

### **2. Image/Video Processing Exploits**
- **Description**: The backend processes user-uploaded images and videos (via `video/utils.py`).
- **How it contributes**: Malicious images/videos could trigger buffer overflows or resource exhaustion.
- **Example**: A malformed video file crashes the `moviepy` library, leading to a DoS.
- **Impact**: High – service unavailability and potential remote code execution.
- **Current Mitigations**: Basic error handling in the code but no input sanitization for file formats.
- **Missing Mitigations**:
  - Input validation for image/video formats and size limits.
  - Using secure libraries (e.g., PIL with sandboxing) for processing.

---

### **3. Cross-Site Scripting (XSS) in Frontend**
- **Description**: The frontend (React/Vite) might reflect user inputs without sanitization.
- **How it contributes**: Malicious users could inject scripts via prompt URLs or image metadata.
- **Example**: A crafted URL parameter in the frontend triggers JavaScript execution to steal cookies.
- **Impact**: High – session hijacking and data theft from users.
- **Current Mitigations**: Frontend code not provided, but the backend’s API lacks XSS protections (e.g., no headers like `Content-Security-Policy`).
- **Missing Mitigations**:
  - Implementing CSP headers in frontend responses.
  - Sanitizing user inputs in the frontend and backend.

---

### **4. Exposure of Debugging Artifacts**
- **Description**: The debug module (`debug/DebugFileWriter.py`) writes files to disk during development.
- **How it contributes**: Debug logs might include API keys, prompts, or generated code if left enabled in production.
- **Example**: Debug files stored in a public-accessible directory exposing API interaction details.
- **Impact**: High – sensitive data exposure.
- **Current Mitigations**: Debugging is controlled via `IS_DEBUG_ENABLED`, but no checks for secure file storage.
- **Missing Mitigations**:
  - Disabling debugging in production.
  - Secure deletion of debug files post-processing.

---

## Medium Attack Surfaces

### **1. Weak Secret Management in Configuration**
- **Description**: Environment variables are managed via `.env` files without encryption.
- **How it contributes**: Misplaced `.env` files (e.g., in public repositories) can leak secrets.
- **Example**: A developer accidentally commits a `.env` file to GitHub, exposing API keys.
- **Impact**: Medium – potential misuse of keys but mitigated by proper version control policies.
- **Current Mitigations**: `.gitignore` excludes `.env`, but human error can bypass this.
- **Missing Mitigations**:
  - Educating developers on secret management best practices.
  - Using environment variable vaults for CI/CD pipelines.

---

### **2. Lack of Input Validation in Evals**
- **Description**: The `/evals` endpoints (routes/evals.py) process user-provided directories.
- **How it contributes**: Path traversal in `folder` parameters could access sensitive files.
- **Example**: A malicious user passes `folder=../../etc/` to access system files.
- **Impact**: Medium – data leakage from the server’s file system.
- **Current Mitigations**: No input sanitization for path parameters.
- **Missing Mitigations**:
  - Sanitizing input paths to prevent traversal (e.g., `os.path.normpath`).
  - Restricting filesystem access for the backend service user.

---

### **3. Unprotected WebSocket Endpoints**
- **Description**: WebSocket endpoints (`/generate-code`) handle unauthenticated connections.
- **How it contributes**: Attackers could flood the endpoint to exhaust server resources.
- **Example**: A bot opens thousands of WebSocket connections to trigger a DoS.
- **Impact**: Medium – service unavailability.
- **Current Mitigations**: No rate limiting or connection pooling.
- **Missing Mitigations**:
  - Limiting concurrent WebSocket connections.
  - Implementing connection timeouts and idle detection.

---

## Summary of Prioritized Remediations

**Critical**:
1. **Secure API Key Management**: Integrate secrets management tools (e.g., Hashicorp Vault) and enforce key rotation.
2. **Input Sanitization and Validation**: Implement strict validation for prompts and user inputs to block malicious patterns.
3. **Docker Hardening**: Restrict network exposure, use minimal base images, and scan Docker images for vulnerabilities.
4. **Dependency Updates**: Regularly update dependencies and run vulnerability scans (e.g., `safety check`).
5. **Audit Logging**: Redact sensitive data in logs and ensure secure log storage.

**High**:
1. **Authentication and Rate Limiting**: Implement JWT authentication and rate-limiting middleware for API endpoints.
2. **Secure Image/Video Processing**: Validate and limit file formats/sizes; use secure libraries.
3. **XSS Protections**: Enforce Content-Security-Policy headers and input sanitization in the frontend.

**Medium**:
1. **Path Sanitization**: Sanitize inputs to `/evals` endpoints to prevent path traversal.
2. **WebSocket Rate Limits**: Restrict concurrent WebSocket connections to prevent abuse.

By addressing these critical and high-risk areas first, the application can significantly reduce its exposure to realistic threats.
