## Mitigation Strategies

### 1. **Secure Environment Variable Handling**
**Description:**
Ensure API keys and sensitive configuration values are stored securely using environment variables. Avoid hardcoding secrets in code.

**Steps to Reduce Risk:**
- Place API keys (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `REPLICATE_API_KEY`) in `.env` files that are listed in `.gitignore` to prevent accidental exposure.
- Use a secrets management tool (e.g., Vault, AWS Secrets Manager) for production deployments instead of `.env` files.
- In Docker configurations (`Dockerfile`, `docker-compose.yml`), inject secrets via environment variables or Docker secrets.

**Threats Mitigated:**
- Exposure of API keys in source control or logs (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `REPLICATE_API_KEY`).
- Unauthorized API access by malicious actors.

**Impact:**
Reduces the risk of API key leaks and unauthorized access.

**Currently Implemented:**
Yes (`.env` files are referenced in `backend/.env` and `.gitignore`).
**Missing Implementation:**
No use of secrets management in production. Suggest adding in deployment docs.

---

### 2. **Restrict CORS Configuration**
**Description:**
Limit cross-origin resource sharing (CORS) to only trusted domains to prevent unauthorized access to backend endpoints.

**Steps to Reduce Risk:**
- Update CORS settings in `backend/main.py` to restrict `allow_origins` to specific frontend domains (e.g., `["http://localhost:5173", "https://screenshottocode.com"]`).
- Avoid using `allow_origins=["*"]` in production.

**Threats Mitigated:**
- Cross-Origin Request Forgery (CSRF) attacks.
- Unauthorized cross-origin requests from malicious domains.

**Impact:**
Blocks unintended access to backend APIs.

**Currently Implemented:**
No (current config allows all origins).
**Missing Implementation:**
Need to configure `allow_origins` to trusted domains.

---

### 3. **Input Validation for User-Provided Data**
**Description:**
Validate and sanitize all user inputs (e.g., URLs, images, prompts) to prevent injection attacks and unauthorized operations.

**Steps to Reduce Risk:**
- Sanitize URLs in `routes/screenshot.py` to block malicious schemes (e.g., `javascript://`).
- Validate uploaded images in `routes/screenshot.py` for content type and size to prevent file upload attacks.
- Restrict special characters in prompts to prevent prompt injection attacks (e.g., disallowing `</prompt>` tags).

**Threats Mitigated:**
- XSS (Cross-Site Scripting) via unsanitized generated HTML.
- SSRF (Server-Side Request Forgery) via malicious URLs.

**Impact:**
Prevents malicious inputs from compromising security or execution flow.

**Currently Implemented:**
No explicit validation seen.
**Missing Implementation:**
Add input validation logic in relevant routes.

---

### 4. **Secure Docker Configuration**
**Description:**
 Harden Docker deployments to prevent unauthorized access and expose fewer attack surfaces.

**Steps to Reduce Risk:**
- Use non-root users in Docker containers (modify `backend/Dockerfile` to use a non-root user).
- Limit exposed ports (`docker-compose.yml`) to only required services (e.g., 5173 for frontend and 7001 for backend) and restrict network access.
- Avoid using `EXPOSE` directives without proper network policies.

**Threats Mitigated:**
- Unauthorized access to exposed ports.
- Elevation of privileges in containerized environments.

**Impact:**
Reduces attack surface and container escape risks.

**Currently Implemented:**
Ports are exposed but no network restrictions.
**Missing Implementation:**
Add user restrictions in Dockerfiles and network policies in deployments.

---

### 5. **Dependency Management and Updates**
**Description:**
 Keep dependencies updated to mitigate known vulnerabilities.

**Steps to Reduce Risk:**
- Regularly run dependency scans using `poetry check` and `npm audit` (for frontend).
- Pin versions in `pyproject.toml` and `package.json` to avoid insecure updates.
- Automate dependency updates with tools like Dependabot.

**Threats Mitigated:**
- Exploitation of known vulnerabilities in libraries (e.g., FastAPI, aiohttp, Tailwind CSS).

**Impact:**
Blocks attacks leveraging outdated libraries.

**Currently Implemented:**
No automation for dependency updates.
**Missing Implementation:**
Add dependency scanning and update workflows.

---

### 6. **Secure Generated Code Execution**
**Description:**
Prevent malicious code injection in the generated HTML/CSS/JS outputs.

**Steps to Reduce Risk:**
- Sanitize generated code to block dangerous patterns (e.g., `<script>` tags, event handlers like `onload`).
- Restrict code execution permissions in the frontend (e.g., using Content Security Policy headers).

**Threats Mitigated:**
- Code injection leading to XSS or unauthorized operations.

**Impact:**
Blocks execution of malicious code snippets.

**Currently Implemented:**
No explicit sanitization in `mock_llm.py` or `routes/generate_code.py`.
**Missing Implementation:**
Add sanitization for generated code outputs.

---

### 7. **Rate Limiting and API Key Restrictions**
**Description:**
Prevent abuse of paid APIs (e.g., OpenAI) through rate limiting and key permissions.

**Steps to Reduce Risk:**
- Implement rate limiting in FastAPI endpoints to block excessive requests.
- Restrict API keys to specific services (e.g., limit OpenAI keys to vision models only).

**Threats Mitigated:**
- API abuse leading to unexpected costs or service disruption.

**Impact:**
Prevents unauthorized or excessive API usage.

**Currently Implemented:**
No rate limiting.
**Missing Implementation:**
Add rate-limit middleware (e.g., FastAPI Rate Limiter).

---

### 8. **Secure Logging Practices**
**Description:**
Avoid logging sensitive information like API keys or user data.

**Steps to Reduce Risk:**
- Sanitize logs in `fs_logging/core.py` to exclude sensitive fields.
- Use logging frameworks like `structlog` to redact secrets automatically.

**Threats Mitigated:**
- Exposure of API keys or user data via logs.

**Impact:**
Reduces data leakage risks.

**Currently Implemented:**
No redaction in logs.
**Missing Implementation:**
Add logging filters or redaction for sensitive data.

---

### 9. **Disable Debug Mode in Production**
**Description:**
Prevent exposing debug endpoints or verbose error messages in production.

**Steps to Reduce Risk:**
- Set `IS_PROD` to `True` in production environments (configurable via env vars).
- Disable debug tools like `pyright` and `pytest` in CI/CD pipelines for production builds.

**Threats Mitigated:**
- Exposure of internal errors or debug interfaces to attackers.

**Impact:**
Reduces information disclosure vulnerabilities.

**Currently Implemented:**
No explicit prod mode check.
**Missing Implementation:**
Set `IS_PROD` and disable debug features in production.

---

### 10. **Secure File Uploads**
**Description:**
Prevent file upload vulnerabilities in the screenshot capture feature.

**Steps to Reduce Risk:**
- Validate MIME types and file extensions of uploaded images.
- Store uploaded files in a non-public directory with restricted permissions.

**Threats Mitigated:**
- Upload of malicious files (e.g., `.php` scripts).

**Impact:**
Blocks file-based attacks.

**Currently Implemented:**
No file upload handling seen, but `routes/screenshot.py` uses external APIs.
**Missing Implementation:**
If adding file uploads, implement validation first.

---

### 11. **Content Security Policy (CSP) Headers**
**Description:**
Enforce strict CSP headers to prevent XSS attacks.

**Steps to Reduce Risk:**
- Add CSP headers in frontend HTTP responses (e.g., `Content-Security-Policy` header in `frontend/Dockerfile` or backend responses).

**Threats Mitigated:**
- XSS attacks via inline scripts or external resources.

**Impact:**
Blocks unauthorized script execution in the browser.

**Currently Implemented:**
No CSP headers.
**Missing Implementation:**
Add CSP headers in frontend/backend responses.

---

### 12. **Secure Session Management**
**Description:**
Protect user sessions if the app uses authentication in the future.

**Steps to Reduce Risk:**
- Use secure cookies with `HttpOnly`, `Secure`, and `SameSite` flags.
- Implement token-based authentication with short-lived JWTs.

**Threats Mitigated:**
- Session hijacking and CSRF.

**Impact:**
Secures user sessions (if added).

**Currently Implemented:**
No authentication.
**Missing Implementation:**
Not applicable unless authentication is added later.
