- Mitigation Strategy: Secure API Key Management
  - Description:
    1. **Environment Variables:** Store API keys (OpenAI, Anthropic, Gemini, Replicate, ScreenshotOne) as environment variables in the backend, as currently suggested in `README.md` and `docker-compose.yml`. Avoid hardcoding keys in the code.
    2. **`.env` File Security:** Ensure the `.env` file (containing API keys) is not committed to version control (already good practice, but explicitly mention). Add `.env` to `.gitignore`.
    3. **Restrict Access:** Limit access to the server or environment where the backend is deployed to authorized personnel only.
    4. **Key Rotation:** Implement a process for regularly rotating API keys to minimize the impact of potential key compromise.
    5. **Vault/Secret Management:** For production environments, consider using a dedicated secret management system (like HashiCorp Vault, AWS Secrets Manager, or similar) to store and manage API keys more securely instead of relying solely on `.env` files.
  - Threats Mitigated:
    - API Key Exposure (High Severity): Prevents unauthorized access to AI models and ScreenshotOne API by securing the API keys.
  - Impact:
    - API Key Exposure: High reduction in risk. Makes it significantly harder for attackers to obtain API keys.
  - Currently Implemented:
    - Partially implemented. `.env` file usage is mentioned in `README.md` and `docker-compose.yml`.
  - Missing Implementation:
    - Key rotation process is not mentioned.
    - Use of a dedicated secret management system for production is not mentioned.
    - Explicit instruction to add `.env` to `.gitignore` is missing in documentation.
    - Secure management of ScreenshotOne API key is not explicitly mentioned.

- Mitigation Strategy: Implement Rate Limiting and Cost Controls
  - Description:
    1. **Backend Rate Limiting:** Implement rate limiting on the backend API endpoints that interact with LLMs and ScreenshotOne API. This can be done using libraries available in FastAPI (e.g., `slowapi`). Limit requests per user or IP address within a specific time window.
    2. **Budget Monitoring:** Set up budget alerts and monitoring for the AI API usage (OpenAI, Anthropic, Gemini, Replicate) and ScreenshotOne API to track costs and prevent unexpected overspending. Utilize the billing dashboards provided by these API providers.
    3. **Usage Quotas:** Define and enforce usage quotas for different user tiers or usage scenarios if applicable.
    4. **Error Handling for API Limits:** Implement proper error handling in the backend to gracefully manage API rate limit errors and inform users appropriately, suggesting retry mechanisms with backoff.
  - Threats Mitigated:
    - Rate Limiting and Cost Management (Medium Severity): Prevents budget overruns and service disruptions due to excessive API usage for both LLMs and ScreenshotOne.
    - Denial of Service (DoS) (Medium Severity): Rate limiting can help mitigate simple DoS attacks by limiting the request rate from a single source.
  - Impact:
    - Rate Limiting and Cost Management: High reduction in risk. Provides control over API costs and prevents unexpected bills.
    - Denial of Service (DoS): Medium reduction in risk. Makes it harder to overwhelm the backend with requests from a single source.
  - Currently Implemented:
    - Not implemented. No rate limiting or cost control mechanisms are evident in the provided files.
  - Missing Implementation:
    - Rate limiting logic in backend API endpoints for both LLM and ScreenshotOne APIs.
    - Budget monitoring and alerting system for both LLM and ScreenshotOne APIs.
    - Usage quota enforcement.
    - Error handling for API rate limits.

- Mitigation Strategy: Enhance Data Security and Privacy
  - Description:
    1. **HTTPS for All Communication:** Ensure all communication between the frontend and backend, and between the backend and AI APIs, and ScreenshotOne API is over HTTPS to encrypt data in transit. This is standard practice but should be explicitly verified.
    2. **Secure Storage (Browser):** While `Troubleshooting.md` mentions keys are stored in the browser, clarify the security measures for browser storage (e.g., `localStorage` or `IndexedDB`). Emphasize that browser storage is not fully secure and sensitive data should be minimized client-side. Reiterate that API keys are only stored in the browser and not on servers as stated in `Troubleshooting.md`.
    3. **Data Minimization:** Minimize the amount of user data stored and processed. Only collect and process data that is strictly necessary for the application's functionality.
    4. **No Server-Side Logging of User Data:** Avoid logging user-uploaded screenshots, video recordings, or captured website screenshots on the server-side. If logging is necessary for debugging, ensure it does not include sensitive user data and is securely managed. Review `fs_logging/core.py` to ensure no sensitive data is logged.
    5. **Privacy Policy:** Implement a clear privacy policy that informs users about how their data is collected, used, and protected.
  - Threats Mitigated:
    - Data Security and Privacy (Medium to High Severity): Reduces the risk of data leakage and unauthorized access to user-uploaded screenshots and videos, and captured website screenshots.
  - Impact:
    - Data Security and Privacy: Medium to High reduction in risk. Improves user data protection and builds trust.
  - Currently Implemented:
    - Partially implemented. HTTPS is generally expected for web applications, but explicit confirmation and enforcement are needed. `Troubleshooting.md` mentions browser storage.
  - Missing Implementation:
    - Explicit HTTPS enforcement.
    - Detailed explanation of browser storage security and its limitations.
    - Data minimization strategy is not explicitly mentioned.
    - Server-side logging review to prevent sensitive data logging, especially for website screenshots.
    - Privacy policy is not mentioned in the provided files.

- Mitigation Strategy: Dependency Scanning and Management
  - Description:
    1. **Regular Dependency Scanning:** Implement automated dependency scanning for both frontend (Yarn/npm) and backend (Poetry) dependencies using tools like `npm audit`, `yarn audit`, and `poetry check` or dedicated vulnerability scanning tools (e.g., Snyk, OWASP Dependency-Check). Integrate these scans into the CI/CD pipeline.
    2. **Dependency Updates:** Regularly update dependencies to the latest versions to patch known vulnerabilities. Follow security advisories and patch releases from dependency maintainers.
    3. **Lock Files:** Ensure lock files (`yarn.lock`, `poetry.lock`) are used and committed to version control to maintain consistent dependency versions across environments and prevent supply chain attacks.
    4. **Vulnerability Monitoring:** Set up alerts for newly discovered vulnerabilities in used dependencies to proactively address them.
  - Threats Mitigated:
    - Dependency Vulnerabilities (Medium Severity): Reduces the risk of exploiting known vulnerabilities in third-party libraries like `openai`, `moviepy`, `Pillow`, `fastapi`, `httpx` and others.
  - Impact:
    - Dependency Vulnerabilities: Medium reduction in risk. Keeps the application protected against known dependency vulnerabilities.
  - Currently Implemented:
    - Partially implemented. `pyproject.toml`, `package.json`, `yarn.lock` and Dockerfiles exist, indicating dependency management is in place. `poetry run pyright` and `poetry run pytest` in `backend/README.md` suggest some level of code quality checks.
  - Missing Implementation:
    - Automated dependency scanning is not explicitly mentioned or integrated into CI/CD.
    - Regular dependency update process is not documented.
    - Vulnerability monitoring and alerting are not mentioned.

- Mitigation Strategy: Input Validation and Sanitization
  - Description:
    1. **File Path Validation:** In `evals.py`, thoroughly validate user-provided folder paths to prevent path traversal vulnerabilities. Ensure paths are within expected directories and sanitize input to remove malicious characters.
    2. **Limit Input File Sizes:** Implement limits on the size of uploaded screenshots and video files in `generate_code.py` and `video/utils.py` to prevent excessively large files that could cause resource exhaustion or DoS.
    3. **File Type Validation:** Validate the file types of uploaded images and videos to ensure they are expected formats (e.g., PNG, JPG, MOV, MP4) in `generate_code.py` and `video/utils.py`.
    4. **Image/Video Processing Limits:** Implement safeguards in image/video processing functions (`image_processing/utils.py`, `video/utils.py`) to prevent processing of maliciously crafted files that could exploit vulnerabilities in image/video libraries (e.g., Pillow, moviepy). Consider using secure processing libraries and keeping them updated.
    5. **URL Validation:** In `screenshot.py`, validate the input URL to `capture_screenshot` to prevent unexpected behavior or SSRF vulnerabilities. Use a URL parsing library to ensure the URL is well-formed and potentially restrict allowed schemes (e.g., `http`, `https`).
    6. **Content Security Policy (CSP):** Implement a Content Security Policy in the frontend to mitigate potential XSS risks if the generated code is directly rendered in the application.
  - Threats Mitigated:
    - Path Traversal (Medium Severity): Prevents attackers from accessing files outside of the intended directories in `evals.py`.
    - Denial of Service (DoS) (Medium Severity): Prevents resource exhaustion from processing excessively large files or maliciously crafted files.
    - Code Injection (Indirect) (Low to Medium Severity): Reduces the risk of vulnerabilities in generated code by limiting input types and sizes, and through CSP (though indirect).
    - Server-Side Request Forgery (SSRF) (Low Severity): Reduces the risk of unintended external requests via `screenshot.py`.
  - Impact:
    - Path Traversal: Medium reduction in risk. Prevents unauthorized file access.
    - Denial of Service (DoS): Low to Medium reduction in risk. Makes it harder to cause resource exhaustion through malicious inputs.
    - Code Injection (Indirect): Low reduction in risk. Provides a layer of defense against potential vulnerabilities in generated code.
    - Server-Side Request Forgery (SSRF): Low reduction in risk. Limits the scope of potential SSRF issues.
  - Currently Implemented:
    - Not explicitly implemented. File path validation, file type validation and size limits are not evident in the provided files. `image_processing/utils.py` and `video/utils.py` exist for image/video processing, but security aspects are not detailed. URL validation in `screenshot.py` is missing.
  - Missing Implementation:
    - File path validation in `evals.py`.
    - Input file size limits in `generate_code.py` and `video/utils.py`.
    - File type validation in `generate_code.py` and `video/utils.py`.
    - Security review of image/video processing logic and libraries in `image_processing/utils.py` and `video/utils.py`.
    - URL validation in `screenshot.py`.
    - Content Security Policy (CSP) implementation in frontend.

- Mitigation Strategy: Disable or Secure Mock Mode in Production
  - Description:
    1. **Environment-Based Configuration:** Ensure the `MOCK` environment variable (used for mock mode in `backend/config.py`) is strictly set to `False` or not defined in production deployments.
    2. **Code Review:** Conduct code reviews before deployments to ensure mock mode is not accidentally enabled in production code.
    3. **Feature Flags:** Consider using a more robust feature flag system instead of a simple environment variable to manage mock mode and other development/debugging features. This allows for more controlled activation and deactivation.
  - Threats Mitigated:
    - Mock Mode Misuse (Low to Medium Severity): Prevents accidental or malicious use of mock mode in production, which could bypass intended functionality or security measures.
  - Impact:
    - Mock Mode Misuse: Medium reduction in risk. Ensures production environment uses real AI API calls and intended application logic.
  - Currently Implemented:
    - Partially implemented. `backend/config.py` uses `MOCK` environment variable to control mock mode.
  - Missing Implementation:
    - Explicit instructions to disable mock mode in production deployment documentation.
    - Code review process to verify mock mode is disabled in production.
    - Consideration of a more robust feature flag system.

- Mitigation Strategy: Server-Side API Key Management (instead of Client-Side)
  - Description:
    1. **Backend API Proxy:** Move API key handling entirely to the backend. The frontend should not directly handle or store API keys. Implement backend API endpoints that act as proxies to the AI APIs and ScreenshotOne API. The backend will authenticate requests and securely manage the API keys.
    2. **Frontend Authentication:** Implement a proper authentication mechanism for frontend users to access the backend API endpoints. This could be session-based authentication, JWT, or similar.
    3. **Authorization:** Implement authorization checks in the backend to ensure users only have access to the features and data they are permitted to access.
  - Threats Mitigated:
    - Rate Limiting Bypass (Client-Side Keys) (Low to Medium Severity): Prevents malicious users from easily bypassing rate limits or abusing the service by hiding API keys on the server-side.
    - API Key Exposure (High Severity): Further reduces API key exposure risk by removing client-side key handling.
  - Impact:
    - Rate Limiting Bypass (Client-Side Keys): Medium reduction in risk. Makes it significantly harder to bypass rate limits.
    - API Key Exposure: High reduction in risk. Centralizes API key management on the server, making it much more secure.
  - Currently Implemented:
    - Not implemented. `Troubleshooting.md` suggests client-side key input and storage in browser. `generate_code.py` retrieves API keys from client-side parameters.
  - Missing Implementation:
    - Backend API proxy for AI API calls and ScreenshotOne API calls.
    - Frontend authentication and backend authorization mechanisms.
    - Removal of client-side API key handling.
