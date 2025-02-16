# Attack Tree for screenshot-to-code Application

## Root Goal: Compromise screenshot-to-code application

### 1.0 Exploit API Key Exposure
- Description: Attacker gains access to OpenAI, Anthropic, or Gemini API keys, or ScreenshotOne API key used by the application. These keys could be exposed through misconfigured environment variables, insecure storage, or frontend exposure.
- Actionable Insights:
    - Ensure all API keys are stored securely and not directly in the frontend code or publicly accessible configuration files.
    - Use secure environment variable management practices.
    - Consider using a secrets management system if deploying to production.
- Likelihood: Medium
- Impact: High - Full access to the AI models and ScreenshotOne service, potentially leading to unauthorized usage, data access, financial implications (API billing), and ability to take arbitrary screenshots.
- Effort: Low - If keys are inadvertently exposed, it requires minimal effort.
- Skill Level: Low - Basic understanding of web application architecture and configuration.
- Detection Difficulty: Medium - Depends on monitoring of API key usage and configuration audits.

### 2.0 Perform Prompt Injection
- Description: Attacker crafts malicious input (screenshot or video) that, when processed by the AI model, causes unintended behavior. This could range from generating malicious code, bypassing intended functionality, or potentially gaining access to internal data or systems if the generated code is executed in a privileged context (less likely in this application).
- Actionable Insights:
    - Implement robust input validation and sanitization on the backend before sending data to AI models.
    - Monitor AI model responses for suspicious or unexpected outputs.
    - Consider sandboxing or isolating the execution environment of the generated code.
- Likelihood: Medium
- Impact: Medium - Could lead to generation of vulnerable code, unexpected application behavior, or in a worst-case scenario, limited backend compromise if the AI response is mishandled.
- Effort: Medium - Requires understanding of AI prompt engineering and the application's workflow.
- Skill Level: Medium - Requires some expertise in AI interaction and application logic.
- Detection Difficulty: Medium - Requires monitoring of AI interactions and output analysis.

### 3.0 Exploit Dependency Vulnerabilities
- Description: Attacker exploits known vulnerabilities in third-party libraries used by the backend (Poetry managed Python packages) or frontend (Yarn managed Node.js packages).
- Actionable Insights:
    - Regularly audit and update backend and frontend dependencies to their latest secure versions.
    - Use dependency scanning tools to identify and remediate known vulnerabilities.
    - Implement a Software Bill of Materials (SBOM) for better dependency management.

    #### 3.1 Backend Dependency Vulnerabilities
    - Description: Exploiting vulnerabilities in Python packages listed in `backend/pyproject.toml`.
    - Actionable Insights:
        - Regularly run `poetry update` to update dependencies.
        - Use `poetry audit` or similar tools to check for known vulnerabilities in dependencies.
    - Likelihood: Medium
    - Impact: Medium - Backend compromise, data access, service disruption depending on the vulnerability.
    - Effort: Medium - Requires identifying vulnerable dependencies and exploiting them.
    - Skill Level: Medium - Requires understanding of Python and common web application vulnerabilities.
    - Detection Difficulty: Medium - Vulnerability scanners can detect known issues, but exploit detection might be harder.

    #### 3.2 Frontend Dependency Vulnerabilities
    - Description: Exploiting vulnerabilities in Node.js packages listed in `frontend/package.json`.
    - Actionable Insights:
        - Regularly run `yarn upgrade` to update dependencies.
        - Use `yarn audit` or similar tools to check for known vulnerabilities in dependencies.
    - Likelihood: Medium
    - Impact: Medium - Frontend compromise, potentially leading to XSS or other client-side attacks.
    - Effort: Medium - Requires identifying vulnerable dependencies and exploiting them.
    - Skill Level: Medium - Requires understanding of JavaScript and common web application vulnerabilities.
    - Detection Difficulty: Medium - Vulnerability scanners can detect known issues, but exploit detection might be harder.

### 4.0 Exploit Insecure Media Processing
- Description: The application processes images using `PIL` library and videos using `moviepy` and `PIL`. Vulnerabilities in image and video processing libraries can be exploited by uploading maliciously crafted media files.
- Actionable Insights:
    - Keep `Pillow` (PIL) and `moviepy` libraries updated to the latest version to patch known vulnerabilities.
    - Implement input validation on media uploads, checking file types, sizes, and formats.
    - Consider using a sandboxed environment for media processing to limit the impact of potential exploits.
- Likelihood: Medium
- Impact: Medium - Backend compromise, potentially leading to arbitrary code execution depending on the vulnerability and exploit.
- Effort: Medium to High - Requires deep understanding of media processing vulnerabilities and libraries used.
- Skill Level: High - Requires expertise in vulnerability research and exploit development.
- Detection Difficulty: Medium - Monitoring file uploads and system behavior might help, but exploit detection can be complex.

### 5.0 Denial of Service (DoS) via Resource Exhaustion
- Description: Attacker sends a large number of requests to the backend, especially for AI code generation or evaluation endpoints, exhausting server resources or API quotas, leading to service disruption.
- Actionable Insights:
    - Implement rate limiting on API endpoints, especially code generation and evaluation endpoints.
    - Monitor server resource usage and API request patterns.
    - Implement request queuing and throttling mechanisms.
- Likelihood: Medium
- Impact: Medium - Service disruption, impacting application availability for legitimate users.
- Effort: Low - Can be achieved with readily available DoS tools or scripts.
- Skill Level: Low - Basic scripting skills and understanding of network requests.
- Detection Difficulty: Medium - Detectable through monitoring network traffic and server load, but distinguishing from legitimate heavy usage can be challenging.

### 6.0 Exposure of Debug Artifacts
- Description: Debugging features are enabled (`IS_DEBUG_ENABLED`) and debug artifacts are written to `DEBUG_DIR`. If `DEBUG_DIR` is publicly accessible or misconfigured, attackers could gain access to sensitive information logged during debugging, potentially including prompts, responses, or internal application states.
- Actionable Insights:
    - Ensure debugging features are disabled in production environments.
    - If debugging is necessary in non-production environments, restrict access to the `DEBUG_DIR` and its contents.
    - Review debug logs regularly and sanitize sensitive information before logging.
- Likelihood: Low to Medium (depending on environment configuration)
- Impact: Medium - Exposure of potentially sensitive information, aiding further attacks or revealing application internals.
- Effort: Low - If debug directory is publicly accessible, it requires minimal effort.
- Skill Level: Low - Basic understanding of web server configuration and file access.
- Detection Difficulty: Medium - Configuration audits and access control monitoring can help detect misconfigurations.

### 7.0 Path Traversal in Evaluation Endpoints
- Description: The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in `evals.py` take folder paths as input. If these paths are not properly validated and sanitized, an attacker could manipulate the folder parameter to access files and directories outside the intended evaluation directories.
- Actionable Insights:
    - Implement strict input validation and sanitization for folder paths in evaluation endpoints.
    - Use absolute paths and avoid relative path constructions when handling file system operations based on user input.
    - Consider using a whitelist approach to restrict access to specific allowed directories for evaluations.
- Likelihood: Medium
- Impact: Medium - Access to sensitive files on the server, potential data leakage or further exploitation depending on accessible files.
- Effort: Medium - Requires understanding of path traversal techniques and the application's file handling logic.
- Skill Level: Medium - Requires knowledge of web application vulnerabilities and file system operations.
- Detection Difficulty: Medium - Input validation checks and path sanitization can prevent exploitation, but detecting attempted path traversal in logs might require specific monitoring rules.

### 8.0 Server-Side Request Forgery (SSRF) via Screenshot API
- Description: The `/api/screenshot` endpoint in `screenshot.py` uses the `screenshotone.com` API to capture website screenshots based on user-provided URLs. If the application does not properly validate and sanitize the input URL, an attacker could provide a malicious URL, potentially leading to SSRF. This could allow the attacker to make requests to internal network resources or external websites, potentially bypassing firewalls or gaining access to sensitive information.
- Actionable Insights:
    - Implement strict validation and sanitization of URLs provided to the `/api/screenshot` endpoint.
    - Consider using a URL whitelist to restrict screenshot capture to only trusted domains.
    - Review the security policies and configurations of the `screenshotone.com` API to understand its security posture and potential risks.
- Likelihood: Medium
- Impact: High - Potential access to internal network resources, data leakage, or further exploitation depending on the internal network configuration and the attacker's goals.
- Effort: Medium - Requires understanding of SSRF vulnerabilities and the application's screenshot functionality.
- Skill Level: Medium - Requires knowledge of web application vulnerabilities and networking concepts.
- Detection Difficulty: Medium - Monitoring outbound requests from the backend server and analyzing URL parameters in logs can help detect SSRF attempts.
