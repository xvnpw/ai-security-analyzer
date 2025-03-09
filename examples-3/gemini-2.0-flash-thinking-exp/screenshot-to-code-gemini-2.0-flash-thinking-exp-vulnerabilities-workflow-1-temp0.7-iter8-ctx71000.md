## Vulnerability List

- Vulnerability Name: **Media Processing Vulnerability via Malicious File Upload (Image & Video)**

- Description:
    1. An attacker uploads a crafted media file (image or video) to the application through the upload functionality.
    2. For images, the backend `process_image` function in `backend/image_processing/utils.py` receives the image data URL, decodes it from base64, and opens the image using the PIL (Pillow) library.
    3. For videos, the backend `split_video_into_screenshots` function in `backend/video/utils.py` receives the video data URL, decodes it from base64, saves it to a temporary file, and processes it using `moviepy` to extract frames as PIL images.
    4. If the uploaded media file is maliciously crafted to exploit a vulnerability in PIL (during image opening or array-to-image conversion) or `moviepy` (during video processing), it could trigger the vulnerability.
    5. Exploiting these libraries' vulnerabilities can lead to denial of service (application crash), information disclosure (e.g., server file paths in error logs), or potentially remote code execution on the server, depending on the specific vulnerability.

- Impact: Depending on the exploited vulnerability, the impact ranges from high to critical:
    - High: Local denial of service (application crashes) or information disclosure (e.g., server file paths in error messages).
    - Critical: Remote code execution on the server, allowing the attacker to gain complete control.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: No explicit input validation or sanitization of media data URLs is implemented before processing with PIL or moviepy. The current processing focuses on functionality (resizing, re-encoding, frame extraction) rather than security validation.

- Missing Mitigations:
    - Input Validation: Implement robust validation of uploaded media files before processing. This should include:
        - File header checks to verify file type and format.
        - Image/video metadata validation to detect anomalies.
        - Potentially using safer image/video processing techniques or libraries where possible.
    - Dependency Scanning: Regularly scan project dependencies (PIL, moviepy) for known vulnerabilities and update to patched versions promptly.
    - Error Handling: Enhance error handling in `process_image` and `split_video_into_screenshots` to gracefully manage malicious or malformed files, preventing crashes and information leaks in error messages.
    - Sandboxing: Consider sandboxing media processing operations to limit the impact of exploits. Run processing in isolated processes with restricted permissions.

- Preconditions:
    - The application must have image and/or video upload features.
    - Uploaded media files must be processed by `process_image` or `split_video_into_screenshots` functions.
    - A exploitable vulnerability must exist in the used versions of PIL or moviepy that can be triggered by crafted media files.

- Source Code Analysis:
    1. **File:** `backend/image_processing/utils.py`
        - **Function:** `process_image(image_data_url: str)`
        - **Vulnerable Line:** `img = Image.open(io.BytesIO(image_bytes))`
        ```python
        # backend/image_processing/utils.py
        def process_image(image_data_url: str) -> tuple[str, str]:
            # ...
            image_bytes = base64.b64decode(base64_data) # Decoding base64 from data URL
            img = Image.open(io.BytesIO(image_bytes)) # Potential vulnerability point: PIL opens image
            # ... image processing logic ...
            return ("image/jpeg", base64.b64encode(output.getvalue()).decode("utf-8"))
        ```
    2. **File:** `backend/video/utils.py`
        - **Function:** `split_video_into_screenshots(video_data_url: str)`
        - **Vulnerable Lines:** `clip = VideoFileClip(temp_video_file.name)` and `frame_image = Image.fromarray(frame)`
        ```python
        # backend/video/utils.py
        def split_video_into_screenshots(video_data_url: str) -> list[Image.Image]:
            # ...
            video_bytes = base64.b64decode(video_encoded_data)
            # ...
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:
                temp_video_file.write(video_bytes)
                temp_video_file.flush()
                clip = VideoFileClip(temp_video_file.name) # Potential vulnerability point: moviepy opens video file
                # ... frame extraction ...
                    frame_image = Image.fromarray(frame) # Potential vulnerability point: PIL converts array to image
                    images.append(frame_image)
            # ...
            return images
        ```
    - Both code snippets show direct use of PIL and moviepy to process user-provided media data without prior security checks, creating potential vulnerability points.

- Security Test Case:
    1. Preparation: Identify known vulnerabilities in PIL or moviepy triggered by crafted media files. Obtain or create a crafted image/video exploiting such a vulnerability. Use vulnerable versions of libraries for testing if possible.
    2. Setup: Deploy a test instance of the application in a controlled environment.
    3. Attack:
        - Access the application UI.
        - Locate image/video upload feature.
        - Prepare a request to upload the crafted malicious media file as a data URL.
        - Send the request to the backend endpoint (e.g., `/generate_code` for images, `/generate-code` with `inputMode=video` for videos via websocket).
    4. Observation and Verification:
        - Monitor server for crashes, errors in logs, resource spikes, or information disclosure in logs/responses.
        - If targeting RCE, attempt to verify code execution (e.g., command execution) in a safe, isolated environment.

---

- Vulnerability Name: **Information Disclosure via Accessible Debug Logs**

- Description:
    1. The application uses debug logging controlled by the `IS_DEBUG_ENABLED` environment variable in `backend/config.py`.
    2. When enabled, debug logs are written to files in the directory specified by `DEBUG_DIR` using `DebugFileWriter.py`.
    3. Functions like `pprint_prompt` in `utils.py` (used in `llm.py`) may log sensitive information, such as prompts sent to LLMs.
    4. If `DEBUG_DIR` is publicly accessible due to misconfiguration (e.g., within web server root) or insecure permissions, an attacker can retrieve these log files.
    5. Exposed logs may contain sensitive information, including:
        - Prompts sent to LLMs, potentially revealing UI screenshots, business logic, or sensitive user data.
        - Parts of generated code, which may expose application logic.

- Impact:
    - High: An attacker could gain access to sensitive information from debug logs, potentially including business logic, UI screenshots, or sensitive user data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Debug logging is controlled by `IS_DEBUG_ENABLED` environment variable, intended to be disabled in production.
    - `DEBUG_DIR` environment variable allows configuring the log directory.

- Missing Mitigations:
    - Secure Default Configuration: Ensure `IS_DEBUG_ENABLED` defaults to `False` and is strongly recommended to remain disabled in production.
    - Access Control for Debug Logs: Implement strict access controls to `DEBUG_DIR` to prevent unauthorized access, even if debug logging is accidentally enabled. Ensure web server configuration prevents direct public access.
    - Sensitive Data Scrubbing: Implement measures to scrub or redact sensitive information from debug logs before writing.
    - Security Review of Logging: Conduct a security review of all logging practices to prevent inadvertent logging of sensitive data.

- Preconditions:
    - `IS_DEBUG_ENABLED` is set to `True` in a publicly accessible instance.
    - `DEBUG_DIR` is accessible to external attackers due to web server misconfiguration or insecure file system permissions.

- Source Code Analysis:
    1. **`backend/config.py`**: Defines `IS_DEBUG_ENABLED` and `DEBUG_DIR` from environment variables.
    2. **`backend/debug/DebugFileWriter.py`**: Writes debug logs to files under `DEBUG_DIR` only when `IS_DEBUG_ENABLED` is true.
    3. **`backend/llm.py`**: Calls `pprint_prompt` within `stream_claude_response_native`, potentially logging sensitive prompt data.
    4. **`backend/utils.py`**: `pprint_prompt` function serializes and prints prompt messages, which can be captured in logs.
    ```python
    # backend/config.py
    IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
    DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
    ```
    ```python
    # backend/debug/DebugFileWriter.py
    from config import DEBUG_DIR, IS_DEBUG_ENABLED
    # ...
    class DebugFileWriter:
        def __init__(self):
            if not IS_DEBUG_ENABLED:
                return
        # ...
    ```
    ```python
    # backend/llm.py
    from utils import pprint_prompt
    async def stream_claude_response_native(...):
        # ...
        pprint_prompt(messages_to_send)
        # ...
    ```
    ```python
    # backend/utils.py
    import json
    def pprint_prompt(prompt_messages: List[ChatCompletionMessageParam]):
        print(json.dumps(truncate_data_strings(prompt_messages), indent=4))
    ```

- Security Test Case:
    1. Deploy application in test environment.
    2. Set `IS_DEBUG_ENABLED=true` and configure `DEBUG_DIR` to a publicly accessible web server directory.
    3. Send a code generation request.
    4. Access `DEBUG_DIR` via web browser.
    5. Open and examine log files for sensitive prompt data, confirming information disclosure.

---

- Vulnerability Name: **Path Traversal in Evaluation Endpoints**

- Description:
    1. The application's `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in `backend/routes/evals.py` retrieve evaluation files based on user-provided folder paths via query parameters (`folder`, `folder1`, `folder2`, etc.).
    2. These endpoints use `os.listdir` and `os.path.join` with the provided folder paths to access files, checking folder existence with `os.path.exists()`.
    3. However, the application lacks proper input validation and sanitization for these folder paths to prevent path traversal attacks.
    4. An attacker can craft malicious URLs with path traversal sequences (e.g., `../../../`) in the folder parameters.
    5. The backend, using unsanitized paths, may resolve to locations outside the intended evaluation directories, allowing access to arbitrary files and directories on the server.
    6. Exploiting this, an attacker can read sensitive files, such as configuration files or application source code, that the server user running the application has access to.

- Impact:
    - High: An attacker can read arbitrary files on the server, potentially including sensitive configuration files, source code, or data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The code checks if the provided folder exists using `os.path.exists()`, which is insufficient to prevent path traversal.

- Missing Mitigations:
    - Input Validation and Sanitization: Implement robust validation for `folder`, `folder1`, `folder2`, etc., parameters:
        - Path Canonicalization: Convert to canonical paths and validate they are within intended base directories.
        - Path Traversal Sequence Removal: Reject requests with `../` or `./` sequences.
        - Safe Path Joining: Use secure path joining functions to prevent traversal outside base directories.
        - Whitelist Approach: Accept only predefined, validated folder names/paths.
    - Restrict File System Permissions: Configure permissions so the application user has minimal necessary access, ideally read-only access to evaluation directories.

- Preconditions:
    - Application is deployed and accessible.
    - Attacker discovers/infers `/evals`, `/pairwise-evals`, `/best-of-n-evals` endpoints and folder path parameters.

- Source Code Analysis:
    1. **`backend/routes/evals.py`**:  `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals` functions directly use `folder`, `folder1`, `folder2` parameters in `os.listdir` and `os.path.join` without sanitization.
    ```python
    # backend/routes/evals.py
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        # ...
        folder_path = Path(folder)
        if not folder_path.exists():
            raise HTTPException(...)
        files = {
            f: os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.endswith(".html")
        }
        # ...
    ```
    - The `os.path.exists()` check is insufficient as it only verifies the final traversed path's existence, not path safety.

- Security Test Case:
    1. Deploy application in test environment.
    2. Identify `/evals`, `/pairwise-evals`, `/best-of-n-evals` endpoints.
    3. Craft request to `/evals?folder=../../../etc/passwd`.
    4. Send request and examine response.
    5. If successful, response will contain `/etc/passwd` content or indicate access attempt, confirming path traversal. Test also with `/pairwise-evals` and `/best-of-n-evals`.

---

- Vulnerability Name: **API Key Exposure via Insecure Configuration**

- Description:
    1. The application stores sensitive API keys (OpenAI, Anthropic, Gemini) in environment variables.
    2. If deployed without secure environment variable configuration, the `.env` file (intended for development) might be exposed or environment variables logged insecurely.
    3. An attacker gaining access to the `.env` file or logs could retrieve these API keys.
    4. Compromised API keys allow unauthorized access to paid AI services, incurring costs and potentially accessing sensitive data within AI service platforms.

- Impact:
    - Unauthorized access to AI services.
    - Financial cost due to unauthorized AI service usage.
    - Potential data leakage within AI service platforms depending on API key permissions.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - API keys are loaded from environment variables, a standard practice.
    - README.md instructs on setting up API keys using `.env` for local development.

- Missing Mitigations:
    - Secure Deployment Documentation: Lack of explicit documentation on secure production deployment and environment variable handling (secrets management, not including `.env` in Docker images, secure logging).
    - Secret Scanning: No automated secret scanning to prevent accidental commits of API keys.
    - Logging Security: No explicit mention of secure logging to avoid logging API keys.

- Preconditions:
    - Application is deployed publicly.
    - Environment variables are insecurely configured, e.g., `.env` file exposed or environment variables logged insecurely.

- Source Code Analysis:
    1. **`backend/config.py`**: API keys are loaded from environment variables using `os.environ.get()`.
    ```python
    # backend/config.py
    import os

    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", None)
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", None)
    ```
    2. **`README.md`**: Instructions encourage `.env` usage for development, which can be insecure in production.
    3. **`docker-compose.yml`**: Uses `.env` file, potentially leading to inclusion in Docker image if not handled carefully.

- Security Test Case:
    1. Simulate insecure deployment: `.env` accessible via web or logs are public.
    2. Access `.env` file or logs via web browser.
    3. Extract API keys.
    4. (Optional) Verify API key validity by making a test API call to OpenAI/Anthropic/Gemini.

---

- Vulnerability Name: **Server-Side Request Forgery (SSRF) in Screenshot Endpoint**

- Description:
    1. The `/api/screenshot` endpoint in `screenshot.py` allows users to provide a URL to capture a screenshot using `screenshotone.com`.
    2. The application directly uses the user-provided URL in a server-side request to `api.screenshotone.com/take` without proper validation.
    3. An attacker can provide malicious URLs, potentially making the server:
        - Access internal network resources.
        - Access localhost resources.
        - Probe internal network ports.
        - Potentially read local files or cloud metadata services.

- Impact:
    - Information Disclosure: Access to internal resources, configuration files, service metadata.
    - Internal Network Scanning: Ability to probe internal network infrastructure.
    - Potential for further exploitation.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None

- Missing Mitigations:
    - URL Validation and Sanitization: Implement strict validation of input URL, allowing only safe protocols and whitelisted domains.
    - Prevent Access to Internal Networks: Configure firewalls to prevent access to internal network ranges.
    - Disable/Restrict URL Schemes: Limit allowed schemes to `http` and `https`, denying others like `file://`, `gopher://`, `ftp://`.

- Preconditions:
    - Application is deployed and publicly accessible.
    - Attacker can access `/api/screenshot` endpoint.

- Source Code Analysis:
    1. **`backend/routes/screenshot.py`**: `capture_screenshot` uses user-controlled `target_url` to make a request to `screenshotone.com`.
    ```python
    # backend/routes/screenshot.py
    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"
        params = {
            "access_key": api_key,
            "url": target_url, # User-controlled URL is used here
            # ...
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(api_base_url, params=params) # HTTP request with user-controlled URL
            # ...
    ```

- Security Test Case:
    1. Identify `/api/screenshot` endpoint.
    2. Craft SSRF payload: `http://127.0.0.1`.
    3. Send POST request to `/api/screenshot` with malicious URL and API key.
    4. Analyze response and side effects for signs of SSRF.

---

- Vulnerability Name: **Accidental Mock AI Response in Production**

- Description:
    1. The application has a mock AI response mode, enabled by the `MOCK` environment variable.
    2. If `MOCK` is set to `true`, the application uses static responses from `mock_llm.py` instead of real AI models.
    3. An attacker manipulating environment variables could enable mock mode in production.
    4. This leads to the application behaving incorrectly in production, bypassing security checks or logic dependent on real AI responses.

- Impact:
    - High: Application malfunction, potential security bypasses, data integrity issues, and exposure of non-production behavior.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Mock mode controlled by `MOCK` environment variable, standard practice.
    - `config.py` correctly reads and converts `MOCK` to boolean `SHOULD_MOCK_AI_RESPONSE`.

- Missing Mitigations:
    - Explicitly Prevent Mock Mode in Production: Mechanism to disable mock mode in production regardless of environment variables.
    - Monitoring and Alerting: Log and monitor mock mode status, especially in production, and trigger alerts if unexpectedly enabled.

- Preconditions:
    - Application deployed where environment variables can be manipulated.
    - Backend uses `SHOULD_MOCK_AI_RESPONSE` flag.
    - Attacker can set/change `MOCK` environment variable.

- Source Code Analysis:
    1. **`backend/config.py`**: `SHOULD_MOCK_AI_RESPONSE` controlled by `MOCK` env var.
    ```python
    # backend/config.py
    SHOULD_MOCK_AI_RESPONSE = bool(os.environ.get("MOCK", False))
    ```
    2. **`backend/mock_llm.py`**: Contains mock LLM responses.
    3. **`backend/llm.py`**: Contains real LLM interaction functions (bypassed in mock mode).

- Security Test Case:
    1. Deploy application in test environment.
    2. Baseline test: Mock mode disabled, check real LLM response.
    3. Enable mock mode: Set `MOCK=true` env var, redeploy.
    4. Test with mock mode enabled: Check for consistent mock responses, confirming bypass.

---

- Vulnerability Name: **Permissive Cross-Origin Resource Sharing (CORS) Policy**

- Description:
    1. The backend application has a permissive CORS policy (`allow_origins=["*"]`) in `backend/main.py`.
    2. This allows cross-origin requests from any domain.
    3. An attacker can host a malicious website on any domain and make requests to the backend API.
    4. The browser will allow these cross-origin requests due to the permissive CORS policy.
    5. This can bypass client-side origin checks and potentially lead to unauthorized actions or data manipulation if backend security is insufficient.

- Impact:
    - High: Permissive CORS weakens security, potentially leading to data breaches or unauthorized actions if backend API security relies on origin or is insufficient.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: Explicitly set `allow_origins=["*"]`.
    ```python
    # backend/main.py
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```

- Missing Mitigations:
    - Restrict `allow_origins`: Set to specific trusted origins (frontend domain(s)).
    - Implement Robust Backend Authentication and Authorization: Backend API should not solely rely on CORS and must have its own authentication and authorization mechanisms.

- Preconditions:
    - Backend application is publicly accessible.
    - Backend API relies on origin-based security assumptions or lacks backend authentication.

- Source Code Analysis:
    1. **`backend/main.py`**: `CORSMiddleware` with `allow_origins=["*"]` allows all origins.

- Security Test Case:
    1. Deploy application backend publicly.
    2. Create malicious HTML file on different domain (`attacker.com`) with JavaScript to make API request to backend.
    3. Open malicious HTML in browser and observe successful API request and response, confirming bypassed CORS.

---

No vulnerabilities found
```
No vulnerabilities found.
