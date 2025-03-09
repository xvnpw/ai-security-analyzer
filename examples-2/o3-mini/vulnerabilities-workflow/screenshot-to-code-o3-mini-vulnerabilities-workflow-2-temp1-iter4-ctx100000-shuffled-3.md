- **Vulnerability Name:** Prompt Injection Leading to Code Injection and XSS
  **Description:**
  An attacker who controls one or more of the input parameters used for code generation (for example, the “history” field or other values injected into the prompt) can include malicious payloads. These inputs are appended directly into the prompt (via functions such as `create_prompt` and `assemble_prompt` in the `prompts/__init__.py` file) without any sanitization. When the LLM generates code based on these prompts, the attacker’s payload can cause the generated HTML to include malicious JavaScript (or other harmful code). When such code is later rendered in a user’s browser, it may execute the injected scripts.
  **Impact:**
  - Generated code may contain injected scripts that execute in the victim’s browser.
  - This can lead to cross-site scripting (XSS) attacks, session hijacking, credential theft, or other browser-side compromises.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - There is no explicit input validation or sanitization in the functions that assemble the prompt (e.g. in `create_prompt` and `assemble_prompt`).
  **Missing Mitigations:**
  - Sanitization/escaping of all user-supplied input (especially the “history” and other prompt parameters) before assembling the LLM prompt.
  - Validation or whitelisting to ensure only expected values (or safe characters) are allowed.
  - Output encoding on any generated HTML before it is rendered in browsers.
  **Preconditions:**
  - The attacker must have access to the web interface or API (for example, via the settings dialog or code generation endpoint) in which they can control input values.
  **Source Code Analysis:**
  - In `prompts/__init__.py`, the `create_prompt` function loops over `params["history"]` and directly appends each piece to the prompt without any sanitization:
    ```python
    for index, text in enumerate(params["history"][1:]):
        if index % 2 == 0:
            message = { "role": "user", "content": text }
        else:
            message = { "role": "assistant", "content": text }
        prompt_messages.append(message)
    ```
    This means that any malicious HTML/JavaScript injected by the attacker becomes part of the context passed to the LLM.
  **Security Test Case:**
  1. Using the front‐end or the WebSocket API that triggers code generation, supply a crafted “history” parameter value containing a payload such as:
     ```
     <script>alert('XSS');</script>
     ```
  2. Initiate a code generation request.
  3. Capture the generated output by monitoring the “setCode” messages sent over the WebSocket connection.
  4. Inspect the output HTML to check whether it now includes the injected `<script>` tag.
  5. Load the generated HTML in a test browser and determine whether the JavaScript executes (for example, by observing the alert).
  6. Document the steps and evidence (e.g. screenshots of the alert) to confirm the vulnerability.

- **Vulnerability Name:** SSRF via Unvalidated URL Parameter in Screenshot API
  **Description:**
  The `/api/screenshot` endpoint accepts a JSON body with a “url” field. This URL is passed without any validation to the function `capture_screenshot` (located in `backend/routes/screenshot.py`) that invokes an external screenshot service API. An attacker can submit a URL that points to internal network resources (for example, `http://localhost/admin` or an internal IP address). Because nothing prevents an attacker from supplying arbitrary URLs, the backend will forward the request—leading to a Server‐Side Request Forgery (SSRF).
  **Impact:**
  - The backend might be induced to perform network requests to internal services that are not otherwise externally accessible.
  - This can lead to information disclosure, network reconnaissance, or even access to privileged services residing on the internal network.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - There is no sanitization or filtering of the “url” parameter in the `ScreenshotRequest` model or in the `capture_screenshot` function.
  **Missing Mitigations:**
  - Input validation that restricts the “url” parameter to a whitelist of safe domains or that rejects URLs pointing to internal IP ranges.
  - Additional network-level controls (such as restricting outbound requests) or safe URL parsing routines.
  **Preconditions:**
  - The attacker must be able to craft POST requests to the `/api/screenshot` endpoint using an arbitrary “url” parameter.
  - The screenshot API (https://api.screenshotone.com/take) is reachable from the backend.
  **Source Code Analysis:**
  - In `backend/routes/screenshot.py`, the function `capture_screenshot` constructs a set of request parameters directly from the user-supplied URL:
    ```python
    params = {
        "access_key": api_key,
        "url": target_url,
        "full_page": "true",
        ...
    }
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
    ```
    The lack of any checks means that an attacker can substitute an internal resource URL.
  **Security Test Case:**
  1. Send a POST request to the `/api/screenshot` endpoint with the following JSON payload:
     ```json
     {
       "url": "http://127.0.0.1:80/admin",
       "apiKey": "valid_api_key"
     }
     ```
  2. Observe (using network logs or monitoring the behavior of internal endpoints) whether the backend calls the provided URL.
  3. Verify if the response contains data that should be confidential.
  4. Document the request and the backend’s behavior to demonstrate that the SSRF is successful.
