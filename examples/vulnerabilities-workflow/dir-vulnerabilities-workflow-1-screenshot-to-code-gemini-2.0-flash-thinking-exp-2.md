- **Vulnerability Name:** Overly Permissive CORS Policy
  - **Description:**
    The backend is configured with FastAPI’s CORSMiddleware using an “allow all” policy (using `allow_origins=["*"]`, `allow_methods=["*"]`, and `allow_headers=["*"]`). An attacker can build a malicious web page that sends cross‑origin AJAX requests to all backend endpoints. In a scenario where sensitive data or functions are exposed by these endpoints, the attacker could have the victim’s browser send authenticated requests (especially given that credentials are allowed) and read the responses.
    Steps to trigger:
      1. The attacker hosts a malicious page on a domain they control.
      2. Using JavaScript, they send an AJAX request (with credentials) to one of the backend endpoints (for example, a code‐generation or screenshot endpoint).
      3. Because the server responds with permissive CORS headers, the browser makes the response available to the attacker’s script.
  - **Impact:**
    Sensitive responses may be read by an attacker’s site (if any endpoints later deal with private data or administrative actions), exposing internal state or enabling misuse of APIs.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The project does enforce CORS via FastAPI middleware—but with a wildcard setting that allows any origin.
  - **Missing Mitigations:**
    In production environments the list of allowed origins should be restricted to only those domains that need access. Additionally, tighter permissions for credentials and methods could be enforced.
  - **Preconditions:**
    The backend must be publicly accessible.
  - **Source Code Analysis:**
    In `backend/main.py` the following middleware is added:
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    This setting causes every origin to be allowed access.
  - **Security Test Case:**
    1. Create a simple HTML page on an attacker‑controlled domain that uses JavaScript (e.g., using XMLHttpRequest or fetch with credentials).
    2. Request a backend endpoint (e.g., `/api/screenshot` or `/generate-code`) from this page.
    3. Verify that the browser allows the response to be read (inspect using developer tools) even though the request is cross‑origin.
    4. Conclude that the overly permissive CORS configuration is in effect.

---

- **Vulnerability Name:** SSRF via the Screenshot Endpoint
  - **Description:**
    The `/api/screenshot` endpoint in `routes/screenshot.py` accepts a URL provided by the client without any sanitization or whitelisting. This URL is passed directly as a parameter (named `url`) to an external API (ScreenshotOne) via an HTTP GET call using httpx.
    Steps to trigger:
      1. An attacker submits a POST request with the JSON payload containing a malicious target URL (for example, an internal URL such as `http://169.254.169.254/latest/meta-data/` or a resource on the private network).
      2. The backend’s `capture_screenshot()` function uses this URL as-is when calling the screenshot API.
  - **Impact:**
    The attacker might use the backend as a proxy to scan internal resources, access sensitive internal endpoints, or otherwise abuse the screenshot API with unintended target URLs. In some scenarios this may even result in a disclosure of sensitive internal information.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    There is no input validation or URL whitelisting in the code for the `target_url` parameter.
  - **Missing Mitigations:**
    The application should validate that the URL points only to allowed (and public) domains. Implementing a whitelist of domains or a validation routine would mitigate this risk.
  - **Preconditions:**
    The screenshot endpoint is publicly accessible and accepts arbitrary URLs within its payload.
  - **Source Code Analysis:**
    In `routes/screenshot.py`:
    ```python
    class ScreenshotRequest(BaseModel):
        url: str
        apiKey: str
    ...
    async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
        params = {
            "access_key": api_key,
            "url": target_url,
            ...
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(api_base_url, params=params)
            ...
    ```
    There is no sanitization or validation of `target_url` before it is used.
  - **Security Test Case:**
    1. Use a tool (for example, curl or Postman) to POST to `/api/screenshot` with a JSON body such as:
       ```json
       {
         "url": "http://169.254.169.254/latest/meta-data/",
         "apiKey": "dummy-key"
       }
       ```
    2. Observe if the response contains data that indicates an internal resource was accessed (or if the external API error message reveals internal endpoints).
    3. If so, the SSRF risk is confirmed.

---

- **Vulnerability Name:** Insecure Handling and Transmission of API Keys in Code Generation
  - **Description:**
    The code‑generation endpoint (implemented over a WebSocket in `routes/generate_code.py`) accepts API keys such as OpenAI and Anthropic keys in the client’s payload. These keys are then used in subsequent calls to third‑party LLM endpoints. An attacker controlling the WebSocket connection or intercepting traffic (if not transported over TLS) could supply, misuse, or exfiltrate these keys.
    Steps to trigger:
      1. An attacker opens a WebSocket connection to `/generate-code` and sends a JSON payload that supplies API key values through parameters (for instance, using keys `"openAiApiKey"` or `"anthropicApiKey"`).
      2. The server uses these keys without additional protection, meaning that an attacker could provide a key they control or capture keys transmitted by a victim if the connection isn’t secured.
  - **Impact:**
    Misuse of the LLM service API keys can result in unauthorized API calls (incurring cost and potential data leakage) and may expose sensitive credentials that could be abused elsewhere.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code provides a fallback to environment‑configured keys when available. However, it still accepts API keys from client‑supplied parameters without further checks.
  - **Missing Mitigations:**
    Implement strict authentication for API key submission and ensure that keys are only accepted over a secure (TLS‑protected) channel. Ideally, API keys for third‑party services should not be user‑supplied from untrusted origins.
  - **Preconditions:**
    The WebSocket connection is established by an unauthenticated (or lightly authenticated) client, and API keys are sent in plaintext (if TLS is not enforced).
  - **Source Code Analysis:**
    In `routes/generate_code.py`, the function `extract_params()` calls:
    ```python
    openai_api_key = get_from_settings_dialog_or_env(params, "openAiApiKey", OPENAI_API_KEY)
    ```
    and similarly for Anthropic. There is no additional verification of these keys received from the client before they are used for making API calls.
  - **Security Test Case:**
    1. Establish a WebSocket connection to the backend’s `/generate-code` endpoint.
    2. Send a JSON payload that includes a deliberately invalid or attacker‑controlled API key.
    3. Monitor if the key is used in making outbound calls and if any sensitive error messages or confirmations are returned via the WebSocket.
    4. Additionally, verify (using network monitoring) that the connection data is encrypted (e.g. via TLS) so that API keys are not sent in cleartext.

---

- **Vulnerability Name:** Unsanitized HTML Output Leading to Cross‑Site Scripting (XSS)
  - **Description:**
    After receiving a response from a language model, the backend calls a helper function to extract the HTML content (using a regular expression) and then transmits this code via the WebSocket to be rendered by the client. If an attacker can manipulate the prompt (or trigger an LLM output) so that the generated HTML contains malicious JavaScript (e.g. `<script>alert('XSS')</script>`), and if the front‑end renders this HTML without further sanitization, then client‑side script execution will follow.
    Steps to trigger:
      1. An attacker submits a prompt (or intercepts and slightly modifies the conversation) so that the LLM returns HTML that includes a malicious `<script>` tag.
      2. The backend extracts the HTML and sends it to the front‑end.
      3. The front‑end injects or displays this HTML directly in the DOM, leading to execution of the malicious code.
  - **Impact:**
    Successful XSS may allow session hijacking, defacement, redirection to phishing sites, or further exploitation of the client’s browser context.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code uses a simple regex in `extract_html_content()` (in `codegen/utils.py`) to pick out the first `<html>…</html>` block. There is no output sanitization or XSS filtering applied thereafter.
  - **Missing Mitigations:**
    The system should sanitize and/or escape any potentially dangerous HTML or JavaScript in the generated output before it is rendered on the client side.
  - **Preconditions:**
    The attacker is able to influence the LLM prompt or the request parameters (contributing to the LLM’s output) and the front‑end renders the result without sanitization.
  - **Source Code Analysis:**
    In `routes/generate_code.py`:
    ```python
    completions = [extract_html_content(completion) for completion in completions]
    ...
    await send_message("setCode", updated_html, index)
    ```
    The helper `extract_html_content()` simply uses:
    ```python
    re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
    ```
    which does not alter any embedded `<script>` tags.
  - **Security Test Case:**
    1. Submit a prompt (via the code generation WebSocket API) crafted to elicit an LLM response containing malicious code (for example, include instructions such as “inject a script that calls `alert('XSS')`”).
    2. When the response is rendered on the front‑end, observe if the script executes (using a test browser or simulated client).
    3. Confirm that without output filtering, the malicious JavaScript runs in the client’s browser.

---

- **Vulnerability Name:** Prompt Injection via Unsanitized User‑Provided Inputs
  - **Description:**
    The process of assembling prompts (in `prompts/__init__.py` functions such as `assemble_prompt()` and `create_prompt()`) directly incorporates user‑supplied parameters (like image URLs and history messages) into the prompt without any sanitization. An attacker may craft history messages or other input fields that include additional instructions or control characters. This could manipulate the context given to the LLM and steer it to generate harmful or unintended output.
    Steps to trigger:
      1. An attacker submits a “history” array in the WebSocket payload containing unexpected HTML or LLM‑control text (e.g. injecting additional system instructions or malicious directives).
      2. The assembled prompt then includes these injections which may cause the LLM to leak sensitive configuration information or output harmful HTML/JS.
  - **Impact:**
    Manipulated prompt output may result in arbitrary code generation, facilitate XSS indirectly, or cause the disclosure of internal system details.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The prompt construction code does not appear to perform any sanitization or validation of the user‑supplied “history” or “image” parameters.
  - **Missing Mitigations:**
    The application must enforce strict input validation and sanitize prompt components (for example, by escaping HTML/JavaScript, enforcing length limits, and/or whitelisting allowed characters) before these values are concatenated into the prompt.
  - **Preconditions:**
    The client is permitted to send arbitrary “history” or other prompt‑related data without prior filtering and the LLM is sensitive to prompt changes.
  - **Source Code Analysis:**
    In `prompts/__init__.py`, the function `create_prompt()` directly appends messages from `params["history"]` into the prompt messages without sanitization. This makes the prompt susceptible to injection attacks.
  - **Security Test Case:**
    1. Submit a request that includes a “history” array with crafted input such as:
       ```
       "</script><script>alert('injection')</script>"
       ```
    2. Monitor the assembled prompt (or the eventual LLM output) to see if the malicious payload is present or if it alters the expected behavior.
    3. Validate that, without proper sanitization, the attacker’s payload is injected into the prompt.

---

- **Vulnerability Name:** Information Disclosure Through Detailed Error Messages on WebSocket
  - **Description:**
    In the code generation route implemented over a WebSocket (`routes/generate_code.py`), when errors occur (for example, authentication errors from OpenAI or rate–limit errors) detailed exception messages and stack traces may be printed to the console and sent back to the client. An attacker can trigger error conditions (for example, by supplying invalid API keys) and receive detailed information about internal workings, configurations, or even file paths.
    Steps to trigger:
      1. An attacker opens a WebSocket connection to `/generate-code` and supplies invalid or deliberately bad parameters.
      2. The backend encounters an exception (such as `openai.AuthenticationError` or `openai.RateLimitError`) and calls `throw_error()`, sending error details over the WebSocket.
  - **Impact:**
    Revealing stack traces and detailed internal error messages can provide attackers with valuable insight into the system’s internal structure and logic, which they could leverage in further attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code does catch some exceptions and calls `throw_error()`; however, the error messages (including exception messages) are relayed directly to the client.
  - **Missing Mitigations:**
    The error responses should be sanitized to remove any technical details (or use generic error messages) rather than sending detailed exception information back to the client.
  - **Preconditions:**
    The attacker can force error paths (for example, via invalid keys or malformed payloads) and the WebSocket connection is not authenticated or encrypted.
  - **Source Code Analysis:**
    In `routes/generate_code.py`, when exceptions such as `openai.AuthenticationError` or `openai.RateLimitError` occur, the code uses:
    ```python
    await throw_error(error_message)
    ```
    where `error_message` is constructed directly from exception messages (and sometimes includes technical details).
  - **Security Test Case:**
    1. Open a WebSocket connection to the `/generate-code` endpoint using a test client.
    2. Supply purposely invalid API key parameters so that an authentication error is triggered.
    3. Capture the error message sent back over the WebSocket and inspect it for internal details (such as specific exception types or stack information).
    4. Verify that error messages do not provide more information than a user‑friendly “Something went wrong” message.
