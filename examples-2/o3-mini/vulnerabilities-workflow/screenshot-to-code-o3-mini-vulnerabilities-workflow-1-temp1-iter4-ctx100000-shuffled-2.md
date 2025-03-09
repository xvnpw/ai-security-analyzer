# List of High-Severity Vulnerabilities in "screenshot-to-code"

Below are the vulnerabilities that meet the criteria:
- They are all high severity.
- They are valid, not already mitigated, and can be triggered by an external attacker with network access to the public instance.
- They are not caused by insecure coding patterns in project files, are not only missing documentation to mitigate, and are not purely denial-of-service vulnerabilities.

---

## Vulnerability Name: Arbitrary File Read via Eval Endpoints
- **Description:**
  The endpoints for evaluations (including `/evals`, `/pairwise-evals`, and `/best-of-n-evals`) directly use user‑supplied folder path parameters to list files on disk. An attacker may submit a path (for example, using path traversal sequences such as “../”) so that the backend lists and returns the contents of arbitrary directories containing HTML files.
  - **Step-by-step trigger:**
    1. The attacker crafts a GET request to the endpoint (e.g. `/evals?folder=../some_sensitive_dir`) where the folder parameter is not sanitized.
    2. The server checks if the path exists (using `Path(folder).exists()`) and then performs an `os.listdir(folder)` without restrictions.
    3. If any files ending with “.html” exist in that folder, their contents are sent back in the response.
- **Impact:**
  Disclosure of confidential internal files such as configuration pages, internal documentation, or even source code that could be used to launch additional attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  None—there is no input validation or path restriction on the folder parameter.
- **Missing Mitigations:**
  • Validate and strictly sanitize any filesystem path inputs, ideally by whitelisting allowed directory trees.
  • Reject path traversal attempts or absolute paths that fall outside a designated safe directory.
- **Preconditions:**
  The attacker must have network access to the public eval endpoints and possess knowledge (or be able to guess) sensitive file locations.
- **Source Code Analysis:**
  In `backend/routes/evals.py` the function `get_evals(folder: str)` directly calls `Path(folder)` and uses `os.listdir(folder)` without any sanitization.
- **Security Test Case:**
  • Use an HTTP client (e.g. curl or Postman) to send a request such as:
    `GET /evals?folder=../`
  • Examine the response for any unexpected HTML content that may reveal sensitive files.

---

## Vulnerability Name: Unauthenticated and Unrestricted Code Generation via WebSocket
- **Description:**
  The `/generate-code` endpoint (implemented as a WebSocket in `backend/routes/generate_code.py`) does not enforce any authentication or rate limiting. Any external client can open a WebSocket connection and submit valid parameters to trigger AI‑powered code generation.
  - **Step-by-step trigger:**
    1. An attacker uses a WebSocket client (or tool such as wscat) to connect to the public endpoint (e.g. `ws://example.com/generate-code`).
    2. The attacker sends a well‑formed JSON payload that includes required parameters (such as image URL, stack, and others).
    3. The backend then calls expensive external APIs (e.g. OpenAI or Anthropic) to generate code and streams the response back.
- **Impact:**
  Unauthorized use of the code generation service may result in excessive API calls—leading to financial costs and resource exhaustion. Attackers might also use the functionality to generate undesired or malicious content.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  There is no authentication or rate limiting in the WebSocket endpoint.
- **Missing Mitigations:**
  • Implement proper authentication (API keys, tokens, or session‑based authentication) for clients connecting to the endpoint.
  • Introduce rate limits to restrict the number of requests per IP/session.
- **Preconditions:**
  The attacker must have access to the public network and be able to open a WebSocket connection.
- **Source Code Analysis:**
  In `backend/routes/generate_code.py` the decorator `@router.websocket("/generate-code")` does not perform any authentication; it simply accepts JSON data from the client and processes it.
- **Security Test Case:**
  • Connect to the WebSocket endpoint using a WebSocket client.
  • Send a valid code-generation JSON payload without any authentication information.
  • Confirm that the server processes the request and returns AI‑generated code.
  • Optionally, send multiple requests in rapid succession to demonstrate the absence of rate limiting.

---

## Vulnerability Name: Potential SSRF via Screenshot Endpoint
- **Description:**
  The `/api/screenshot` endpoint accepts a JSON payload in which the user supplies a URL. This URL is then forwarded as a parameter to an external screenshot service (via the `capture_screenshot` function).
  - **Step-by-step trigger:**
    1. The attacker submits a POST request to `/api/screenshot` with a body such as:
       ```json
       { "url": "http://127.0.0.1/admin", "apiKey": "sk-dummy" }
       ```
    2. The backend passes this unsanitized URL to the external API call (`httpx.get` call to `https://api.screenshotone.com/take`) without additional validation.
    3. If the external service does not validate the URL adequately, it may fetch internal resources.
- **Impact:**
  This could lead to server‑side request forgery (SSRF), allowing the attacker to probe internal network resources and potentially expose sensitive internal information.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  No validation or sanitization of the `url` parameter is implemented.
- **Missing Mitigations:**
  • Implement input validation to ensure that the URL is well‑formed and belongs to an allowed (external) domain.
  • Consider whitelisting acceptable URL schemes and hostnames to prevent internal targeting.
- **Preconditions:**
  The attacker must be able to send arbitrary URLs in the request payload and the external screenshot service must not enforce strict URL validation.
- **Source Code Analysis:**
  In `backend/routes/screenshot.py`, the function `capture_screenshot` directly assigns the user‑controlled “url” field from the request into the parameters for the GET request to `"https://api.screenshotone.com/take"`.
- **Security Test Case:**
  • Use an HTTP client to send a POST request to `/api/screenshot` with a JSON body containing a URL that points to an internal address (e.g., `"http://127.0.0.1/admin"`).
  • Analyze the output for signs that internal resources are being captured or that unexpected behavior occurs.

---

## Vulnerability Name: OpenAI Base URL Injection Vulnerability
- **Description:**
  For non‑production setups (when the `IS_PROD` flag is false), the code generation endpoint allows the client to pass an `openAiBaseURL` parameter. This parameter is then used directly when constructing the OpenAI client.
  - **Step-by-step trigger:**
    1. An attacker connects to the `/generate-code` WebSocket endpoint and sends a payload containing:
       ```json
       { "openAiBaseURL": "http://malicious.example.com/v1", ... }
       ```
    2. The helper function `get_from_settings_dialog_or_env` in `backend/routes/generate_code.py` uses the provided value (since `IS_PROD` is false) and passes it to the OpenAI client constructor.
    3. Subsequent requests to the OpenAI API are then routed to the attacker‑controlled URL.
- **Impact:**
  This vulnerability enables the attacker to intercept, modify, or eavesdrop on sensitive API calls—including prompts and responses—thus compromising confidentiality and integrity.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  In production environments the user‑supplied base URL is ignored, but in non‑production it is accepted without restriction.
- **Missing Mitigations:**
  • Validate the supplied `openAiBaseURL` against a whitelist of allowed endpoints.
  • Alternatively, disallow user‑supplied OpenAI base URLs entirely or restrict this functionality to trusted management interfaces.
- **Preconditions:**
  The attacker must be able to control the WebSocket payload while the backend is running in a non‑production mode.
- **Source Code Analysis:**
  In `backend/routes/generate_code.py`, the function `get_from_settings_dialog_or_env` retrieves the `"openAiBaseURL"` parameter from the client payload and uses it if present (when not in production).
- **Security Test Case:**
  • In a controlled non‑production environment, connect to the WebSocket endpoint and include an `"openAiBaseURL"` value set to a test server under the attacker’s control.
  • Verify (for example, by monitoring outgoing HTTP requests) that the OpenAI client uses the provided URL.
  • Confirm that altering this parameter changes the target destination of the API calls.
