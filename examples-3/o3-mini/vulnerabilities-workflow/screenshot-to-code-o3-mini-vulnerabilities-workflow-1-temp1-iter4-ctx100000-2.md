# Vulnerabilities List

Below is the list of high‑severity vulnerabilities discovered in the project. Each vulnerability describes how an external attacker can abuse publicly available endpoints to trigger unintended behavior and cause financial/exfiltration risks.

---

## 1. Unauthorized Access to AI Code Generation WebSocket Endpoint

**Description:**
The `/generate-code` WebSocket endpoint does not require any authentication or authorization. An attacker can connect to this endpoint using any WebSocket client and supply valid looking JSON parameters to trigger expensive AI model calls (using OpenAI, Anthropic, or Gemini models). Because no user verification or rate limiting is in place, an attacker may initiate repeated code generation tasks without restriction.

**Impact:**
- Financial loss due to high-cost model invocations (e.g. GPT-4, Claude, etc.)
- Potential exhaustion of API quotas and resources, leading to service disruption for legitimate users

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The WebSocket is configured with open CORS (allowing all origins), which is appropriate for public-facing APIs in some cases.
- No authentication is enforced, and the endpoint simply accepts incoming connections.

**Missing Mitigations:**
- An authentication layer (for example, API tokens or session-based authentication) on the WebSocket endpoint
- Rate-limiting and abuse detection to limit the number and frequency of code generation requests
- Authorization checks that restrict access to trusted or paying users only

**Preconditions:**
- The application is deployed in a public environment where the `/generate-code` endpoint is reachable.
- An attacker must know or discover the WebSocket endpoint URL.

**Source Code Analysis:**
1. In `backend/routes/generate_code.py`, the endpoint accepts the connection immediately via `await websocket.accept()` without performing any authentication.
2. The parameters taken from the WebSocket message (such as `generatedCodeConfig`, `inputMode`, etc.) are used directly to assemble the prompt and trigger backend calls to expensive AI models.
3. There is no check, token, or session verification before the code generation process starts.

**Security Test Case:**
1. Use a WebSocket client (for example, using a tool like “wscat” or a simple custom script) to connect to `ws://<server-address>/generate-code`.
2. Send a valid JSON request containing all required parameters (e.g., a valid `generatedCodeConfig`, `inputMode`, and other required fields).
3. Verify that the server begins streaming code generation “chunk” messages without any authentication challenge.
4. Automate sending multiple requests to confirm that an attacker could repeatedly trigger high‑cost model calls.

---

## 2. Arbitrary File Read in Evaluation Endpoints

**Description:**
Several endpoints used for evaluation—such as `/evals`, `/pairwise-evals`, and `/best-of-n-evals`—take a folder path as a query parameter with no proper sanitization or access controls. The code then uses this folder parameter to list and read HTML files from disk. An attacker may supply an arbitrary folder path (absolute or relative) to retrieve files from sensitive areas of the server filesystem.

**Impact:**
- Sensitive internal HTML files, configuration details, or proprietary source code may be disclosed.
- Data leakage could be exploited to map the server’s internal file structure or facilitate further attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- A basic existence check is performed (using `Path(folder).exists()`), and only files ending with “.html” are considered.

**Missing Mitigations:**
- Proper sanitization and validation of the `folder` parameter to restrict file access only to intended directories (for example, by using a whitelist or canonicalizing path inputs).
- Access control checks that prevent arbitrary folder paths from being read by unauthenticated users.

**Preconditions:**
- The evaluation endpoints are publicly accessible.
- The attacker can supply a folder path (via query parameters) knowing or guessing internal directory names.

**Source Code Analysis:**
1. In `backend/routes/evals.py`, the function `get_evals` directly creates a `Path` from the `folder` query parameter and then uses `os.listdir(folder)` to enumerate files.
2. Similar unsanitized folder inputs are used in the `/pairwise-evals` and `/best-of-n-evals` routes, leaving the application open to directory traversal attacks.

**Security Test Case:**
1. Send a GET request to the `/evals` endpoint with a crafted folder parameter (for example, `?folder=/etc` or any other sensitive directory known to contain “.html” files).
2. Observe if the response returns HTML file contents from an unexpected or restricted folder.
3. Verify that sensitive data (or unintended files) can be obtained through this endpoint.

---

## 3. Server-Side Request Forgery (SSRF) in Screenshot API Endpoint

**Description:**
The `/api/screenshot` endpoint accepts a JSON payload including a `url` parameter and an API key. The backend function `capture_screenshot` passes the user‑supplied URL directly as a parameter to the external screenshot service API (`https://api.screenshotone.com/take`) without any validation. An attacker may supply a URL that points to internal network resources or services not intended to be publicly accessible.

**Impact:**
- The internal network (or private IP ranges) might be scanned or accessed if the external API or the HTTP client does not block requests to internal addresses.
- Sensitive administrative pages or internal services could be captured by an attacker via screenshots.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The design delegates screenshot taking to the external service (screenshotone.com), which may have its own controls.
- No immediate sanitization is performed, and the request is simply forwarded.

**Missing Mitigations:**
- Input validation/sanitization to ensure that the `url` parameter only contains allowed external URLs.
- Implementation of an allowlist or checks that block private IP addresses (e.g., 127.0.0.1, 10.0.0.0/8, 192.168.0.0/16).
- Additional network-level filtering (egress filtering) to guarantee that only permitted destinations are queried.

**Preconditions:**
- The `/api/screenshot` endpoint is publicly accessible.
- The server’s HTTP client (httpx) acts on the unvalidated user‑supplied URL as a parameter to an external API.

**Source Code Analysis:**
1. In `backend/routes/screenshot.py`, the function `capture_screenshot` accepts `target_url` (sourced directly from the JSON request body) and uses it as the value for the `"url"` key in the parameters sent to the external API call.
2. There is no check to ensure that `target_url` does not point to an internal resource.

**Security Test Case:**
1. Send a POST request to `/api/screenshot` with a JSON payload—for example:
   ```json
   {
     "url": "http://127.0.0.1/admin",
     "apiKey": "any-key"
   }
   ```
2. Observe whether the response contains a screenshot (or error) that suggests the backend tried to access the internal URL instead of only permitted external sites.
3. Repeat with other URLs known to resolve to internal services and verify that there is no filtering in place.
