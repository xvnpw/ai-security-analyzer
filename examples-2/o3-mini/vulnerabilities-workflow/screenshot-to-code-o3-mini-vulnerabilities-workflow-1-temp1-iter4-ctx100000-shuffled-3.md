# Vulnerability List

---

## Vulnerability Name: Arbitrary File Disclosure via Evals Endpoints

**Description:**
The eval endpoints (`/evals`, `/pairwise-evals`, and `/best-of-n-evals`) accept a folder path via query parameters without proper validation or sanitization. An attacker can supply an arbitrary folder (using relative paths such as `../` or even absolute paths like `/etc`) so that the server uses the unsanitized input to list and read files.
**Step-by-Step Exploitation:**
1. The attacker sends a GET request to the endpoint, for example:
   `GET http://<server-address>/evals?folder=../`
2. The server converts the folder parameter into a path without sanitization.
3. The application calls `os.listdir` on the provided folder, potentially listing files outside the intended directory.
4. By varying the folder parameter (e.g., using an absolute path such as `/etc`), the attacker can retrieve sensitive or protected files.

**Impact:**
An attacker may gain access to sensitive internal files (such as configuration files, source code, or logs). This unauthorized disclosure could aid in further exploitation by revealing system details and potential vulnerabilities.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
None – The endpoints only check for the existence of the folder and then list its contents, with no access restrictions or input validation enforced.

**Missing Mitigations:**
- Enforce strict input validation and sanitization on the folder parameter.
- Restrict folder access to a white-listed directory (i.e., force the folder parameter to be within the designated evals subdirectory).
- Normalize the input path and block traversal characters (e.g., “../”).

**Preconditions:**
- The backend API is publicly accessible.
- No authentication or authorization is required to call the eval endpoints.

**Source Code Analysis:**
1. In `backend/routes/evals.py`, the endpoint (e.g., `get_evals`) accepts a query parameter `folder` and creates a `Path` object directly from the input.
2. The code then invokes `os.listdir` on this folder without verifying if it is within an approved directory.
3. The same unsanitized pattern is used in `/pairwise-evals` and `/best-of-n-evals` endpoints.
4. **Visualization:**
   - **Input:** User-supplied folder parameter (potentially `../` or `/etc`)
   - **Processing:** Direct conversion to a `Path` object → `os.listdir` is called
   - **Output:** Unrestricted file listing leading to disclosure

**Security Test Case:**
1. Using a tool like curl, send:
   ```
   curl "http://<server-address>/evals?folder=../"
   ```
2. Verify that the response contains a directory listing from an unintended path.
3. Repeat the test with an absolute path:
   ```
   curl "http://<server-address>/evals?folder=/etc"
   ```
4. Confirm that sensitive file data is disclosed, proving the vulnerability.

---

## Vulnerability Name: Unauthenticated Access to Code Generation and Evaluation Endpoints

**Description:**
Core backend endpoints—most notably the WebSocket endpoint `/generate-code` (which streams code generation from multiple LLM services) and the eval endpoints—are exposed without any authentication or authorization controls.
**Step-by-Step Exploitation:**
1. An attacker using a public network connects to the WebSocket endpoint (`/generate-code`) using a tool such as wscat:
   ```
   wscat -c ws://<server-address>/generate-code
   ```
2. The attacker sends a valid JSON payload that meets the expected parameter schema.
3. The server initiates the code generation process and streams the output without any authentication hurdles.
4. Additionally, the attacker can directly send GET requests to endpoints like `/evals?folder=<arbitrary_path>`, accessing evaluation data without verification.

**Impact:**
An unauthenticated attacker may trigger resource-intensive requests to third-party services (e.g., OpenAI, Anthropic, Gemini) resulting in high costs and potential resource exhaustion. Additionally, the attacker could indirectly manipulate the output or force unintended code generation, further increasing the risk of exploitation.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None – The application is presently designed as a publicly accessible tool with no authentication, rate limiting, or authorization in place.

**Missing Mitigations:**
- Introduce proper authentication (e.g., API keys or tokens) on all sensitive endpoints.
- Implement rate limiting or quotas to prevent abuse and resource exhaustion.
- Restrict high-risk operations (such as code generation) solely to authenticated users.

**Preconditions:**
- The backend is deployed with public access over HTTP/WebSocket connections.
- No authentication measures exist, allowing external actors to freely access these endpoints.

**Source Code Analysis:**
1. In `backend/routes/generate_code.py`, the `/generate-code` WebSocket endpoint accepts connections and processes parameters without any verification or authentication.
2. The endpoint receives downstream requests and directly initiates code generation.
3. Similarly, eval endpoints in `backend/routes/evals.py` process requests without verifying the identity of the requester.

**Security Test Case:**
1. Connect to the WebSocket endpoint using a client such as wscat:
   ```
   wscat -c ws://<server-address>/generate-code
   ```
2. Submit a crafted JSON payload that adheres to the expected schema.
3. Observe the initiation and streaming of code generation without any authentication challenge.
4. Separately, send unauthorized GET requests to eval endpoints (e.g., `/evals?folder=<arbitrary_path>`) and verify that evaluation files are returned.

---

## Vulnerability Name: Server‑Side Request Forgery (SSRF) via Screenshot Endpoint

**Description:**
The `/api/screenshot` endpoint accepts a target URL from the client and directly passes it to an external screenshot service (`https://api.screenshotone.com/take`) without any validation or sanitization.
**Step-by-Step Exploitation:**
1. An attacker crafts a POST request with a JSON payload where the `url` parameter is set to a malicious or internal target (e.g., `http://127.0.0.1/admin`).
2. The attacker sends the payload to the `/api/screenshot` endpoint:
   ```json
   {
     "url": "http://127.0.0.1/admin",
     "apiKey": "any_value"
   }
   ```
3. The server receives the payload and directly relays the supplied URL to the external screenshot service without validating its legitimacy.
4. The forwarded request can cause internal resources to be accessed or probed by the external service, facilitating an SSRF attack.

**Impact:**
An attacker can leverage the SSRF vulnerability to scan internal networks, access sensitive internal endpoints, and potentially launch further attacks by exploiting exposed internal services. This compromise can expose internal infrastructure details and sensitive data.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None – The code takes the client-supplied URL and uses it in the HTTP GET request to the third-party service without any restrictions or sanitization.

**Missing Mitigations:**
- Validate and sanitize the `url` parameter to ensure only external, permitted domains are accepted.
- Enforce a whitelist of allowable domains and block IP ranges corresponding to internal networks (e.g., 127.0.0.1, 10.0.0.0/8).

**Preconditions:**
- The attacker must be able to send POST requests to the `/api/screenshot` endpoint.
- The endpoint is publicly accessible without authentication.

**Source Code Analysis:**
1. In `backend/routes/screenshot.py`, the `capture_screenshot` function reads the `target_url` from the JSON `url` field.
2. The function constructs a parameters dictionary with the provided URL and forwards it via an HTTP GET request to `https://api.screenshotone.com/take`.
3. There is no logic to verify that the URL does not point to internal networks or disallowed addresses.
4. **Visualization:**
   - **Step 1:** User supplies URL via JSON payload.
   - **Step 2:** No sanitization or filtering is performed.
   - **Step 3:** The URL is passed to the external service, risking internal exposure.

**Security Test Case:**
1. Craft a POST request with the following JSON payload:
   ```json
   {
     "url": "http://127.0.0.1/admin",
     "apiKey": "any_value"
   }
   ```
2. Use a tool like curl or Postman to send the request:
   ```
   curl -X POST -H "Content-Type: application/json" -d '{"url": "http://127.0.0.1/admin", "apiKey": "any_value"}' http://<server-address>/api/screenshot
   ```
3. Observe whether the response indicates that the internal URL is being processed by the screenshot service.
4. Confirm that the internal resource was accessed through the forwarded request, verifying the SSRF vulnerability.
