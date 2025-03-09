# Vulnerabilities List

## 1. Unrestricted CORS and Unauthenticated WebSocket Endpoint

**Description:**
The backend is configured to allow all origins via CORSMiddleware (using `allow_origins=["*"]`) without any further access control. In addition, the critical WebSocket endpoint (`/generate-code`) is open to any connection without authentication or origin validation. An external attacker can host a malicious webpage on another domain that automatically opens a WebSocket connection to the backend. By tricking a victim into visiting the attacker’s site, the attacker may intercept any sensitive data (for example, user‑supplied API keys entered in the settings dialog) or even inject crafted payloads that result in unauthorized code-generation requests.

**Impact:**
- Unauthorized third‑party sites can interact with the backend, potentially tricking legitimate users into revealing their API keys.
- The attacker may forge requests to the code-generation endpoint, abusing expensive LLM credits and stealing sensitive usage information.
- This could lead to financial loss, service abuse, and compromise of the sensitive credentials provided by users in the front‑end.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The project simply enables CORS with `allow_origins=["*"]`—a configuration commonly used for public front‑ends but not acceptable for endpoints handling sensitive API key material.

**Missing Mitigations:**
- Restrict allowed origins to a known, trusted set instead of using a wildcard.
- Implement authentication/authorization for the WebSocket endpoint and validate the incoming connection’s origin to ensure it comes from a legitimate front‑end.

**Preconditions:**
- The attacker must be able to lure a user into visiting a malicious webpage that contains JavaScript code establishing a WebSocket connection to the backend.

**Source Code Analysis:**
- **File:** `backend/main.py`
  - The CORSMiddleware is configured with `allow_origins=["*"]`, meaning no origin is blocked.
- **File:** `backend/routes/generate_code.py`
  - The WebSocket endpoint (`/generate-code`) immediately accepts connections using `await websocket.accept()` without checking the origin or requiring any credentials, thereby allowing connections from any external source.

**Security Test Case:**
1. Develop a simple test webpage on an attacker-controlled domain that contains JavaScript to open a WebSocket connection to `ws://<backend-domain>:7001/generate-code`.
2. Program the page to send a dummy payload that includes simulated API keys (or mimic a valid settings input).
3. Log or display the response received from the WebSocket server.
4. Observe that the connection is accepted and responses (or error/status messages) are returned without any restrictions.
5. Verify that the lack of origin validation and authentication allows an attacker to interact with the endpoint.

---

## 2. Unvalidated URL Input in Screenshot API Leading to SSRF

**Description:**
The `/api/screenshot` endpoint accepts a URL in the request body and directly passes it as the `url` parameter to the third‑party screenshot service API (`https://api.screenshotone.com/take`) without any validation or sanitization. An external attacker can supply a malicious target URL (for example, an internal network address like `http://127.0.0.1` or another private IP) which could cause the external service—or, if the service itself is misconfigured, the backend—to access resources on an internal network.

**Impact:**
- May lead to Server‑Side Request Forgery (SSRF) attacks where an attacker induces the backend (or the external service acting on behalf of the backend) to access internal systems or resources that should not be externally exposed.
- This can be exploited for internal network reconnaissance, unauthorized data access, or further lateral movement within a compromised environment.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- There is no filtering or proper validation implemented on the `url` parameter; the endpoint simply forwards the user‑provided URL to the external screenshot service.

**Missing Mitigations:**
- Validate and sanitize the supplied URL by ensuring it uses an allowed scheme (e.g., HTTP/HTTPS) and matches an expected pattern, optionally whitelisting known safe domains.
- Enforce restrictions by disallowing URLs that resolve to local or private IP addresses before passing them to the external API.

**Preconditions:**
- An external attacker must be able to send a POST request to `/api/screenshot` with an arbitrary `url` value along with a valid (or even arbitrary) API key.

**Source Code Analysis:**
- **File:** `backend/routes/screenshot.py`
  - The `ScreenshotRequest` Pydantic model accepts a `url` string from the client.
  - The function `capture_screenshot(target_url, api_key)` is then called with the user‑supplied URL.
  - A parameters dictionary is built that directly includes the `target_url` as the value for the `"url"` key without performing any URL format validation or host whitelisting.

**Security Test Case:**
1. Use a tool (e.g., curl or Postman) to send a POST request to `http://<backend-domain>:7001/api/screenshot` with a JSON body such as:
   ```json
   {
     "url": "http://127.0.0.1/admin",
     "apiKey": "test-key"
   }
   ```
2. Observe the response. If the backend processes the request and returns a screenshot (or an error message that references the internal address), it indicates that the URL was accepted without proper validation.
3. Optionally, verify via request logs or network monitoring whether the backend, or the external service acting on its behalf, attempts to access the internal URL.
4. Conclude that the endpoint is vulnerable to SSRF due to unsanitized user input.
