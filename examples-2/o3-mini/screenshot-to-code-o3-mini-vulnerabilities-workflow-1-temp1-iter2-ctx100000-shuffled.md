Below is the combined list of vulnerabilities. Duplicate vulnerabilities from the two lists were merged into a single entry while preserving all the details as provided.

---

### Vulnerability Name: Server‑Side Request Forgery (SSRF) in Screenshot API Endpoint

**Description:**
The `/api/screenshot` endpoint (located in `backend/routes/screenshot.py`) accepts a JSON request containing a user‑supplied URL (via the `url` field) and an API key. The URL is directly embedded in a request sent to an external screenshot service (`https://api.screenshotone.com/take`) without any validation or sanitization. This allows an attacker to supply a deliberately crafted URL (for example, an internal address like `http://169.254.169.254/`) and force the backend to make unintended outbound requests.
**Step by Step Trigger Process:**
1. An attacker connects to the publicly accessible `/api/screenshot` endpoint.
2. A JSON payload is crafted where the `url` is set to a target internal address (or any malicious URL) while providing an arbitrary `apiKey`.
3. The service forwards this URL directly to the external screenshot API service, thus indirectly instructing the backend to access the specified target URL.

**Impact:**
An attacker leveraging this SSRF vulnerability may:
- Access internal network resources that are typically shielded from external requests.
- Bypass network segmentation and probe non‑public services.
- Potentially use the backend as a proxy to conduct further internal reconnaissance or other secondary attacks.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- No input validation or URL whitelisting is applied on the screenshot endpoint.

**Missing Mitigations:**
- Validate and sanitize the incoming URL to ensure it complies with an allowed format.
- Implement a strict whitelist of allowed hostnames or reject URLs that resolve to private/internal IP ranges.
- Optionally proxy and validate the responses from the external screenshot service to avoid exposure of unintended data.

**Preconditions:**
- The `/api/screenshot` endpoint is publicly accessible.
- The backend server is permitted to make outbound network calls without filtering.

**Source Code Analysis:**
1. In `backend/routes/screenshot.py`, a `ScreenshotRequest` model accepts fields for `url` and `apiKey`.
2. The endpoint function receives the request and extracts the `url` without any sanitization.
3. The function `capture_screenshot(target_url, api_key, device)` is then called, which directly embeds the attacker-controlled URL into the parameters for the GET request sent to `https://api.screenshotone.com/take`.
4. Because the URL is not pre-checked, any attacker-supplied URL (including internal addresses) will be forwarded to the external service.

**Security Test Case:**
1. Send a POST request to `/api/screenshot` with a JSON body similar to:
   ```json
   {
     "url": "http://169.254.169.254/",
     "apiKey": "any-value"
   }
   ```
2. Monitor the backend’s network traffic (or examine server logs) to check if a request is made to the internal IP.
3. Verify that the response or behavior confirms that the internal URL was processed, thereby confirming the SSRF vulnerability.

---

### Vulnerability Name: Directory Traversal Leading to Arbitrary File Read in Evals Endpoints

**Description:**
Certain endpoints under `/evals` (e.g., `/evals`, `/pairwise-evals`, and `/best-of-n-evals` in `backend/routes/evals.py`) accept a `folder` query parameter. This parameter is used directly to construct filesystem paths using Python’s `Path` object and functions like `os.listdir` without any sanitization. An attacker can supply an absolute or relative path (for example, `/etc` or `../../secret`) that causes the application to traverse directories and disclose sensitive files.
**Step by Step Trigger Process:**
1. An attacker crafts a GET request to an eval endpoint with a manipulated `folder` parameter containing path traversal characters (such as `../../`).
2. The backend uses this parameter directly to create a path object and list directory contents without verifying that it stays within an allowed directory.
3. As a result, the endpoint may return file listings (or file contents) from sensitive areas of the filesystem.

**Impact:**
- Unauthorized disclosure of system files, configuration files, or internal documentation.
- The disclosed information could be leveraged for further attacks, such as privilege escalation or lateral movement within the environment.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The code checks for the existence of the specified folder but does not perform bounds checking, path normalization, or apply directory restrictions.

**Missing Mitigations:**
- Sanitize and canonicalize the `folder` parameter to remove any path traversal characters.
- Restrict file access by limiting the permissible directory to a known safe path or by applying a whitelist of allowed directories.

**Preconditions:**
- The eval endpoints are publicly accessible.
- An attacker can control the `folder` query parameter in the URL.

**Source Code Analysis:**
1. In `backend/routes/evals.py`, the `get_evals` function begins by accepting the `folder` query parameter.
2. The parameter is passed to the `Path` constructor and used directly with `os.listdir` to list all files within that path.
3. The logic then filters for files ending with “.html” and returns them, without verifying that the folder lies within an intended base directory.

**Security Test Case:**
1. Send a GET request to an endpoint such as `/evals?folder=../../../../etc` using a tool like curl or Postman.
2. Observe the response to see if it lists files from outside the intended directory.
3. If sensitive files or an error message that exposes internal file structure appears, the vulnerability is confirmed.

---

### Vulnerability Name: Insecure Debug File Storage Exposing Sensitive Data

**Description:**
The debug system in `backend/debug/DebugFileWriter.py` writes detailed artifacts (including prompt messages, AI completions, and full code responses) to a file system location specified by the environment variable `DEBUG_DIR` whenever debug mode is enabled (controlled by `IS_DEBUG_ENABLED`). If debugging remains enabled in a production environment—or if the debug directory is misconfigured as a publicly accessible directory—an attacker may access these files and obtain sensitive internal details.
**Step by Step Trigger Process:**
1. An attacker identifies that the application is in debug mode (`IS_DEBUG_ENABLED=True`).
2. The attacker discovers or guesses the location of the debug directory from `DEBUG_DIR`.
3. The attacker accesses the directory (either via exposed static file serving or other means) and reads the debug artifacts to extract sensitive information.

**Impact:**
- Exposure of detailed internal debug logs which may contain architectural details, API key usage, and other sensitive data.
- This information can be exploited to further compromise the system, craft targeted attacks, or escalate privileges.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- Debug logging is controlled by an environment variable (`IS_DEBUG_ENABLED`), which should ideally not be enabled in production.

**Missing Mitigations:**
- Ensure that debug mode is disabled by default for production deployments.
- Store debug artifacts in a secured, non‑public directory with restricted access.
- Consider redacting or sanitizing sensitive information in debug outputs prior to writing them to disk.

**Preconditions:**
- The application is deployed with debug mode enabled (`IS_DEBUG_ENABLED=True`).
- The debug directory (as defined by `DEBUG_DIR`) is improperly secured or served publicly.

**Source Code Analysis:**
1. In `backend/debug/DebugFileWriter.py`, when `IS_DEBUG_ENABLED` is set to true, the application creates or reuses the directory specified by `DEBUG_DIR`.
2. The code then writes several debug files (including full AI response data and extracted HTML) directly into this directory without rigorous access control.
3. This process results in sensitive data being stored in a location that might be accessible if misconfigured.

**Security Test Case:**
1. Deploy the application with `IS_DEBUG_ENABLED=True` and set the `DEBUG_DIR` to a known location.
2. Trigger an application process that logs detailed debug information (for example, an AI–driven code generation request).
3. Attempt to access the debug directory through its public interface or by listing its contents, and verify if sensitive debug data is exposed.

---

### Vulnerability Name: Unauthenticated Access to AI Code Generation WebSocket Endpoint

**Description:**
The WebSocket endpoint at `/generate-code` (located in `backend/routes/generate_code.py`) accepts incoming JSON parameters without enforcing any authentication or authorization. In the absence of user validation, the endpoint falls back to using API keys defined in the environment if the client omits valid credentials. This setup allows an attacker to connect via WebSocket and supply arbitrary parameters, resulting in unauthorized AI code generation requests.
**Step by Step Trigger Process:**
1. An external attacker, with access to the publicly available WebSocket endpoint, connects to `/generate-code` using a WebSocket client (e.g., `wscat`).
2. The attacker sends a JSON payload containing the parameters needed to trigger AI code generation, while intentionally omitting or providing invalid authentication details.
3. Since no valid user authentication is enforced, the endpoint defaults to using the API keys from the environment, thereby processing the malicious request.

**Impact:**
- Unauthorized consumption of AI API credits (from providers such as OpenAI, Anthropic, etc.), resulting in potential financial loss.
- Resource exhaustion and possible disruption of service, as the attack abuses the expensive AI code generation functionality.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- No authentication, authorization, or rate limiting is enforced on the WebSocket endpoint.

**Missing Mitigations:**
- Implement robust user authentication and authorization before processing WebSocket requests.
- Enforce strict rate limiting and validate incoming WebSocket messages to ensure legitimacy.

**Preconditions:**
- The backend instance is publicly accessible.
- API keys are pulled from the environment when a client omits valid credentials.

**Source Code Analysis:**
1. In `backend/routes/generate_code.py`, the WebSocket endpoint is defined with `@router.websocket("/generate-code")`.
2. Upon connection, the WebSocket is accepted immediately, and the endpoint waits for a JSON payload from the client.
3. The payload is processed by a function (e.g., `extract_params`) which does not verify the identity or credentials of the requester, falling back on environment-based API keys if none are provided.
4. As a consequence, an unauthenticated user is able to trigger AI code generation requests.

**Security Test Case:**
1. Connect to the WebSocket endpoint using a tool like `wscat`:
   ```
   wscat -c ws://public-instance.example.com/generate-code
   ```
2. Send a minimal JSON payload that omits proper API keys or credentials yet adheres to the expected schema.
3. Verify that the server responds by streaming generated code chunks, indicating that the AI call was made using fallback credentials.
4. Check logs or billing information to confirm unauthorized consumption of API credits.

---

### Vulnerability Name: Insecure CORS Configuration Allowing Credentialed Requests from Any Origin

**Description:**
The FastAPI application in `backend/main.py` applies CORSMiddleware with an overly permissive configuration. It allows any origin (`allow_origins=["*"]`) while also enabling credentials (`allow_credentials=True`). According to the CORS specification, when credentials (like cookies) are allowed the server must not use the wildcard (`*`) for allowed origins. This misconfiguration enables any website, including malicious ones under an attacker’s control, to make credentialed requests to the API.
**Step by Step Trigger Process:**
1. A malicious website is hosted by an attacker.
2. The attacker crafts a web page that initiates AJAX requests (with credentials, such as cookies) to the backend API.
3. Due to the CORS configuration in place, the browser permits the requests from any origin even if credentials are involved, allowing the attacker to receive sensitive response data.

**Impact:**
- An attacker may trick authenticated users into visiting a malicious website that makes credentialed AJAX calls to the backend API.
- Such attacks can lead to unauthorized actions on behalf of the user (CSRF-like behavior), data leakage, or further compromise of the application.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The application includes CORS configuration; however, it is misconfigured by using `allow_origins=["*"]` in combination with `allow_credentials=True`.

**Missing Mitigations:**
- Replace the wildcard origin with a strict whitelist of trusted origins when credentials are enabled.
- Alternatively, disable credentials for public APIs that do not require them.

**Preconditions:**
- The backend API is accessed in contexts (e.g., browsers) where credentials such as cookies are attached automatically.
- An attacker can host a controlling web page on a malicious domain.

**Source Code Analysis:**
1. In `backend/main.py`, the application adds CORSMiddleware as follows:
   ```python
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["*"],
       allow_credentials=True,
       allow_methods=["*"],
       allow_headers=["*"],
   )
   ```
2. The combination of a wildcard allowed origin with credential support violates best practices, thereby exposing credentialed endpoints to requests from any domain.

**Security Test Case:**
1. From a controlled client (using a browser with the Origin header set to a malicious domain like `http://malicious.example.com`), initiate an AJAX request to one of the API endpoints with credentials enabled (cookies attached).
2. Check the response headers to confirm that the backend returns `Access-Control-Allow-Origin: *` (or does not restrict the origin).
3. Validate that after correcting the configuration to only allow specific origins (for example, `https://trusted.example.com`), requests originating from unauthorized domains are blocked.

---

*All the above vulnerabilities are exploitable by an external attacker on a publicly accessible instance of the application and remain unmitigated in the current project codebase.*
