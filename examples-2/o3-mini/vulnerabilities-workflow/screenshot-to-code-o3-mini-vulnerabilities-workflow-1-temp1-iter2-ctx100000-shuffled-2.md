Below is the updated list of vulnerabilities that meet the specified criteria:

---

### Vulnerability Name: Unauthenticated Access to AI Code Generation WebSocket Endpoint

**Description:**
The WebSocket endpoint at `/generate-code` (located in `backend/routes/generate_code.py`) accepts incoming JSON parameters without enforcing any authentication or authorization. In the absence of user validation, the endpoint falls back to using API keys defined in the environment when the client omits valid credentials. An external attacker can simply connect via WebSocket and supply arbitrary parameters, thereby triggering AI code generation requests that consume expensive AI API credits.

**Impact:**
An attacker may abuse this endpoint to generate code on demand, resulting in unauthorized consumption of third‑party AI services (e.g. OpenAI, Anthropic, Gemini). This can lead to significant financial losses, resource exhaustion, and potential disruption of service.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
No authentication, authorization, or rate limiting is applied in the code.

**Missing Mitigations:**
• Implement proper user authentication and authorization checks before processing requests.
• Enforce strict rate limiting and validation on incoming WebSocket messages.

**Preconditions:**
• The backend instance is publicly accessible.
• Environment API keys are being used when the client does not supply valid credentials.

**Source Code Analysis:**
- In `backend/routes/generate_code.py` the endpoint starts with:
  ```python
  @router.websocket("/generate-code")
  async def stream_code(websocket: WebSocket):
      await websocket.accept()
      # ...
      params: dict[str, str] = await websocket.receive_json()
      extracted_params = await extract_params(params, throw_error)
      # Fallback: if keys are missing, 'get_from_settings_dialog_or_env' pulls from environment
  ```
- The function `get_from_settings_dialog_or_env` falls back to environment variables without verifying the identity of the requester.

**Security Test Case:**
1. Using a WebSocket client (for example, `wscat`), connect to the endpoint:
   ```
   wscat -c ws://public-instance.example.com/generate-code
   ```
2. Send a minimal JSON payload (omitting valid API keys or any authentication details) that still conforms to the expected schema.
3. Observe that the server responds by streaming code chunks—indicating that the AI call was made even without proper authentication.
4. Verify the consumption of API calls (via logs or billing) to confirm unauthorized usage.

---

### Vulnerability Name: Server‑Side Request Forgery (SSRF) in Screenshot Endpoint

**Description:**
The endpoint `/api/screenshot` in `backend/routes/screenshot.py` accepts a user‑supplied URL (via the `url` field in the JSON body) without any validation or sanitization. The URL is then incorporated directly into the parameters sent to the external screenshot service (`https://api.screenshotone.com/take`). An attacker can supply a URL pointing to an internal or restricted resource, potentially using the server as a proxy to access internal network services.

**Impact:**
An attacker may leverage SSRF to probe internal systems, access private endpoints, or induce the backend to perform requests against internal infrastructure. This can lead to information disclosure or further compromise of the internal network.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
There is no validation or filtering of the `url` parameter before making the request.

**Missing Mitigations:**
• Validate and sanitize the input URL.
• Enforce a whitelist of allowed domains or use a proxy that restricts access to internal IP ranges.

**Preconditions:**
• The API is publicly accessible.
• The server’s network configuration permits outbound requests that could reach internal resources.

**Source Code Analysis:**
- In `backend/routes/screenshot.py`:
  ```python
  class ScreenshotRequest(BaseModel):
      url: str
      apiKey: str

  @router.post("/api/screenshot")
  async def app_screenshot(request: ScreenshotRequest):
      url = request.url
      api_key = request.apiKey
      image_bytes = await capture_screenshot(url, api_key=api_key)
      # ...
  ```
- In `capture_screenshot()`, the `target_url` is embedded in the parameters without checks:
  ```python
  params = {
      "access_key": api_key,
      "url": target_url,
      # other parameters
  }
  ```

**Security Test Case:**
1. Use a tool like curl or Postman to issue a POST request to the endpoint with a payload such as:
   ```json
   {
     "url": "http://127.0.0.1:80",
     "apiKey": "dummy"
   }
   ```
2. Monitor the network traffic or check logs to determine whether the backend initiates a request to the internal URL.
3. Confirm that the response or behavior indicates that the internal address was accessed.

---

### Vulnerability Name: Directory Traversal Leading to Arbitrary File Read in Evals Endpoints

**Description:**
Several endpoints under `/evals` (for example, GET `/evals`, `/pairwise-evals`, and `/best-of-n-evals` in `backend/routes/evals.py`) accept a `folder` query parameter provided directly by the client. This parameter is used to build file system paths (via the `Path` constructor and `os.listdir`) without proper sanitization or restriction. An attacker may supply specially crafted folder paths (e.g. using `../` sequences) to traverse directories and read files that were not intended for public disclosure.

**Impact:**
This vulnerability can result in the unintended disclosure of arbitrary files (especially HTML files used for evaluations) and other sensitive information stored on the server’s filesystem.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The code only checks for the existence of the folder but does not normalize or restrict the path.

**Missing Mitigations:**
• Sanitize and normalize the `folder` parameter.
• Restrict file access to a known safe directory (e.g., by whitelisting allowed base directories).

**Preconditions:**
• The eval endpoints are publicly accessible.
• An attacker can supply an arbitrary folder value.

**Source Code Analysis:**
- In `backend/routes/evals.py`, the `get_evals` function begins with:
  ```python
  @router.get("/evals", response_model=list[Eval])
  async def get_evals(folder: str):
      if not folder:
          raise HTTPException(status_code=400, detail="Folder path is required")
      folder_path = Path(folder)
      if not folder_path.exists():
          raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
      files = { f: os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html") }
  ```
- The folder parameter is directly used without a whitelist or path normalization, permitting traversal.

**Security Test Case:**
1. Send a GET request to the endpoint with a folder parameter like:
   ```
   GET /evals?folder=../../../../etc
   ```
2. Examine the response to see if it lists files from outside the intended directory.
3. If sensitive files are returned (or error messages reveal their existence), the vulnerability is confirmed.

---

### Vulnerability Name: Insecure CORS Configuration Allowing Credentialed Requests from Any Origin

**Description:**
In `backend/main.py`, the FastAPI application applies the CORSMiddleware with an overly permissive configuration. It allows any origin (`allow_origins=["*"]`) while also enabling credentials (`allow_credentials=True`). According to the CORS specification, when credentials are allowed, the server must not use the wildcard (`*`) as the allowed origin. This misconfiguration can enable a malicious website to make credentialed cross-origin requests to the API.

**Impact:**
An attacker may trick an authenticated user into visiting a malicious domain which then makes AJAX calls (including those with credentials such as cookies) to the backend API. Such attacks can result in cross-site request forgery (CSRF)–like behavior and unauthorized actions on behalf of the user.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The project does include CORS configuration; however, it is misconfigured by combining `allow_origins=["*"]` with `allow_credentials=True`.

**Missing Mitigations:**
• Remove the wildcard origin when credentials are enabled and instead specify a whitelist of trusted origins.
• Alternatively, disable credentials if the API is truly public.

**Preconditions:**
• The backend API is accessed by browsers that store credentials (e.g., cookies).
• An attacker can host a page on a controlled domain and trick a user with valid credentials to visit it.

**Source Code Analysis:**
- In `backend/main.py`:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
  This combination violates best practices for CORS when using credentialed requests.

**Security Test Case:**
1. From a test client (for example, using a browser with a manipulated Origin header set to `http://malicious.example.com`), send an AJAX request (with credentials enabled) to one of the backend API endpoints.
2. Observe that the response includes `Access-Control-Allow-Origin: *` or otherwise does not restrict the origin, enabling the malicious site to access the response data.
3. Verify that after applying a strict whitelist (for example, allowing only `https://screenshottocode.com`), requests from unauthorized origins are blocked.

---

All the above vulnerabilities are valid, of at least high severity, are not already mitigated, and are exploitable by an external attacker on a publicly accessible instance of the application.
