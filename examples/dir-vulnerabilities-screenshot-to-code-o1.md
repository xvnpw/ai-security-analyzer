## 1. Unauthenticated and Unlimited Access to Code Generation Endpoints

**Description**
An external attacker can invoke the `/generate-code` WebSocket endpoint repeatedly without any authentication or usage limitation. By sending repeated or large requests, the attacker forces the application to call OpenAI/Anthropic language model APIs, incurring cost and potentially exhausting the associated API key’s quota.

1. The attacker locates the publicly available `/generate-code` WebSocket endpoint.
2. The attacker crafts repeated requests or automates sending large prompts to the endpoint.
3. Each request triggers a backend call to OpenAI or Anthropic APIs, consuming credits and accruing charges.
4. Eventually the service owner’s account may run out of credits or be heavily billed without any direct benefit to them.

**Impact**
- **Financial damage** due to uncontrolled API calls on paid language model credits.
- **Service disruption** for legitimate users if the API key usage limit or spending cap is reached.

**Vulnerability Rank**
High

**Currently Implemented Mitigations**
None identified in the code for protecting or limiting access to `/generate-code`.

**Missing Mitigations**
- **Authentication**: Ensure only authorized users can invoke the code generation feature.
- **Rate Limiting / Quotas**: Impose rate limits to prevent automated abuse.
- **API Key Isolation**: Use per-user keys or billing separation to limit damage if one key is abused.

**Preconditions**
- Attacker has network access to the website endpoint.
- The `/generate-code` route is publicly exposed with no checks on incoming requests.

**Source Code Analysis**
- **File**: `backend/routes/generate_code.py`
- In `@router.websocket("/generate-code")` function, there is no requirement for credentials or user identity, and no rate limiting.
- Received prompts are processed and sent on to OpenAI/Anthropic purely based on user-supplied data.

**Security Test Case**
1. Write a small script to open a WebSocket connection to `/generate-code`.
2. Send an arbitrary prompt or a large repeated prompt in quick succession (e.g., in a loop).
3. Observe in the OpenAI/Anthropic dashboard that requests and corresponding charges increase dramatically, confirming the lack of access control and rate limits.


---

## 2. Arbitrary Local File Reading Through Evals Endpoints

**Description**
Several endpoints (e.g., `GET /evals`, `GET /pairwise-evals`, `GET /best-of-n-evals`) accept a `folder` parameter that is used directly to list and read `.html` files from the filesystem. There is no path validation or restriction. An attacker can supply any path on the server that contains matching `.html` files (or symlinks to sensitive files renamed with the `.html` extension) and have them returned in the response.

1. Attacker locates the `folder` parameter by examining the API.
2. Attacker supplies an absolute or relative path (e.g., `/etc/ssl`, `../some/private/dir`) if it has or can be made to have files ending in `.html`.
3. The endpoint calls `os.listdir` and reads the matching `.html` files, returning those contents to the attacker.

**Impact**
- **Information disclosure** by reading local files on the server, potentially leaking sensitive details if `.html` files or symbolic links are present.
- Attackers can pivot further with knowledge gleaned from internal file contents.

**Vulnerability Rank**
High

**Currently Implemented Mitigations**
None. The route logic directly concatenates the user-supplied path with the filesystem listing and reads it.

**Missing Mitigations**
- **Path Restriction**: Restrict these endpoints to only a known safe directory (e.g., a dedicated “evals” folder).
- **Validation**: Reject any attempts at relative paths (`../`) or absolute paths that extend beyond a whitelisted directory.
- **File Type Checking**: Ensure only certain known safe files in a single folder are readable.

**Preconditions**
- Attacker has network access to query the eval endpoints.
- There exist readable `.html` files or symlinks in the targeted filesystem path.

**Source Code Analysis**
- **File**: `backend/routes/evals.py`
- Functions like `get_evals(folder: str)` call `folder_path = Path(folder)` and `os.listdir(folder)` with no input sanitization, returning the file contents.

**Security Test Case**
1. Send a request to `/evals?folder=/tmp` (or another server directory containing one or more `.html` files).
2. Observe the response listing and contents of those `.html` files.
3. Confirm that no checks or filters block reading from arbitrary paths.


---

## 3. Rendering LLM-Generated HTML Without Sanitization (Possible XSS)

**Description**
When code generation completes, the backend sends raw HTML output from the language model to the client via JSON messages of type `"setCode"`. In typical usage, the front-end loads or displays that HTML. An attacker controlling the prompt (or any user with access to the code generation feature) could instruct the LLM to embed malicious JavaScript. If this HTML is then inserted into the DOM without sanitization or isolated sandboxing, it can execute code in the user’s browser.

1. An attacker enters a prompt like: “Create an HTML page containing `<script>alert('XSS');</script>`…”.
2. The LLM returns the malicious script in its generated HTML.
3. The front-end or any integrated viewer displays the raw HTML, allowing the script to run with the app’s origin privileges.

**Impact**
- **XSS** leads to private data exfiltration, session hijacking, or performing any actions on behalf of the user.
- If multiple users share a session or it’s a multi-tenant environment, the attacker can compromise other users’ sessions.

**Vulnerability Rank**
High

**Currently Implemented Mitigations**
None. The code merely extracts `<html>` content from the model’s response and sends it to the UI.

**Missing Mitigations**
- **HTML Sanitization** (e.g., use a trusted library to remove scripts and other dangerous tags).
- **Sandboxing** in an `<iframe>` from a different origin.
- Optionally, **CSP** (Content Security Policy) to prevent inline script execution.

**Preconditions**
- Attacker can provide input to the LLM (e.g., via `/generate-code`).
- The user or the system automatically renders or hosts the returned HTML in the same origin.

**Source Code Analysis**
- **File**: `backend/routes/generate_code.py`, near the `@router.websocket("/generate-code")` function.
- Completions are returned as raw HTML strings without any sanitization.
- Front-end presumably injects this into the DOM, enabling potential script execution.

**Security Test Case**
1. Send a prompt to `/generate-code` containing:
   ```
   <script>alert('XSS');</script>
   ```
2. Wait for the LLM to echo the malicious code in the generated HTML.
3. Observe if the rendered result triggers a JavaScript alert (or other malicious behavior) in the browser.


---

## 4. Middle-Man SSRF via Unrestricted Screenshot Service

**Description**
The `/api/screenshot` endpoint sends user-supplied URLs to the external ScreenshotOne.com service, returning the screenshot image bytes. Though the screenshot process happens on ScreenshotOne’s side, an attacker may use this route to probe or snapshot internal resources if ScreenshotOne is able to reach them. There is no URL filtering, so any address can be provided.

1. An attacker calls `POST /api/screenshot` with a local or internal IP in `request.url` (e.g., `http://10.0.0.1:8080`).
2. If ScreenshotOne has broader network access, it attempts to connect there and retrieve a screenshot.
3. The resulting screenshot is given back to the attacker, potentially revealing internal services or behind-a-firewall data.

**Impact**
- Indirect reconnaissance into private or restricted endpoints if ScreenshotOne can connect to them.
- Potentially bypassing IP-based or basic firewall restrictions if the ScreenshotOne service’s location is trusted.

**Vulnerability Rank**
Medium

**Currently Implemented Mitigations**
None identified. The code directly passes the attacker’s URL to the ScreenshotOne API without checks.

**Missing Mitigations**
- **Domain Allow-List**: Only permit screenshots for known acceptable domains.
- **Regex / IP Filtering**: Block requests to local or private IP ranges.
- **User Verification**: Restrict this feature to authenticated or paid users to reduce abuse.

**Preconditions**
- Attacker can reach the `/api/screenshot` endpoint.
- The remote screenshot provider can attempt to fetch private/internal endpoints from its vantage point.

**Source Code Analysis**
- **File**: `backend/routes/screenshot.py`, in the `capture_screenshot()` function.
- The `target_url` parameter is passed directly to the external screenshot service with no validation.

**Security Test Case**
1. Issue a `POST /api/screenshot` request with JSON:
   ```json
   {
     "url": "https://internal-service.example.local/"
   }
   ```
2. Inspect the response to see if a screenshot is returned, indicating internal access.
3. Confirm that no domain checks block attempts to screenshot private addresses.


---

> These vulnerabilities represent high-priority concerns for the “screenshot-to-code” application. To secure the system, implement authentication and authorization checks, sanitize or isolate LLM-generated outputs, limit local file reading to known directories, and restrict the screenshot feature to allowlisted domains.
