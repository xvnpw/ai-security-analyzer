# Combined Vulnerabilities

## 1) Arbitrary File Read via Unrestricted Folder Parameter

### Description
An attacker can pass arbitrary folder paths to the API endpoints (`/evals`, `/pairwise-evals`, or `/best-of-n-evals`) in order to read `.html` files from anywhere on the server’s file system. These endpoints trust the `folder` (and similar) query parameter, check only if the directory exists, then read all `.html` files there and return their contents as part of the API response. By specifying sensitive folders or files, an external attacker can exfiltrate confidential information stored in `.html` files on the server.

In addition, certain code flows in `backend/routes/evals.py` look for a `.png` file with the same base name in `EVALS_DIR/inputs` before returning each `.html` file’s content. If a matching `.png` is found, the backend returns the `.html` file. Consequently, if a developer inadvertently places any `.html` file in an arbitrary folder with a corresponding `.png` in `EVALS_DIR/inputs`, an attacker can fetch that `.html` content. In both scenarios, `.html` files are accessible to unauthenticated users.

### Step-by-step Trigger
1. Attacker discovers or guesses the API endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) that accept a `folder` (or `folderX`) query parameter.
2. Attacker supplies an arbitrary path such as `/home/user/secrets/`, `/var/www/`, or any directory containing `.html` files.
3. The backend checks if that directory exists; if so, it attempts to list `.html` files in that location.
4. Depending on the code path, the backend may also check for matching `.png` files in `EVALS_DIR/inputs`. If found, it proceeds to read the `.html` file content.
5. The application returns the file content (in base64 or plain text) in the JSON or HTTP response.
6. The attacker gains access to any data contained in those `.html` files, which may include sensitive or private information.

### Impact
This vulnerability allows attackers to read arbitrary `.html` files from the host’s filesystem, potentially exposing sensitive information such as secrets, tokens, logs, or configuration files saved under an `.html` extension. Even where the route requires a matching `.png`, the risk remains that a correctly named `.html` file in a server path could be disclosed. Overall, this poses a serious threat to the confidentiality of the application and underlying system.

### Vulnerability Rank
**Critical**
This issue enables an unauthenticated attacker to directly leak sensitive information from the server.

### Currently Implemented Mitigations
- None. The server only verifies that the directory exists and does not restrict or sanitize the user-supplied path.

### Missing Mitigations
- Restrict directory traversal by validating or sanitizing the `folder` parameter, ensuring it only points to a predefined safe data directory.
- Disallow use of absolute paths, “../”, or any patterns that escape the legitimate data folder.
- If browsing or debugging files is necessary, implement strict authorization or remove the functionality from production.

### Preconditions
- The attacker can access the API endpoints externally and no authentication is required.
- The server contains `.html` files either outside the intended evaluation folder or in a location where a matching `.png` might exist.
- The attacker can guess or discover valid folder paths containing `.html` files.

### Source Code Analysis
- In `routes/evals.py`, functions like `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` accept a user-controlled `folder` parameter.
- The code checks `folder_path.exists()`—if true, it enumerates `.html` files in that folder.
- In some code paths, for each `.html` file found, the backend checks if a `.png` with the same base name resides in `EVALS_DIR/inputs`. If so, it returns the `.html` content.
- No path restriction or authentication is enforced. For example:
  ```python
  folder_path = Path(folder)
  if not folder_path.exists():
      raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

  files = [f for f in os.listdir(folder) if f.endswith(".html")]
  # Possibly checks a matching .png in EVALS_DIR/inputs

  with open(output_file, "r", encoding="utf-8") as f:
      output_html = f.read()
  # output_html is then returned to the caller
  ```
- As a result, attackers can specify arbitrary paths (e.g., `/etc/nginx/`) to exfiltrate `.html` files.

### Security Test Case
1. From an external machine, send `GET /evals?folder=/` (or any other path on the filesystem with `.html` files).
2. Observe that the server returns `.html` file contents within the HTTP response if they exist.
3. Verify the attacker can read internal files not intended for public disclosure.
4. Place a test `.html` file (e.g. `secret.html`) in `/some/hidden/folder` and a matching `secret.png` in `EVALS_DIR/inputs`, then request:
   `GET /evals?folder=/some/hidden/folder`
   Confirm `secret.html` is returned when it matches a `.png` base name.
5. Confirm these responses demonstrate a lack of path restrictions or file access constraints, proving the vulnerability.

---

## 2) Unrestricted Access to Costly API Endpoints

### Description (Step by Step)
1. An attacker discovers the publicly available `/generate-code` route (`backend/routes/generate_code.py`) and establishes a WebSocket connection without any authentication.
2. The attacker continuously sends large prompts or numerous requests (e.g., long base64 images or lengthy text) to the service.
3. The backend relays these requests to external APIs (OpenAI, Anthropic, ScreenshotOne, etc.) using credentials stored in environment variables.
4. Because there are no rate limits or authentication checks, an attacker can trigger unbounded usage, racking up significant expenses for the service owner.

### Impact
The service owner may incur substantial monetary costs due to excessive API calls (OpenAI, Anthropic, ScreenshotOne). Account limits may also be exhausted, disrupting or halting legitimate usage.

### Vulnerability Rank
**High**

### Currently Implemented Mitigations
- None. No authentication, rate limiting, or usage restriction is in place for `/generate-code`.

### Missing Mitigations
- Enforce authentication (API tokens, OAuth, or similar).
- Implement rate limiting and throttling measures (e.g., IP-based or token bucket).
- Restrict usage of `/generate-code` to authorized users only.
- Limit request size or frequency to prevent abuse.

### Preconditions
- The URL of the FastAPI instance is publicly known or guessable.
- The backend is configured with valid environment variables for third-party API keys.
- Any client on the internet can open a WebSocket to the `/generate-code` endpoint.

### Source Code Analysis
- In `backend/routes/generate_code.py`, a WebSocket endpoint `/generate-code` is exposed without authentication or usage constraints.
- Calls like `stream_openai_response` or `stream_claude_response` use the environment-variable credentials to perform actions on behalf of the project owner.
- CORS is enabled with `allow_origins=["*"]`, permitting requests from any web origin.

### Security Test Case
1. Host the application publicly without any security layers.
2. Write a test script that opens a WebSocket to `/generate-code` and sends large or repeated prompts.
3. Confirm that usage scales indefinitely and the service owner’s API keys are charged for each request.
4. Demonstrate that there is no rate limiting, no authentication, and no usage quota, confirming the vulnerability.
