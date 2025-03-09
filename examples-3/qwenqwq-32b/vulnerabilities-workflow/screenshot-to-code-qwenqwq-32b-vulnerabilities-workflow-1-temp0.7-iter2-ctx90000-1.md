# Updated List of Vulnerabilities

## 1. Path Traversal Vulnerability in `/evals` Endpoints (Critical)
**Vulnerability Name:** Path Traversal via Unsanitized File Paths
**Description:**
The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints allow unauthenticated users to specify arbitrary `folder` paths via query parameters. These paths are directly used in `os.path.exists` and file operations without validation, enabling access to sensitive files outside the intended directory.

**Step-by-Step Exploitation:**
1. An attacker crafts a request with a malicious `folder` parameter, e.g., `folder=/etc/passwd`.
2. The backend reads files from the specified path and returns their contents via the API.

**Impact:**
- Sensitive file exposure (e.g., credentials, source code).
- Potential system compromise via reading SSH keys or configuration files.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** None.
**Missing Mitigations:**
- Validate `folder` paths to ensure they reside within an allowed directory.
- Sanitize paths using `pathlib.Path` to prevent traversal.

**Preconditions:**
- The service is publicly accessible.

**Source Code Analysis:**
- **File:** `backend/routes/evals.py`
  ```python
  async def get_evals(folder: str):
      if not folder:
          ...
      if not os.path.exists(folder):  # Unvalidated path
          ...
  ```
  The `folder` parameter is directly used without validation.

**Security Test Case:**
1. Use `curl` to send `GET /evals?folder=/etc/passwd`.
2. Verify the response contains `/etc/passwd` contents.

---

## 2. Exposure of API Keys via WebSocket (High)
**Vulnerability Name:** API Key Leakage via Client-Supplied Parameters
**Description:**
API keys (e.g., OpenAI) are sent in plaintext over WebSocket connections. If HTTPS is not enforced, attackers can intercept these keys and misuse external services.

**Step-by-Step Exploitation:**
1. An attacker intercepts the WebSocket traffic using tools like Wireshark.
2. Captures the API key from the `generated_code_config` parameters.

**Impact:**
- Unauthorized use of external services (e.g., OpenAI credits depletion).

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None.
**Missing Mitigations:**
- Enforce HTTPS for WebSocket connections.
- Avoid client-supplied API keys; store them securely on the server.

**Preconditions:**
- The service is not using HTTPS for WebSocket communication.

**Source Code Analysis:**
- **File:** `backend/routes/generate_code.py`
  ```python
  openai_api_key = get_from_settings_dialog_or_env(params, "openAiApiKey", OPENAI_API_KEY)
  ```
  The `openAiApiKey` is read directly from client parameters and transmitted in plaintext.

**Security Test Case:**
1. Use Wireshark to monitor WebSocket traffic.
2. Send a request with `openAiApiKey="test_key"` and check for plaintext exposure.

---

## 4. XSS via Mock Responses (High)
**Vulnerability Name:** Cross-Site Scripting via Mock Responses
**Description:**
Hardcoded mock HTML responses (e.g., `NYTIMES_MOCK_CODE`) in non-production environments may contain unsanitized scripts. If deployed in production with mocks enabled, attackers can inject scripts to steal user data.

**Step-by-Step Exploitation:**
1. Enable mocks in production (`SHOULD_MOCK_AI_RESPONSE=True`).
2. Trigger a mock response containing malicious `<script>` tags.

**Impact:**
- Session hijacking and data theft via injected scripts.

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None.
**Missing Mitigations:**
- Disable mock responses in production.
- Sanitize mock content to remove scripts/html tags.

**Preconditions:**
- Mock responses are enabled in production.

**Source Code Analysis:**
- **File:** `backend/mock_llm.py`
  Mock responses include unsanitized scripts like:
  ```html
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  ```

**Security Test Case:**
1. Enable mocks in production.
2. Use `/generate-code` to retrieve a mock response and verify script execution in the browser.
