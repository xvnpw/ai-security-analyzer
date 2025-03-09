- **Vulnerability Name:** Server‐Side Request Forgery (SSRF) via Configurable API Base URL
  **Description:**
  The backend reads the API base URL for OpenAI (and similarly for other providers) from an environment variable and—which can be overwritten via the front‐end settings dialog—passes it directly into the AI client libraries. An attacker with access to the settings dialog (or who can forge a WebSocket request with custom parameters) could set this URL to point to an internal resource (e.g. an internal IP or service) so that subsequent API calls made by the backend are routed internally.
  **Impact:**
  - Attackers can force the backend to issue requests to internal or restricted services.
  - Disclosure of sensitive internal data or information about internal network structure is possible.
  - The attacker may exploit this to perform further attacks via compromised backends.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The project uses environment variables (via a settings dialog or .env file) for values like `OPENAI_BASE_URL` but no validation is performed on these values.
  **Missing Mitigations:**
  - Input validation and enforcement of a whitelist for allowable API URLs.
  - In production, disallow user‐supplied overrides of critical parameters (or require additional authentication/authorization).
  **Preconditions:**
  - The attacker must have access to set or modify the `OPENAI_BASE_URL` parameter (via the settings dialog or by intercepting WebSocket messages).
  - The backend must be configured to use the user‐supplied API endpoint.
  **Source Code Analysis:**
  - In **backend/config.py**, the code reads:
    ```python
    OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", None)
    ```
    and later in **backend/llm.py** the function `stream_openai_response()` instantiates the AI client with the provided `base_url` without any sanity checks.
  **Security Test Case:**
  1. Use a web client (or WebSocket testing tool) to initiate a connection to the `/generate-code` endpoint.
  2. In the settings dialog input (or directly in the JSON payload), set `OPENAI_BASE_URL` to a URL pointing to an internal service (e.g. `http://127.0.0.1:80/v1`).
  3. Trigger a code-generation request and monitor (or use an internal debugger/log) to verify that the backend attempts to send its API request to the internal URL.
  4. Confirm that the internal endpoint receives the unexpected request.
