- **Vulnerability Name:** SSRF via Misconfigured OPENAI_BASE_URL Parameter
  **Description:**
  An attacker can supply a malicious value for the OpenAI base URL via the settings dialog (or in the environment file) when the application is deployed in non‐production mode. The steps to trigger this vulnerability are:
  1. An external user accesses the frontend’s settings dialog and supplies a value for the openAiBaseURL parameter (for example, “http://127.0.0.1:8080/v1”) that points to an internal or attacker-controlled server.
  2. In the backend’s parameter extraction routine (in the function that calls get_from_settings_dialog_or_env), the provided URL is accepted because the protection is only enabled in production (i.e. when IS_PROD is true).
  3. The value is then passed to the AsyncOpenAI client (in functions such as stream_openai_response and generate_image_dalle) without further validation.
  4. As a result, the backend sends API calls intended for OpenAI to an attacker-controlled or internal address—potentially allowing unauthorized access to internal services.

  **Impact:**
  The attacker may perform a Server-Side Request Forgery (SSRF) attack: by forcing the backend to interact with internal network resources (or an attacker-controlled server) the adversary could retrieve sensitive data from internal systems or manipulate internal communications.

  **Vulnerability Rank:** High

  **Currently Implemented Mitigations:**
  - In production deployments (when the IS_PROD flag is true), user‑supplied overrides for openAiBaseURL are disabled.
  - The system may fall back to a predefined environment variable value if no client input is given.

  **Missing Mitigations:**
  - There is no rigorous validation or whitelisting of the URL on non‑production systems.
  - The application does not enforce restrictions on the scheme (e.g. ensuring HTTPS), domain, or IP address (to block internal/private addresses).
  - No checks are in place to verify the required path component (such as “/v1”) in the URL.

  **Preconditions:**
  - The deployment is running in a non‑production configuration allowing client‑supplied values for openAiBaseURL (i.e. IS_PROD is false).
  - The attacker has access to the frontend settings dialog or the API endpoint that accepts this parameter.

  **Source Code Analysis:**
  - In the file **backend/routes/generate_code.py** (within the `extract_params` function), the code conditionally populates the `openai_base_url` variable by calling `get_from_settings_dialog_or_env` if IS_PROD is false.
  - The obtained base URL is later passed into the AsyncOpenAI client (see **backend/llm.py**, function `stream_openai_response` and in the image generation methods) without any validation against a whitelist or format check. This means an attacker‑controlled URL will be directly used for outbound API calls.

  **Security Test Case:**
  1. Deploy a test instance of the application in non‑production mode (ensure IS_PROD is false).
  2. Connect to the backend’s code‐generation endpoint (for example, via the WebSocket `/generate-code` endpoint).
  3. In the JSON payload, set the property `"openAiBaseURL"` to a malicious URL such as `"http://127.0.0.1:8080/v1"`.
  4. Monitor backend logs or use an intercepting proxy to verify that the backend instantiates the OpenAI client with the supplied URL and makes outbound requests to that address.
  5. Confirm that requests to internal endpoints are triggered as a result of the injected URL.
