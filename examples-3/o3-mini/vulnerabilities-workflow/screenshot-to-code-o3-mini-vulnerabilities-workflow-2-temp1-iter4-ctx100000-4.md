- **Vulnerability Name:** Server‑Side Request Forgery (SSRF) via Custom OpenAI Proxy Configuration

  - **Description:**
    The backend reads the value of the configurable parameter (OPENAI_BASE_URL) from environment variables or allows it to be set via the settings dialog in the frontend. This value is then directly passed to the OpenAI client without any explicit validation or sanitization. An attacker who can supply a malicious URL can force the backend to make unauthorized network requests. Step-by-step exploitation includes:
    1. Accessing the settings dialog (or modifying the deployment's .env file) to change the OPENAI_BASE_URL parameter.
    2. Supplying a malicious URL (for example, `http://192.168.1.100:8000/v1` or another internal/private address).
    3. Triggering a code generation request via the frontend.
    4. The backend instantiates the AsyncOpenAI client with the supplied URL and sends API calls to the attacker‑controlled or internal endpoint.
    5. The attacker can thus access internal services, bypass network restrictions, or exfiltrate sensitive data.

  - **Impact:**
    Successful exploitation of this vulnerability can allow an attacker to:
    - Access internal network endpoints not normally exposed.
    - Retrieve sensitive data from internal services.
    - Utilize the backend as a proxy for internal network reconnaissance or further attacks.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The project documentation (README) provides guidance on configuring the OPENAI_BASE_URL (e.g., including “v1” in the URL), but there are no runtime validation checks.
    - The parameter is directly read from the environment or settings dialog and passed to the backend client without further verification.

  - **Missing Mitigations:**
    - Input validation to ensure the URL is well-formed and points to allowed endpoints.
    - Sanitization to block URLs containing private, loopback, or internal IP addresses.
    - Network egress controls to restrict outbound connections exclusively to legitimate OpenAI API endpoints.

  - **Preconditions:**
    - The attacker must have the ability to supply or modify the OPENAI_BASE_URL parameter via the settings dialog or by tampering with environment variables.
    - The deployment must allow the backend network access to internal or attacker‑controlled resources.

  - **Source Code Analysis:**
    - **In `backend/config.py`:**
      The following code retrieves the base URL without any sanitization:
      ```python
      OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", None)
      ```
    - **In `backend/llm.py`:**
      The function `stream_openai_response` instantiates the AsyncOpenAI client:
      ```python
      client = AsyncOpenAI(api_key=api_key, base_url=base_url)
      ```
      Here, the `base_url` is used directly without checks.
    - **In `backend/routes/generate_code.py`:**
      A helper function retrieves the base URL from either the settings dialog or the environment, again passing the value on without performing any validation.
    - The absence of input validation allows an attacker to set a malicious URL that will be used in API calls, enabling SSRF.

  - **Security Test Case:**
    1. **Prepare a Test Instance:** Deploy the application with the frontend publicly accessible.
    2. **Supply a Malicious URL:**
       - In the frontend settings dialog (or by modifying the backend’s .env file), set the OpenAI base URL to a malicious endpoint (e.g., `http://127.0.0.1:8000/v1`), where the tester controls the server.
    3. **Trigger a Code Generation Request:**
       - Use the application’s interface to initiate a code generation process.
    4. **Monitor Outbound Requests:**
       - Check the attacker-controlled endpoint’s logs to determine if it receives any requests from the backend.
    5. **Confirm Exploitation:**
       - If the backend sends requests to the malicious URL instead of the legitimate OpenAI API endpoint, the SSRF vulnerability is validated.
