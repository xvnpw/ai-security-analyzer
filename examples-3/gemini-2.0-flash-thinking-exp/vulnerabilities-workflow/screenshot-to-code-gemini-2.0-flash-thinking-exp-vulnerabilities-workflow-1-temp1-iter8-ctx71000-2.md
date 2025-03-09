### Vulnerability List

- **Vulnerability Name:** Unprotected Evaluation and Code Generation Endpoints leading to API Key Abuse

- **Description:**
    1. An external attacker accesses the publicly available instance of the application.
    2. The attacker discovers unprotected evaluation and code generation endpoints. These include:
        - REST API endpoint: `/api/run_evals` (POST), as defined in `backend/routes/evals.py`.
        - WebSocket endpoint: `/generate-code`, as defined in `backend/routes/generate_code.py`.
    3. For the REST API endpoint, the attacker crafts a POST request to `/api/run_evals` to trigger evaluation runs, as seen in `backend/routes/evals.py`.
    4. For the WebSocket endpoint, the attacker establishes a WebSocket connection to `/generate-code` and sends a JSON message with parameters to initiate code generation, as seen in `backend/routes/generate_code.py`.
    5. The backend, lacking authentication or authorization on both endpoints, processes these requests.
    6. Both evaluation and code generation processes utilize the application's configured API keys (e.g., OpenAI API key, Anthropic API key, Gemini API key from `backend/config.py`) to interact with external services. Evaluation logic is in `backend/evals/*` and code generation logic is in `backend/llm.py` and `backend/routes/generate_code.py`.
    7. By repeatedly triggering evaluation or code generation runs with various inputs or by exploiting potential weaknesses in the application logic, the attacker can abuse the project's API keys. This leads to unexpected API usage costs and potential exposure of the project's API keys if logging is not properly secured.

- **Impact:**
    - **Financial Impact:** The attacker can cause unexpected and potentially significant financial charges by abusing the project's API keys for AI services (OpenAI, Anthropic, Gemini, Replicate) through both evaluation and code generation functionalities.
    - **Resource Exhaustion:** Repeated requests to evaluation or code generation endpoints initiated by the attacker can consume server resources, impacting the performance and availability of the application for legitimate users.
    - **Potential API Key Leakage:** If the evaluation or code generation processes or logging mechanisms inadvertently expose the API keys, the attacker could potentially extract and misuse these keys for broader malicious activities beyond the project's intended scope.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None apparent from the provided files. The files define evaluation REST API endpoints (`/evals.py`) and a code generation websocket endpoint (`/generate_code.py`) but do not include any mechanisms for access control or authentication to protect these endpoints.

- **Missing Mitigations:**
    - **Authentication and Authorization:** Implement robust authentication to verify user identity before allowing access to the evaluation REST API endpoints (`/api/run_evals`, `/api/evals`, `/api/pairwise-evals`, `/api/best-of-n-evals`) and the code generation WebSocket endpoint (`/generate-code`). Implement authorization to ensure only authorized users (e.g., developers, administrators) can trigger evaluations and code generations.
    - **Rate Limiting:** Implement rate limiting on both the evaluation REST API endpoints and the code generation WebSocket endpoint to restrict the number of requests from a single IP address or user within a given timeframe. This can mitigate abuse by limiting the frequency of malicious requests.
    - **Input Validation and Sanitization:** Thoroughly validate and sanitize inputs to both evaluation REST API endpoints and the code generation WebSocket endpoint to prevent unexpected behavior or potential injection vulnerabilities.
    - **API Key Security:** Ensure API keys are securely managed and not inadvertently logged or exposed during the evaluation or code generation processes. Consider using environment variables (as currently done) but ensure proper access control to the environment where the application runs. Regularly audit and rotate API keys.
    - **Monitoring and Alerting:** Implement monitoring for unusual activity on both the evaluation REST API endpoints and the code generation WebSocket endpoint (e.g., high request rates, unusual input patterns). Set up alerts to notify administrators of potential abuse.

- **Preconditions:**
    - The application must have a publicly accessible instance.
    - Unprotected evaluation REST API endpoints (e.g., `/api/run_evals`) and code generation WebSocket endpoint (`/generate-code`) must be implemented and exposed without authentication or authorization.
    - The evaluation and code generation functionalities must utilize the application's API keys to interact with external AI services.

- **Source Code Analysis:**
    - **`backend/main.py`:** Includes `app.include_router(evals.router)` and `app.include_router(generate_code.router)`, suggesting the existence of evaluation REST API endpoints and code generation websocket endpoint.
    - **`backend/routes/evals.py`:** Defines REST API endpoints under `/api/evals`, including:
        - `/run_evals` (POST): Directly calls `run_image_evals` which uses API keys to perform evaluations. No authentication or authorization is implemented.
    - **`backend/routes/generate_code.py`:** Defines a WebSocket endpoint `/generate-code`:
        - `/generate-code`: Establishes a websocket connection and upon receiving a JSON message, triggers code generation using API keys. No authentication or authorization is implemented for establishing websocket connections or processing messages.
    - **`backend/evals/core.py` and `backend/llm.py`:** Contain functions that use API keys (e.g., `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`) when calling LLM services ( `stream_claude_response`, `stream_gemini_response`, `stream_openai_response`).
    - **`backend/config.py`:** API keys are loaded from environment variables, which is a good practice for configuration, but doesn't inherently prevent abuse if the endpoints using these keys are unprotected.
    - **Absence of Authentication/Authorization Code:** None of the provided files contain explicit code implementing authentication or authorization for the evaluation REST API endpoints or the code generation websocket endpoint, or for the application in general.

- **Security Test Case:**
    1. Deploy the `screenshot-to-code` application in a publicly accessible environment.
    2. **Test for REST API Endpoint (/api/run_evals):**
        - Identify the evaluation REST API endpoint URL (e.g., `http://<public-ip>:5173/api/run_evals`).
        - Using a tool like `curl` or `Postman`, send a POST request to `/api/run_evals` endpoint with a JSON body like `{"models":["gpt-4o"], "stack":"react"}`.
        - Monitor the API usage dashboards for the configured AI services (OpenAI, Anthropic, Gemini, Replicate) associated with the project's API keys. Observe if the API usage increases significantly after sending the evaluation request.
        - Repeat the request multiple times, potentially with varying inputs or in rapid succession. Observe if API usage continues to increase, indicating successful triggering of evaluations by the attacker.
    3. **Test for WebSocket Endpoint (/generate-code):**
        - Establish a WebSocket connection to the `/generate-code` endpoint (e.g., using a WebSocket client or browser's developer console). The WebSocket URL would be something like `ws://<public-ip>:5173/generate-code`.
        - Send a JSON message through the WebSocket connection to trigger code generation. A sample message could be: `{"inputMode": "screenshot", "screenshot": "data:image/png;base64,...", "generatedCodeConfig": "react", "isImageGenerationEnabled": false}`.
        - Monitor the API usage dashboards for the configured AI services. Observe if the API usage increases after sending the code generation request via WebSocket.
        - Send multiple code generation requests in rapid succession through the WebSocket connection. Observe if API usage continues to increase, indicating successful abuse of the code generation functionality.
    4. If API usage increases without legitimate user activity on the application for both REST API and WebSocket tests, it confirms that these endpoints are unprotected and can be abused to consume project's API resources.
