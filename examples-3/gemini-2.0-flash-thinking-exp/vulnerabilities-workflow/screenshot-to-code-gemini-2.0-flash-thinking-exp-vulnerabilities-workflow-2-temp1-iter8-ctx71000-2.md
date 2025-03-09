- Vulnerability name: Insecure API Key Usage
- Description:
    1. The application is designed to use API keys from OpenAI, Anthropic, or Gemini to access AI models.
    2. Users are instructed to provide their API keys, which are then stored either in environment variables or in the browser's local storage via the settings dialog.
    3. The backend code directly utilizes these API keys to authenticate requests to the AI model providers when processing user requests (e.g., converting screenshots to code).
    4. If an instance of this application is deployed publicly without any form of authentication or access control, an attacker can access the application's frontend.
    5. The attacker can then use the application's features, such as uploading screenshots or videos and requesting code generation.
    6. These actions trigger backend requests to the configured AI models, authenticated with the legitimate user's API keys.
    7. As a result, the attacker can effectively use the application as an API proxy, incurring costs and potentially exceeding API usage limits for the legitimate user.
- Impact:
    - Unauthorized usage of the application's functionality.
    - Financial cost to the legitimate user due to unintended API consumption by the attacker.
    - Potential exhaustion of the user's API quota or rate limits.
    - Disclosure of application functionality and potential abuse of AI models for malicious purposes if combined with further vulnerabilities (though not directly part of this vulnerability itself).
- Vulnerability rank: High
- Currently implemented mitigations:
    - None in the provided code. The application is designed to be standalone and does not include built-in authentication or access control mechanisms. The `README.md` mentions a hosted (paid) version, which likely has mitigations, but they are not present in the open-source project.
- Missing mitigations:
    - **Authentication and Authorization**: Implement user authentication to verify the identity of users accessing the application. Authorization mechanisms should control access to sensitive functionalities.
    - **API Key Management**: Securely manage API keys.  Avoid storing API keys directly in environment variables if the deployment context is not secure. Consider using more robust secret management solutions or backend-for-frontend architecture where keys are securely managed on the server-side and not exposed to the client.
    - **Rate Limiting**: Implement rate limiting to restrict the number of requests from a single user or IP address within a specific timeframe. This can help mitigate abuse by attackers.
    - **Input Validation and Sanitization**: While not directly mitigating API key exposure, validating and sanitizing user inputs (like uploaded images or videos) can prevent other potential issues arising from malicious inputs.
- Preconditions:
    - The application must be deployed and accessible over a network (e.g., publicly accessible internet or a local network reachable by the attacker).
    - The user deploying the application must have configured valid API keys for at least one of the supported AI models (OpenAI, Anthropic, or Gemini).
    - No authentication or access control mechanism is implemented or enabled on the deployed instance of the application.
- Source code analysis:
    - **`backend/config.py`**: API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) are loaded directly from environment variables using `os.environ.get()`.
    ```python
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", None)
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", None)
    ```
    - **`backend/generate_code.py`**: The `stream_code` WebSocket endpoint handles the code generation process. It extracts API keys using the `get_from_settings_dialog_or_env` function, which checks both the settings dialog parameters (from frontend, likely local storage) and environment variables.
    ```python
    openai_api_key = get_from_settings_dialog_or_env(
        params, "openAiApiKey", OPENAI_API_KEY
    )

    anthropic_api_key = get_from_settings_dialog_or_env(
        params, "anthropicApiKey", ANTHROPIC_API_KEY
    )
    ```
    - **`backend/generate_code.py`**: Inside the `stream_code` function, based on the user's input mode and available API keys, the application calls different LLM streaming functions (`stream_openai_response`, `stream_claude_response`, `stream_gemini_response`) which require API keys. For example, when using OpenAI models:
    ```python
    tasks.append(
        stream_openai_response(
            prompt_messages,
            api_key=openai_api_key, # API key is passed here
            base_url=openai_base_url,
            callback=lambda x, i=index: process_chunk(x, i),
            model=model,
        )
    )
    ```
    - **`backend/llm.py`**: Functions like `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` (as previously analyzed) take API keys as parameters and use them to initialize the respective API clients, directly using the potentially exposed API keys for each request to the LLM providers.
    - **`backend/evals/core.py`**: The `generate_code_core` function, used for evaluation and code generation, also directly utilizes these API keys (as previously analyzed).
    - **`backend/main.py`**: The FastAPI application does not implement any authentication or authorization middleware by default. The CORS middleware (`CORSMiddleware`) with `allow_origins=["*"]` further suggests an open access configuration by default.
- Security test case:
    1. Deploy the `screenshot-to-code` application as per the instructions in `README.md`, ensuring it is publicly accessible (e.g., using `docker-compose up -d --build` on a cloud instance without further network restrictions). Configure API keys in the `.env` file.
    2. As an attacker, access the publicly deployed frontend of the application through a web browser (e.g., `http://<deployed-instance-ip>:5173`).
    3. Upload a sample screenshot of a UI design using the application's interface.
    4. Select a stack (e.g., HTML + Tailwind) and initiate the code generation process.
    5. Observe that the application successfully generates code, indicating that it has successfully used the configured API key to access the chosen AI model.
    6. To further confirm unauthorized API key usage, monitor the API usage dashboard for the configured API key (e.g., on the OpenAI platform). Increased usage corresponding to the attacker's actions will validate the vulnerability. Alternatively, if the API provider allows, set up billing alerts and observe if usage charges are incurred due to actions performed by the attacker through the publicly accessible instance.
    7. Repeat steps 3-6 multiple times with different screenshots and stacks to simulate sustained unauthorized usage.
    8. If rate limiting is not implemented by the AI provider and the application, the attacker can continue to generate code, continuously consuming the legitimate user's API credits without any restrictions.
