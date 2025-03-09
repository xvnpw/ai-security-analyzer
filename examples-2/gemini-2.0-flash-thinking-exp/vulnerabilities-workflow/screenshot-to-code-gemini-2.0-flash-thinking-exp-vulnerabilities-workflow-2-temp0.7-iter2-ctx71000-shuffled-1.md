- Vulnerability Name: **Unprotected API Key Usage leading to potential API abuse**
- Description:
    1. The application allows users to provide their OpenAI or Anthropic API keys through the frontend settings dialog or environment variables.
    2. When a user sends a request to generate code (e.g., by uploading a screenshot), the backend directly uses these API keys to make requests to the respective AI model providers (OpenAI, Anthropic, Gemini, Replicate).
    3. There is no authentication or authorization mechanism in place to verify if the user making the request is the legitimate owner of the provided API key.
    4. An attacker can access the publicly available instance of the application and use it to send code generation requests, utilizing the API keys configured by another legitimate user.
    5. This can lead to the attacker consuming the legitimate user's API credits, potentially incurring significant costs on their accounts without their consent or knowledge.
- Impact:
    - Financial loss for legitimate users due to unauthorized consumption of their API credits.
    - Potential depletion of API quotas, disrupting service for legitimate users.
    - Risk of exposure and misuse of user's API keys if intercepted or logged improperly, although the project claims keys are only stored in the browser.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The application mentions in `README.md` and `Troubleshooting.md` that API keys are stored only in the user's browser (frontend settings dialog) or environment variables (backend `.env`). This client-side storage for browser keys is a form of mitigation against server-side key exposure, but does not prevent abuse via the application itself.
    - The `IS_PROD` flag in `config.py` disables user-specified OpenAI Base URL in production, which is a minor mitigation against potential redirection attacks, but not directly related to API key abuse.
- Missing Mitigations:
    - **Authentication and Authorization**: Implement a user authentication system to identify and verify users. Introduce authorization checks to ensure only authenticated users can initiate code generation requests using their own API keys.
    - **API Key Management**: Securely manage API keys, ideally server-side and associated with user accounts. Avoid directly using user-provided keys for backend calls. Consider using a proxy service or backend managed keys.
    - **Rate Limiting**: Implement rate limiting on the backend API endpoints to restrict the number of requests from a single user or IP address within a given time frame. This can help prevent abuse and excessive API consumption.
    - **Usage Monitoring and Quotas**: Implement monitoring of API usage per user account and set up configurable quotas to limit spending and prevent unexpected charges.
- Preconditions:
    - A legitimate user has configured their OpenAI or Anthropic API key within the application (either through the frontend settings dialog or backend environment variables if self-hosting).
    - The application instance is publicly accessible.
    - The attacker has access to the publicly accessible application instance.
- Source Code Analysis:
    - **`backend/routes/generate_code.py`**:
        - The `stream_code` function in `generate_code.py` handles the websocket connection for code generation.
        - `extract_params` function retrieves API keys from the request parameters (`params.get("openAiApiKey")`, `params.get("anthropicApiKey")`) and environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
        - The extracted API keys are directly passed to `stream_openai_response` and `stream_claude_response` functions in `llm.py`.
        - There are no checks to verify the ownership or validity of the provided API keys beyond basic presence checks (e.g., `if not OPENAI_API_KEY:`).
        - No authentication or authorization is performed to restrict access to the code generation functionality.
    - **`backend/llm.py`**:
        - `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` functions directly use the provided `api_key` parameter when making calls to the AI model providers.
        - No validation or security checks are performed on the API keys within these functions.
    - **`backend/config.py`**:
        - `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `REPLICATE_API_KEY` are loaded from environment variables, but these are directly used without further protection in `generate_code.py`.
    - **`backend/video_to_app.py`**:
        - This file shows another example of direct API key usage. In `video_to_app.py`, the `ANTHROPIC_API_KEY` (loaded from environment variables via `config.py`) is directly passed to `stream_claude_response_native` function:
        ```python
        completion = await stream_claude_response_native(
            system_prompt=VIDEO_PROMPT,
            messages=prompt_messages,
            api_key=ANTHROPIC_API_KEY, # <--- Direct API key usage
            callback=lambda x: process_chunk(x),
            model=Llm.CLAUDE_3_OPUS,
            include_thinking=True,
        )
        ```
        - This confirms that API keys are directly used throughout the backend when interacting with different LLM providers.

    ```python
    # backend/routes/generate_code.py - Snippet showing API key usage

    async def extract_params(
        params: Dict[str, str], throw_error: Callable[[str], Coroutine[Any, Any, None]]
    ) -> ExtractedParams:
        # ...
        openai_api_key = get_from_settings_dialog_or_env(
            params, "openAiApiKey", OPENAI_API_KEY
        )
        anthropic_api_key = get_from_settings_dialog_or_env(
            params, "anthropicApiKey", ANTHROPIC_API_KEY
        )
        # ...
        return ExtractedParams(..., openai_api_key=openai_api_key, anthropic_api_key=anthropic_api_key, ...)

    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        # ...
        extracted_params = await extract_params(params, throw_error)
        openai_api_key = extracted_params.openai_api_key
        anthropic_api_key = extracted_params.anthropic_api_key
        # ...
        if SHOULD_MOCK_AI_RESPONSE:
            # ...
        else:
            # ...
            tasks: List[Coroutine[Any, Any, Completion]] = []
            for index, model in enumerate(variant_models):
                if model == Llm.GPT_4O_2024_11_20 or model == Llm.O1_2024_12_17:
                    tasks.append(
                        stream_openai_response(
                            prompt_messages,
                            api_key=openai_api_key, # <--- Direct API key usage
                            base_url=openai_base_url,
                            callback=lambda x, i=index: process_chunk(x, i),
                            model=model,
                        )
                    )
                elif (
                    model == Llm.CLAUDE_3_5_SONNET_2024_06_20
                    or model == Llm.CLAUDE_3_5_SONNET_2024_10_22
                    or model == Llm.CLAUDE_3_7_SONNET_2025_02_19
                ):
                    tasks.append(
                        stream_claude_response(
                            prompt_messages,
                            api_key=anthropic_api_key, # <--- Direct API key usage
                            callback=lambda x, i=index: process_chunk(x, i),
                            model=claude_model,
                        )
                    )
            # ...
    ```

- Security Test Case:
    1. **Precondition:** Ensure a legitimate user has configured their OpenAI API key in the application's frontend settings dialog.
    2. **Attacker Action:** As an attacker, open a browser and navigate to the publicly accessible instance of the "screenshot-to-code" application.
    3. **Attacker Action:** Upload a screenshot or provide any input that triggers the code generation process. Do not configure any API keys in *your* browser's settings dialog.
    4. **Expected Outcome:** The application should successfully generate code using the API key configured by the legitimate user.
    5. **Verification:** Check the legitimate user's OpenAI API usage dashboard. There should be API calls logged corresponding to the attacker's code generation request, indicating that the attacker has successfully used the legitimate user's API key.
    6. **Further Verification (Optional):** Monitor the API cost incurred by the legitimate user. Repeated attacks will increase the API costs on the legitimate user's account.

This vulnerability allows an attacker to leverage the resources (API keys) of legitimate users without any authentication or authorization, leading to potential financial and service disruption impacts.
