## Combined Vulnerability List

This document outlines the identified vulnerabilities, combining information from provided lists and removing duplicates.

### Unprotected API Key Usage leading to potential API abuse

- **Description:**
    1. The application allows users to provide their OpenAI or Anthropic API keys through the frontend settings dialog or environment variables.
    2. When a user sends a request to generate code (e.g., by uploading a screenshot), the backend directly uses these API keys to make requests to the respective AI model providers (OpenAI, Anthropic, Gemini, Replicate).
    3. There is no authentication or authorization mechanism in place to verify if the user making the request is the legitimate owner of the provided API key.
    4. An attacker can access the publicly available instance of the application and use it to send code generation requests, utilizing the API keys configured by another legitimate user.
    5. This can lead to the attacker consuming the legitimate user's API credits, potentially incurring significant costs on their accounts without their consent or knowledge.

- **Impact:**
    - Financial loss for legitimate users due to unauthorized consumption of their API credits.
    - Potential depletion of API quotas, disrupting service for legitimate users.
    - Risk of exposure and misuse of user's API keys if intercepted or logged improperly, although the project claims keys are only stored in the browser.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The application mentions in `README.md` and `Troubleshooting.md` that API keys are stored only in the user's browser (frontend settings dialog) or environment variables (backend `.env`). This client-side storage for browser keys is a form of mitigation against server-side key exposure, but does not prevent abuse via the application itself.
    - The `IS_PROD` flag in `config.py` disables user-specified OpenAI Base URL in production, which is a minor mitigation against potential redirection attacks, but not directly related to API key abuse.

- **Missing Mitigations:**
    - **Authentication and Authorization**: Implement a user authentication system to identify and verify users. Introduce authorization checks to ensure only authenticated users can initiate code generation requests using their own API keys.
    - **API Key Management**: Securely manage API keys, ideally server-side and associated with user accounts. Avoid directly using user-provided keys for backend calls. Consider using a proxy service or backend managed keys.
    - **Rate Limiting**: Implement rate limiting on the backend API endpoints to restrict the number of requests from a single user or IP address within a given time frame. This can help prevent abuse and excessive API consumption.
    - **Usage Monitoring and Quotas**: Implement monitoring of API usage per user account and set up configurable quotas to limit spending and prevent unexpected charges.

- **Preconditions:**
    - A legitimate user has configured their OpenAI or Anthropic API key within the application (either through the frontend settings dialog or backend environment variables if self-hosting).
    - The application instance is publicly accessible.
    - The attacker has access to the publicly accessible application instance.

- **Source Code Analysis:**
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
        - In `video_to_app.py`, the `ANTHROPIC_API_KEY` is directly passed to `stream_claude_response_native` function.

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

- **Security Test Case:**
    1. **Precondition:** Ensure a legitimate user has configured their OpenAI API key in the application's frontend settings dialog.
    2. **Attacker Action:** As an attacker, open a browser and navigate to the publicly accessible instance of the "screenshot-to-code" application.
    3. **Attacker Action:** Upload a screenshot or provide any input that triggers the code generation process. Do not configure any API keys in *your* browser's settings dialog.
    4. **Expected Outcome:** The application should successfully generate code using the API key configured by the legitimate user.
    5. **Verification:** Check the legitimate user's OpenAI API usage dashboard. There should be API calls logged corresponding to the attacker's code generation request, indicating that the attacker has successfully used the legitimate user's API key.
    6. **Further Verification (Optional):** Monitor the API cost incurred by the legitimate user. Repeated attacks will increase the API costs on the legitimate user's account.

---

### Image Processing Vulnerability via Malicious Image Payload

- **Description:** An attacker can upload a specially crafted image file via the application's frontend. This image is then processed by the backend using the Pillow (PIL) library in the `process_image` function located in `backend/image_processing/utils.py`. If the uploaded image exploits a known or unknown vulnerability in the Pillow library, it could lead to various security impacts.  Specifically, a malicious image could trigger arbitrary code execution on the backend server, cause a denial of service, or lead to information disclosure. The vulnerability is triggered when the backend attempts to parse and process the malicious image using `Image.open()`.

- **Impact:** The impact of this vulnerability is highly dependent on the specific vulnerability within the Pillow library that is exploited. In a worst-case scenario, successful exploitation could lead to Remote Code Execution (RCE) on the backend server, allowing the attacker to gain complete control of the server and potentially access sensitive data, modify system configurations, or use the server for further malicious activities. Even in less severe scenarios, a successful exploit could still result in a denial-of-service (DoS) if the image processing causes the backend application to crash or become unresponsive, or information disclosure if the vulnerability allows reading sensitive files or memory.

- **Vulnerability Rank:** High to Critical

- **Currently Implemented Mitigations:** The `process_image` function in `backend/image_processing/utils.py` includes image resizing and compression to meet Claude API requirements. It checks for image dimensions and size limits before processing. While these checks might reduce the likelihood of some types of DoS attacks related to excessively large images, they do not specifically mitigate against vulnerabilities within the image processing library itself when handling maliciously crafted image payloads. There are no explicit input validation checks to sanitize or validate the image file format or content before it's processed by Pillow.

- **Missing Mitigations:**
    - **Input validation:** Implement checks to validate the image file format and content before processing it with Pillow. This could include verifying the image header, using safer image processing techniques, or employing a dedicated image sanitization library.
    - **Library Updates:** Regularly update the Pillow library to the latest version to ensure that known vulnerabilities are patched promptly. Dependency management tools and processes should be in place to automate and track library updates.
    - **Sandboxing:** Consider sandboxing the image processing operations. Running the image processing in a restricted environment can limit the impact of a successful exploit by preventing the attacker from gaining full access to the backend system, even if they manage to execute code through a Pillow vulnerability.

- **Preconditions:**
    - The application must be running and accessible to external users.
    - An attacker needs to be able to access the web application and use the image upload functionality, which is a standard feature of the application.

- **Source Code Analysis:**
    - The vulnerability is located in the `process_image` function within `backend/image_processing/utils.py`:
        ```python
        import base64
        import io
        from PIL import Image

        def process_image(image_data_url: str) -> tuple[str, str]:
            # ...
            base64_data = image_data_url.split(",")[1]
            image_bytes = base64.b64decode(base64_data)
            img = Image.open(io.BytesIO(image_bytes)) # Vulnerable line
            # ... rest of image processing ...
        ```
        - Step 1: The `process_image` function is called when the backend receives an image data URL, typically from user input via the frontend.
        - Step 2: The function extracts the base64 encoded image data from the `image_data_url`.
        - Step 3: `base64.b64decode(base64_data)` decodes the base64 string back into bytes, representing the image data.
        - Step 4: `Image.open(io.BytesIO(image_bytes))` uses the Pillow library to open and parse the image from the byte data. This is where a maliciously crafted image can exploit vulnerabilities within Pillow. Pillow attempts to automatically determine the image format and parse it, and vulnerabilities in format parsing (e.g., PNG, JPEG, etc.) can be triggered at this stage.
        - Step 5: If a malicious image is successfully processed and exploits a vulnerability, it can lead to unintended behavior, such as code execution.

- **Security Test Case:**
    1. Setup: Have a running instance of the `screenshot-to-code` application. Prepare a malicious image file specifically crafted to exploit a known vulnerability in the Pillow library.
    2. Base64 Encode: Encode the malicious image file into a base64 data URL.
    3. Capture Request: Using the frontend of the `screenshot-to-code` application, initiate the process of converting a screenshot to code. Inject the base64 data URL of the malicious image.
    4. Send Request: Send the modified request to the backend server. This will trigger the backend to process the malicious image data.
    5. Monitor Backend: Monitor the backend server's behavior. Check for error logs, application crashes, or any signs of unexpected system behavior.
    6. Verify Exploitation: If the backend server exhibits unexpected behavior (crashes, errors, becomes unresponsive) or if you can confirm code execution, then the vulnerability is confirmed.
