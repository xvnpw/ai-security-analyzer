- Vulnerability Name: **Sensitive Data Exposure via Third-Party AI Services**
- Description:
    1. A user uploads a visual input, which can be a screenshot or a video, containing sensitive information (e.g., API keys, passwords, personal data, internal application details) to the application.
    2. The application, as designed, sends this visual input (screenshot or frames extracted from video) to a third-party AI service (like OpenAI, Anthropic, or Google Gemini) for processing to generate code. For video inputs, the application first splits the video into multiple screenshots (frames) before sending them to the AI service.
    3. The communication channel between the application and the third-party AI service, or the data storage at the AI service provider's end, could be compromised by an attacker.
    4. If compromised, the attacker could intercept the visual input data in transit or access stored data at the AI service provider, thereby gaining unauthorized access to the sensitive information contained within the user's uploaded content.
- Impact:
    - **Confidentiality Breach:** Sensitive information from user screenshots or video frames, such as API keys, passwords, or personal data, could be exposed to unauthorized parties.
    - **Data Leakage:**  Internal application details or proprietary information visible in visual inputs could be leaked, potentially aiding further attacks or harming the user or organization.
    - **Reputational Damage:** If user data is exposed through the application, it could severely damage the reputation and trustworthiness of the application and its developers.
    - **Compliance Violations:** Exposure of personal data could lead to violations of data protection regulations like GDPR, CCPA, etc., resulting in legal and financial repercussions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - **No Server-Side Storage of API Keys:** The `README.md` mentions, "Your key is only stored in your browser. Never stored on our servers." This mitigates the risk of server-side API key compromise for the application itself, but doesn't address the risk during transit to or storage at third-party AI services.
    - **Placeholder Images:** The application uses placeholder images initially and can generate images later using AI. This might reduce the initial amount of sensitive visual data processed if image generation is deferred, but screenshots and video frames themselves are still processed by AI.
- Missing Mitigations:
    - **Data Sanitization:** Implement mechanisms to detect and remove sensitive information from visual inputs (screenshots and video frames) before sending them to third-party AI services. This could include techniques like Optical Character Recognition (OCR) to identify text and then redact or mask potentially sensitive patterns (e.g., API key formats, password patterns). For video inputs, sanitization should be applied to each extracted frame.
    - **End-to-End Encryption:** Ensure that the communication channel between the application and the third-party AI services is end-to-end encrypted to protect data in transit. While HTTPS is used, it only encrypts communication to the service endpoint, not necessarily end-to-end to prevent interception at the AI provider or during internal processing.
    - **Data Processing Agreements and Security Audits of AI Providers:**  Establish clear data processing agreements with third-party AI service providers that outline their security measures, data handling policies, and compliance certifications. Regularly audit or request security audit reports from these providers to ensure they meet acceptable security standards.
    - **User Awareness and Consent:**  Clearly inform users about the data privacy implications of uploading visual inputs, specifically mentioning that these inputs will be processed by third-party AI services. Obtain explicit consent and provide users with control over what type of data they upload.
    - **Minimize Data Sent:**  Explore techniques to minimize the amount of data sent to AI services. For example, instead of sending the entire screenshot or video frame, could the application pre-process the image to extract only UI element structures or features needed for code generation, discarding potentially sensitive visual content?
    - **Consider Self-Hosted or Privacy-Focused AI Models:** For users with high sensitivity requirements, offer options to use self-hosted AI models or privacy-focused AI services that provide stronger data protection guarantees and control over data processing.
- Preconditions:
    - User must upload a screenshot or a video that contains sensitive information.
    - The application must be configured to use a third-party AI service (OpenAI, Anthropic, Google Gemini, Replicate).
    - An attacker must be able to compromise the communication channel or data storage of the chosen third-party AI service.
- Source Code Analysis:
    - **`backend/llm.py`:** This file contains the core logic for interacting with different LLM APIs (OpenAI, Anthropic, Gemini). Functions like `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` are responsible for sending requests to these services. These functions take `messages` as input, which includes image data.
    ```python
    from openai import AsyncOpenAI
    from anthropic import AsyncAnthropic
    from google import genai

    async def stream_openai_response(
        messages: List[ChatCompletionMessageParam],
        api_key: str, # API key passed as argument
        base_url: str | None,
        callback: Callable[[str], Awaitable[None]],
        model: Llm,
    ) -> Completion:
        client = AsyncOpenAI(api_key=api_key, base_url=base_url) # API key is used to initialize the client
        # ... sends messages to OpenAI API ...

    async def stream_claude_response( # Similar structure for Claude and Gemini
        messages: List[ChatCompletionMessageParam],
        api_key: str, # API key passed as argument
        callback: Callable[[str], Awaitable[None]],
        model: Llm,
    ) -> Completion:
        client = AsyncAnthropic(api_key=api_key) # API key is used to initialize the client
        # ... sends messages to Anthropic API ...

    async def stream_gemini_response(
        messages: List[ChatCompletionMessageParam],
        api_key: str, # API key passed as argument
        callback: Callable[[str], Awaitable[None]],
        model: Llm,
    ) -> Completion:
        client = genai.Client(api_key=api_key) # API key is used to initialize the client
        # ... sends messages to Gemini API ...
    ```
    - The `messages` parameter in these functions, built in `evals/core.py` and `prompts/__init__.py`, includes the `image_url` which contains the base64 encoded screenshot data. This data is directly sent to the third-party AI services.
    - **`backend/prompts/__init__.py`:** This file is responsible for assembling the prompt messages that are sent to the LLMs. The `assemble_prompt` function constructs the message payload, including the `image_url` with the screenshot data.
    ```python
    # backend/prompts/__init__.py
    def assemble_prompt(
        image_data_url: str,
        stack: Stack,
        result_image_data_url: Union[str, None] = None,
    ) -> list[ChatCompletionMessageParam]:
        # ...
        user_content: list[ChatCompletionContentPartParam] = [
            {
                "type": "image_url",
                "image_url": {"url": image_data_url, "detail": "high"}, # Screenshot data URL is included here
            },
            # ...
        ]
        # ...
        return [
            # ...
            {
                "role": "user",
                "content": user_content, # User content with image_url is part of the message
            },
        ]
    ```
    - **`backend/routes/generate_code.py`:** This file handles the websocket endpoint `/generate-code` which is used to stream code generation. The `stream_code` function extracts parameters, assembles prompts using `create_prompt`, and then calls the appropriate `stream_*_response` function from `llm.py` to interact with the chosen LLM. This confirms that user inputs (screenshots or video frames) are processed and sent to third-party LLMs via these streaming functions. The code iterates through `NUM_VARIANTS` to generate multiple code variants, potentially using different models.
    - **`backend/video/utils.py`:** This file contains functions to handle video inputs. The `split_video_into_screenshots` function decodes a base64 encoded video data URL, splits the video into frames, and returns a list of PIL images representing these frames. The `assemble_claude_prompt_video` function takes a video data URL, extracts frames using `split_video_into_screenshots`, and formats these frames into a list of messages suitable for the Claude API, encoding each frame as a base64 image within the message content. This demonstrates that video inputs are processed by splitting them into screenshots and then sending these screenshots to the AI service, similar to how static screenshots are handled.
    - **Data Flow Visualization:**
        ```mermaid
        graph LR
            A[User Uploads Screenshot/Video] --> B(Frontend);
            B --> C{Backend API Route (/generate-code)};
            C --> D[Assemble Prompt (prompts/__init__.py or video/utils.py)];
            D --> E[Include Visual Input Data (image_data_url or video frames)];
            E --> F(llm.py - stream_openai_response/stream_claude_response/stream_gemini_response);
            F --> G[Third-Party AI Service (OpenAI/Anthropic/Gemini)];
            G --> H[Potential Compromise (Transit/Storage)];
            H --> I[Sensitive Data Exposure];
        ```
    - The code analysis, particularly in `backend/routes/generate_code.py` and `backend/video/utils.py`, reinforces that user-uploaded visual inputs, including both screenshots and videos which are converted to frames, potentially containing sensitive data, are packaged into messages and sent to third-party AI services for processing. There's no explicit data sanitization or end-to-end encryption implemented in the provided code to protect this data during transmission or at rest on the AI provider's side.

- Security Test Case:
    1. **Precondition:** Ensure you have an OpenAI API key set up and the application is configured to use OpenAI (or another supported AI service).
    2. **Prepare a Malicious Screenshot:** Create a screenshot file (e.g., `sensitive_screenshot.png`) that intentionally includes a simulated sensitive API key or password clearly visible in the image. For example, embed the text "TEST_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" within the screenshot image.
    3. **Upload the Screenshot:** Using the application's frontend, upload the `sensitive_screenshot.png` as the input image for code generation.
    4. **Intercept Network Traffic (Optional but Recommended):** Use a network interception proxy tool (like Burp Suite or Wireshark) to monitor the network requests sent by the application.
    5. **Analyze Outgoing Request:** Inspect the network traffic for the request sent to the third-party AI service API endpoint (e.g., OpenAI's `/v1/chat/completions`). Look for the request body and confirm that the base64 encoded image data is included in the `messages` payload.
    6. **Simulate AI Service Compromise (Conceptual):** In a real-world scenario, this step would involve compromising the AI service provider's infrastructure or communication channel, which is beyond the scope of a typical test case and likely illegal.  For the purpose of this test, assume a hypothetical compromise.
    7. **Verify Data Exposure (Manual Review and Logs):** If you had access to the hypothetical compromised AI service logs or intercepted data, you would search for your uploaded screenshot data. You should be able to find the base64 encoded image data and decode it to retrieve the original `sensitive_screenshot.png`, including the embedded simulated API key "TEST_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".
    8. **Expected Outcome:** The test will demonstrate that user-uploaded screenshot data, including sensitive information embedded within it, is transmitted to and processed by the third-party AI service without any implemented data sanitization or end-to-end encryption, confirming the vulnerability of Sensitive Data Exposure via Third-Party AI Services.
