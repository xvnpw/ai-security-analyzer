### Vulnerability List:

- **Vulnerability Name:**  Prompt Injection via Malicious Screenshot/Mockup/Video Frame

- **Description:**
    1. An attacker crafts a manipulated screenshot, design mockup, or video frame.
    2. This manipulated image or video frame contains text or visual elements that are designed to be interpreted by the AI model as instructions rather than as part of the intended UI design.
    3. The user uploads this malicious image, mockup, or video to the application. For video uploads, the application automatically splits the video into frames and processes them as individual images.
    4. The backend processes the image data (or video frames) and uses it as input to the AI model, constructing a prompt that includes the content of the image/frames.
    5. The AI model, interpreting the malicious instructions within the image/frames as part of the design requirements, generates code that incorporates these instructions. This can result in the generation of unintended, vulnerable, or malicious code (e.g., including JavaScript for XSS, embedding links to phishing sites, or altering the intended application logic).
    6. The application returns this generated code to the user.
    7. The user, unaware of the malicious code injected via prompt injection, may use or deploy this code, thereby unknowingly introducing vulnerabilities into their application or website.

- **Impact:**
    - **Cross-Site Scripting (XSS):** An attacker can inject JavaScript code into the generated output. If a user deploys this code, the injected script will execute in the user's browser when the page is accessed. This could lead to:
        - Stealing user session cookies, allowing for session hijacking.
        - Redirecting users to malicious websites.
        - Displaying misleading content or defacing the website.
        - Performing actions on behalf of the user without their consent.
    - **Open Redirect:**  An attacker could inject HTML or JavaScript that redirects users to an external malicious website, potentially for phishing or malware distribution.
    - **Client-Side Code Manipulation:** The attacker might be able to subtly alter the intended functionality of the generated code, leading to unexpected behavior or security flaws in the user's application.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - There are no explicit mitigations visible in the provided project files to prevent prompt injection vulnerabilities. The application directly takes user-provided screenshots, mockups, or video frames and uses them as input for the AI model without any apparent sanitization or security measures. The code generation process relies entirely on the AI model's interpretation of the input.

- **Missing Mitigations:**
    - **Input Sanitization/Validation:** Implement robust input sanitization and validation on the uploaded screenshot/mockup/video frames. This could involve:
        - Analyzing the image/frame content for potentially malicious patterns or keywords before sending it to the AI model.
        - Using Optical Character Recognition (OCR) to extract text from the image/frames and then applying sanitization rules to the extracted text before including it in the prompt.
        - Employing image/video analysis techniques to detect anomalies or suspicious elements within the input.
    - **Prompt Engineering for Security:** Refine the prompts sent to the AI model to minimize the risk of prompt injection. This could involve:
        - Clearly separating user-provided image/frame content from the system instructions within the prompt.
        - Using delimiters or formatting to explicitly define the boundaries of the image/frame-derived content.
        - Instructing the AI model to strictly adhere to generating code based on the *design* of the screenshot/mockup/video frame and to ignore any text-based instructions that might be embedded within the input itself.
    - **Output Sanitization:** Implement sanitization of the generated code before presenting it to the user. This could involve:
        - Parsing the generated HTML, CSS, and JavaScript code to identify and remove potentially malicious or unintended code snippets (e.g., `<script>` tags, `javascript:` URLs, event handlers that execute external code).
        - Using a Content Security Policy (CSP) meta tag in the generated HTML to restrict the capabilities of the generated web page, such as limiting the sources from which scripts can be loaded or preventing inline JavaScript execution.
        - Employing static code analysis tools to scan the generated code for known vulnerability patterns.
    - **User Awareness and Education:**  Educate users about the risks of prompt injection and advise them to:
        - Carefully review the generated code before using it.
        - Be cautious about uploading screenshots, mockups, or videos from untrusted sources.
        - Understand that the generated code is based on AI interpretation and may contain unintended or insecure elements.

- **Preconditions:**
    - The attacker needs to be able to create a manipulated screenshot, design mockup, or video. This is a relatively low precondition as image and video editing tools are widely available.
    - The user must upload this malicious input to the publicly accessible instance of the screenshot-to-code application.
    - The user must then utilize or deploy the generated code without carefully reviewing it.

- **Source Code Analysis:**
    1. **`backend/routes/generate_code.py` (WebSocket Entry Point):** This file handles the `/generate-code` websocket endpoint, which is the primary entry point for code generation requests.
        ```python
        @router.websocket("/generate-code")
        async def stream_code(websocket: WebSocket):
            await websocket.accept()
            params: dict[str, str] = await websocket.receive_json() # [USER INPUT] Receives parameters including image data
            extracted_params = await extract_params(params, throw_error)
            stack = extracted_params.stack
            input_mode = extracted_params.input_mode
            # ...
            prompt_messages, image_cache = await create_prompt(params, stack, input_mode) # [PROMPT CREATION] Calls create_prompt
            # ...
            # LLM interaction using stream_openai_response, stream_claude_response, etc.
        ```
        - The `stream_code` function in `generate_code.py` is the starting point. It receives user input via a websocket connection in the form of a JSON payload (`params`). This payload includes the image data (or video data) and other parameters.
        - It calls `extract_params` to validate and extract relevant parameters from the user input.
        - Crucially, it calls `create_prompt` to assemble the prompt that will be sent to the LLM.

    2. **`prompts/__init__.py` (Prompt Assembly - Injection Point):** The `create_prompt` function (and subsequently `assemble_prompt`) is responsible for constructing the prompt. As previously analyzed, `assemble_prompt` directly embeds the `image_data_url` into the prompt without sanitization.
        ```python
        def assemble_prompt(
            image_data_url: str,
            stack: Stack,
            result_image_data_url: Union[str, None] = None,
        ) -> list[ChatCompletionMessageParam]:
            # ...
            user_content: list[ChatCompletionContentPartParam] = [
                {
                    "type": "image_url",
                    "image_url": {"url": image_data_url, "detail": "high"}, # [INJECTION POINT] Image URL directly embedded
                },
                {
                    "type": "text",
                    "text": user_prompt,
                },
            ]
            # ...
        ```
        - **Vulnerability Point:** The `image_data_url` (derived from user-uploaded image/video frames) is directly embedded into the prompt. Malicious content in the image/video frame will be passed to the LLM as instructions.

    3. **`video/utils.py` (Video Frame Extraction):** For video inputs, `backend/video/utils.py` is used to process the video and extract frames.
        ```python
        async def assemble_claude_prompt_video(video_data_url: str) -> list[Any]:
            images = split_video_into_screenshots(video_data_url) # [FRAME EXTRACTION] Splits video into images
            # ... converts images to prompt format ...
        ```
        - `assemble_claude_prompt_video` in `video/utils.py` is used when the input is a video. It calls `split_video_into_screenshots` to break down the video into individual frames (images).
        - These extracted frames are then processed similarly to single image uploads, making video inputs also vulnerable to prompt injection.

    4. **`llm.py` (LLM Interaction - Vulnerability Propagation):**  Files like `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` take the `messages` (containing the unsanitized image/video frame content) and send them to the LLMs. This part remains the same as described in the initial analysis.

    5. **Code Generation by LLM & Output to User:** The LLM generates code based on the prompt, including any malicious instructions. The generated code is then returned to the user via the websocket, without sanitization.

    **Visualization (Updated to include WebSocket and Video Input):**

    ```
    [Attacker-crafted Malicious Screenshot/Mockup/Video] --> Upload/Websocket --> [Backend API Endpoint (`/generate-code`)] -->
                                                                                                 |
                                                                                                 V
    [prompts/__init__.py - create_prompt/assemble_prompt] --> [Unsanitized Image/Frame Content in Prompt] -->
                                                                                                 |
                                                                                                 V
    [llm.py - stream_openai_response/...] --> [LLM API (e.g., OpenAI, Claude)] -->
                                                                                                 |
                                                                                                 V
    [Malicious Code Generated by LLM] --> [Backend] --> [Frontend (WebSocket)] --> [User Receives Malicious Code]
    ```

- **Security Test Case:**
    1. **Precondition:**  Ensure you have a running instance of the `screenshot-to-code` application accessible via `http://localhost:5173` (or the appropriate URL).
    2. **Craft a Malicious Screenshot (or Mockup):**
        - Use an image editing tool.
        - Create a simple screenshot that resembles a basic webpage.
        - **Inject Malicious Code:** Within the screenshot, add text representing malicious JavaScript, e.g., `<script>alert("XSS Vulnerability");</script>` or `<img src="x" onerror="alert('XSS')">`. Visually integrate this text as part of the "design".
        - Save as PNG (e.g., `malicious_screenshot.png`).
    3. **Access the Application:** Open a browser and navigate to `http://localhost:5173`.
    4. **Upload the Malicious Screenshot:** Use the application's UI to upload `malicious_screenshot.png`.
    5. **Select Stack and Generate Code:** Choose any stack (e.g., HTML + Tailwind) and click "Generate Code".
    6. **Review Generated Code:** Examine the generated code.
    7. **Verify Malicious Code Injection:** Check if the injected JavaScript is in the generated HTML.
    8. **Execute Generated Code (Impact Confirmation):**
        - Copy the generated HTML.
        - Create `test.html`, paste the code.
        - Open `test.html` in a browser.
        - **Observe XSS Execution:** An alert box with "XSS Vulnerability" (or injected message) should appear, confirming XSS.

    **Optional: Video Test Case (Extends the above test)**
    1. **Create a Malicious Video:** Use a video editing tool. Create a short video (e.g., screen recording). In one of the frames, inject the malicious JavaScript text as described in step 2 of the screenshot test case.
    2. **Upload the Malicious Video:** In the application UI, if video upload is supported, upload the malicious video.
    3. **Follow steps 5-8 from the Screenshot Test Case:**  Generate code, review, verify injection, and execute to confirm the XSS vulnerability via video input.

This test case (and its video extension) confirms prompt injection leading to XSS, demonstrating the vulnerability via both image and potentially video inputs. More complex payloads can be used for further exploitation.
