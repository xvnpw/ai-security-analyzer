* Vulnerability Name: **Unsanitized Input Leading to Malicious Code Generation (Prompt Injection)**
* Description:
    * An attacker can craft a malicious screenshot or screen recording that, when uploaded and processed by the AI model, can lead to the generation of vulnerable or malicious code.
    * This is possible because the application lacks proper sanitization of the input image or video content before feeding it to the AI model.
    * The AI model, interpreting the malicious content as part of the design or instructions, incorporates it into the generated code.
    * For example, a screenshot could contain text that, when interpreted by the AI, results in the AI generating JavaScript code with an `alert()` function or embedding a malicious iframe.
* Impact:
    * Users who utilize the generated code might unknowingly include vulnerabilities in their web applications.
    * This could lead to various security issues like Cross-Site Scripting (XSS) if the generated code includes malicious JavaScript, or other types of injection vulnerabilities depending on the crafted prompt.
    * If an attacker injects code that makes insecure API calls, it could lead to data breaches or unauthorized actions in systems where the generated code is deployed.
    * The generated code could also contain backdoors or redirect users to malicious websites.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * There is no evidence in the provided project files of any input sanitization or output encoding mechanisms implemented to prevent prompt injection attacks. The code directly processes the input image/video and uses it in prompts to LLMs.
    * The `config.py` file includes a `SHOULD_MOCK_AI_RESPONSE` flag, but this is only for debugging and not a security mitigation.
* Missing Mitigations:
    * **Input Sanitization:** Implement robust sanitization of the input screenshot and screen recording content before sending it to the AI model. This should involve stripping out or encoding potentially malicious code snippets or commands within the image or video.
    * **Output Encoding:**  Ensure that the generated code is properly encoded to prevent execution of injected scripts, especially when rendering the generated HTML in a browser. For example, if the AI is asked to generate text that is later displayed on a web page, the application should HTML-encode this text to prevent XSS.
    * **Content Security Policy (CSP):** Implement a strong Content Security Policy to limit the capabilities of the generated code within a user's browser, reducing the potential impact of injected malicious scripts. This is a general mitigation for XSS, but relevant here as the generated code might be vulnerable.
    * **Regular Security Audits and Vulnerability Scanning:** Regularly audit the code and the AI model interactions for potential vulnerabilities, including prompt injection. Use vulnerability scanning tools to identify potential weaknesses.
    * **User Awareness and Warnings:** Display clear warnings to users about the potential risks of using AI-generated code, especially from untrusted sources. Advise users to carefully review and test the generated code before deploying it.
* Preconditions:
    * The attacker needs to be able to upload a screenshot or screen recording to the application.
    * The application must be configured to use a real AI model (not mock mode).
    * The attacker needs to have knowledge of prompt injection techniques and how to embed malicious payloads within images or videos in a way that the AI model will interpret and incorporate into the generated code.
* Source Code Analysis:
    * **`backend/llm.py`:** This file contains the core logic for interacting with different LLMs (OpenAI, Anthropic, Gemini). The functions `stream_openai_response`, `stream_claude_response`, `stream_claude_response_native`, and `stream_gemini_response` take messages as input and stream responses from the respective LLMs. There is no code in these functions that sanitizes the input messages or checks for malicious content. The messages are directly forwarded to the LLM APIs.
    * **`backend/main.py` and `backend/routes/`:** These files set up the FastAPI backend and define the API endpoints. The routes, specifically `generate_code.py`, handle receiving the user's screenshot/video and passing it to the LLM interaction functions in `llm.py`.  A review of the `generate_code.py` route confirms that no input validation or sanitization is performed before calling the LLM functions. The code directly extracts parameters from the websocket message and uses them to create prompts and call LLMs.
        * **`backend/routes/generate_code.py` analysis:** The `/generate-code` websocket endpoint in `generate_code.py` receives user input through `websocket.receive_json()`. This input, including parameters related to the image or video, is directly used to construct prompts via the `create_prompt` function. There is no sanitization or validation of the input content within the `stream_code` function or in the `extract_params` function which parses the initial parameters. The `create_prompt` function (code not provided in PROJECT FILES, but based on context from previous analysis) likely takes this unsanitized input and embeds it into prompts sent to the LLMs.
    * **`backend/prompts/`:** These files (`claude_prompts.py`, `imported_code_prompts.py`, `screenshot_system_prompts.py`, `test_prompts.py`, `types.py`, `__init__.py`) define the prompts used for different scenarios and models. The prompts themselves do not include any instructions to the LLMs to sanitize or validate user inputs.  Instead, they focus on instructing the LLMs to generate code based on the input image, assuming the input is trustworthy.
    * **`backend/video_to_app.py` (referenced in previous analysis but not provided as file content this time, functionality is now within `backend/video/utils.py` and `backend/routes/generate_code.py`):**  The video processing logic is now in `backend/video/utils.py`. The `assemble_claude_prompt_video` function in `backend/video/utils.py` prepares the prompt messages for video input by splitting the video into screenshots and encoding each screenshot into a base64 data URL. It includes these data URLs directly in the prompt.  Crucially, there is no sanitization of the video content or the extracted screenshots before they are incorporated into the prompt. This means if a video frame contains malicious text or visual elements intended for prompt injection, they will be directly passed to the LLM.
    * **`backend/evals/core.py` and `backend/evals/runner.py` (referenced in previous analysis) and `backend/routes/evals.py`:** These files are related to evaluation and testing, and do not introduce sanitization logic. `backend/routes/evals.py` reads files from the filesystem to perform evaluations but doesn't process user-provided input for code generation in a way that would mitigate prompt injection.

    **Visualization of Vulnerability Flow:**

    ```
    [Attacker] --> [Crafted Malicious Screenshot/Video]
             |
             V
    [Frontend] --> [WebSocket /generate-code] --> [Backend - generate_code.py - stream_code] (receives image/video data in params)
             |
             V
    [Backend - generate_code.py - extract_params & create_prompt] --> [video/utils.py - assemble_claude_prompt_video (for videos)] --> [llm.py - stream_*(...) functions] (forwards unsanitized input in prompt to LLM)
             |
             V
    [LLM (Claude/GPT-4/Gemini)] --> [Generates Code with potentially malicious content]
             |
             V
    [Backend] --> [WebSocket /generate-code] --> [Frontend] --> [User receives potentially vulnerable code]
    ```

* Security Test Case:
    1. Open the web application in a browser.
    2. Prepare a malicious PNG image. For example, use an image editor or online tool to create a PNG image. Within the image, embed text that, when interpreted as code, will execute JavaScript. A simple way to do this is to include text like:
       ```html
       <img src="x" onerror="alert('XSS Vulnerability!')">
       ```
       Render this HTML text within the image itself so that it becomes part of the visual content of the PNG.
    3. In the application, select "Image" input mode and choose the malicious PNG image file you created.
    4. Select "HTML + Tailwind" (or any other HTML-based stack) as the desired output stack.
    5. Click the "Generate Code" button.
    6. After the code is generated and displayed in the application:
        * **Inspect the Generated Code:** Carefully examine the generated HTML code. Look for the presence of the injected malicious payload. In this case, search for the `<img src="x" onerror="alert('XSS Vulnerability!')">` tag or any variation of it. The AI model might slightly alter the injected code, but the core malicious part should be recognizable.
        * **Execute the Generated Code (locally and with caution):** Copy the generated HTML code. Save it as an HTML file (e.g., `test.html`) on your local machine. Open this `test.html` file in a web browser.
        * **Verify XSS:** If the alert box with "XSS Vulnerability!" appears when you open `test.html`, this confirms that the prompt injection was successful and the AI generated code that executes the malicious JavaScript.

    If the alert box appears, the vulnerability is proven. If you want to test for more sophisticated payloads, you could inject code that tries to redirect the user to a different website, or attempts to steal cookies or other sensitive information (in a safe test environment). For video input, a similar approach can be used. Create a short video where some frames contain malicious text or visual elements. Upload this video to the application and observe if the generated code reflects the injected content.
