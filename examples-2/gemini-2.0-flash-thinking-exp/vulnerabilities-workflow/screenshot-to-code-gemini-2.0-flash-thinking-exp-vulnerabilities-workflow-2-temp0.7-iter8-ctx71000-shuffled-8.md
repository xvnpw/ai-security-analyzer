- Vulnerability Name: Cross-Site Scripting (XSS) via AI-Generated Code
- Description:
    1. An attacker crafts a screenshot that contains UI elements or text prompts specifically designed to induce the AI model to generate HTML code containing malicious JavaScript. For example, the screenshot could depict an input field with text like `<img src=x onerror=alert('XSS')>` or a button with a label designed to be interpreted as an HTML tag with an `onerror` attribute.
    2. A user, intending to convert a design to code, uploads this crafted screenshot to the application through the frontend interface.
    3. The frontend sends the screenshot to the backend for processing.
    4. The backend utilizes an AI model (like Claude or GPT-4 Vision) to analyze the screenshot and generate code based on its interpretation of the visual elements. Due to the nature of AI models and the crafted input, the generated code inadvertently includes the malicious JavaScript provided in the screenshot.
    5. The backend transmits this AI-generated code, which now contains the malicious script, back to the frontend via a WebSocket connection.
    6. The frontend receives the generated HTML code and dynamically renders it within the application's user interface. If the frontend uses methods like `dangerouslySetInnerHTML` in React (or similar approaches in other frameworks) without proper sanitization, the browser will execute the embedded malicious JavaScript code as it parses and renders the HTML.
    7. The malicious JavaScript code executes in the user's browser within the context of the application. This can lead to various XSS attack scenarios.
- Impact:
    - Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code within the victim's browser when they view the AI-generated code.
    - This can have severe consequences, including:
        - **Session Hijacking:** Stealing session cookies to impersonate the user and gain unauthorized access to their account.
        - **Credential Theft:** Capturing user input, including usernames and passwords, if the injected script is designed to do so.
        - **Redirection to Malicious Sites:** Redirecting the user to attacker-controlled websites, potentially for phishing or malware distribution.
        - **Defacement:** Altering the visual appearance of the web page to mislead or disrupt users.
        - **Data Theft:** Accessing and exfiltrating sensitive data accessible by the web application.
        - **Malware Distribution:** Injecting scripts that download and execute malware on the user's system.
        - In the specific context of this application, an attacker could potentially steal API keys (OpenAI, Anthropic, Replicate) if they are stored in the browser's local storage or cookies, or manipulate the application to perform actions on behalf of the user, such as initiating further code generation requests or modifying settings.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None. Based on the provided code files, there is no evidence of input sanitization or output encoding applied to the AI-generated code before it is sent to the frontend or rendered in the user's browser. The backend code focuses on processing images and interacting with AI models, and the provided frontend code is not available to confirm client-side sanitization.
- Missing mitigations:
    - **Frontend Input Sanitization:** Implement robust sanitization of the AI-generated HTML code on the frontend before rendering it. This should involve parsing the HTML and removing or escaping any potentially malicious JavaScript code, such as `<script>` tags, event handlers (e.g., `onload`, `onerror`, `onclick`), and JavaScript URLs (e.g., `javascript:alert('XSS')`). Libraries like DOMPurify are designed for this purpose and can be integrated into the frontend application.
    - **Content Security Policy (CSP):** Implement a Content Security Policy to restrict the sources from which the browser is allowed to load resources and to disable inline JavaScript execution. A properly configured CSP can significantly reduce the risk of XSS attacks by preventing the execution of injected malicious scripts, even if they bypass input sanitization. The CSP should include directives such as `default-src 'self'`, `script-src 'self'`, and `style-src 'self' 'unsafe-inline'`. The `unsafe-inline` for styles should ideally be replaced with a nonce-based or hash-based approach for better security, but `'unsafe-inline'` is often used for Tailwind CSS in development and might be present in the configuration. For scripts, inline scripts should be avoided if possible, and if necessary, nonce or hash based CSP should be used.
    - **Regular Security Audits and Penetration Testing:** Conduct regular security audits and penetration testing to identify and address potential vulnerabilities, including XSS, in both the frontend and backend of the application. This should include specific test cases for XSS vulnerabilities arising from AI-generated content.
- Preconditions:
    - The attacker needs to craft a screenshot that effectively tricks the AI model into generating HTML code containing malicious JavaScript. This may require some experimentation to understand how the AI model interprets different visual inputs and generates code.
    - A user must upload and process this crafted screenshot using the application. The user does not need to be authenticated or have any special privileges to trigger the vulnerability.
- Source Code Analysis:
    - `backend/routes/generate_code.py`: This Python file defines the `/generate-code` WebSocket endpoint, which is the core of the code generation process.
        - The `stream_code` function handles WebSocket connections and orchestrates the code generation workflow.
        - It receives parameters from the frontend, including the screenshot image (`params["image"]`), desired stack (`generated_code_config`), and input mode (`inputMode`).
        - It calls `create_prompt` to assemble prompts for the AI model based on the input image and selected stack. The prompts themselves (defined in `backend/prompts` directory) do not include any sanitization logic; they are focused on instructing the AI to generate code based on the screenshot.
        - The code then interacts with different AI models (OpenAI, Anthropic, Gemini) through functions like `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` (defined in `backend/llm.py`) to generate code. These LLM interaction functions are purely for communication with the AI models and do not perform any sanitization on the responses.
        - The generated code is extracted using `extract_html_content` from `backend/codegen/utils.py`. This function (`extract_html_content`) only extracts the HTML content from the AI's response using regular expressions to find content within `<html>` tags and does not perform any sanitization.
        - The extracted HTML code is then sent back to the frontend via the WebSocket using `await websocket.send_json({"type": "setCode", "value": updated_html, "variantIndex": index})`.  Critically, there is no sanitization or encoding of `updated_html` before sending it to the frontend.
    - `backend/mock_llm.py`: This file provides mock responses for the LLM, used when `SHOULD_MOCK_AI_RESPONSE` is enabled in `backend/config.py`. The file includes several examples of HTML code that the AI could generate, such as `APPLE_MOCK_CODE`, `NYTIMES_MOCK_CODE`, `MORTGAGE_CALCULATOR_VIDEO_PROMPT_MOCK`, `GOOGLE_FORM_VIDEO_PROMPT_MOCK`, and `TALLY_FORM_VIDEO_PROMPT_MOCK`. Notably, `MORTGAGE_CALCULATOR_VIDEO_PROMPT_MOCK` contains `<script>` tags with JavaScript code, demonstrating that the AI model (or its mock) can indeed generate HTML containing JavaScript. This highlights the potential for XSS if this generated code is rendered unsanitized in the frontend.
    - `backend/image_generation/core.py`: This file contains functions for generating images using DALL-E 3 or Replicate. The `generate_images` function processes HTML code to find `<img>` tags and replace placeholder images with AI-generated ones. While it parses HTML using BeautifulSoup, it does not include any sanitization of the HTML code itself. This function manipulates image URLs within the generated code but does not address the risk of malicious JavaScript within the HTML structure.
    - `backend/evals/core.py`: This file orchestrates the code generation process for evaluations, selecting the appropriate LLM and calling the corresponding API. Similar to `routes/generate_code.py`, it focuses on prompt assembly and LLM interaction without any output sanitization.
    - `frontend/src` (Project files for frontend are not provided, assuming React based on README.md):
        - It is assumed that the frontend, upon receiving the `setCode` message via WebSocket, takes the `value` (which is the AI-generated HTML code) and renders it in the UI.
        - If the frontend uses React's `dangerouslySetInnerHTML` (or similar methods in Vue or plain JavaScript) to render this HTML without sanitization, it will directly inject the AI-generated HTML into the DOM.
        - If the AI-generated HTML contains malicious JavaScript, the browser will execute it when rendering the component, leading to XSS.

    **Visualization of Vulnerability Flow:**

    ```
    Attacker (Crafted Screenshot) --> User --> Frontend (Upload) --> Backend (/generate-code)
                                                                    |
                                                                    V
                                                        AI Model (Generates Malicious Code)
                                                                    |
                                                                    V
                            Backend (/generate-code) --> Frontend (Renders Malicious Code without Sanitization) --> User's Browser (XSS Execution)
    ```

- Security Test Case:
    1. **Craft a Malicious Screenshot:** Create a PNG image. Within the image, include text that, when interpreted as HTML by the AI, will contain JavaScript code. For instance, use the text: `<div id="test" style="width: 100px; height: 100px; background-color: lightblue;" onclick="alert('XSS Vulnerability!')">Click Me</div>`. Save this image as `xss_test.png`.
    2. **Prepare Base64 Encoded Image:** Convert the `xss_test.png` image to a base64 data URL. You can use online tools or Python:
       ```python
       import base64
       with open("xss_test.png", "rb") as image_file:
           base64_string = base64.b64encode(image_file.read()).decode('utf-8')
           data_url = f"data:image/png;base64,{base64_string}"
           print(data_url)
       ```
       Copy the generated `data_url`.
    3. **Access the Application:** Open the web application in a browser (e.g., `http://localhost:5173` if running locally, or the hosted version).
    4. **Open Developer Tools:** Open the browser's developer tools (usually by pressing F12) and go to the "Network" tab to monitor WebSocket communication.
    5. **Initiate Code Generation:** In the application, paste the copied base64 `data_url` into the image input field (or use the UI to upload the `xss_test.png` if that's supported and easier). Select any stack (e.g., "HTML + Tailwind"). Click the button to generate code.
    6. **Observe WebSocket Messages:** In the "Network" tab of the developer tools, filter for "websocket" or "ws". Inspect the WebSocket messages. You should see messages being sent and received. Look for a message of type `setCode`.
    7. **Inspect Rendered Output:** After the code generation completes, observe the output in the application's UI. You should see a light blue box with "Click Me" text as designed in the screenshot.
    8. **Trigger XSS:** Click on the "Click Me" box in the rendered output.
    9. **Verify XSS:** If a JavaScript alert box pops up displaying "XSS Vulnerability!", it confirms that the JavaScript code from the AI-generated output has been executed, thus demonstrating the XSS vulnerability.
    10. **Inspect Source Code (Alternative Verification):** If the alert doesn't appear for some reason, right-click on the rendered output in the browser and select "Inspect" or "Inspect Element". Examine the HTML source code. You should find the injected `div` element with the `onclick="alert('XSS Vulnerability!')"` attribute in the rendered DOM. This confirms that the malicious JavaScript was injected into the page by the AI and rendered by the frontend without sanitization.

This test case demonstrates how a crafted screenshot can lead to XSS in the application due to the AI model generating unsafe code and the frontend rendering it without proper sanitization.
