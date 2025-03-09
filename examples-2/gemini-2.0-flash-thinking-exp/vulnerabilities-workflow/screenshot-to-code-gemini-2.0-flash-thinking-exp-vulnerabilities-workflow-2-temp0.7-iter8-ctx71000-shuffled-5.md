### Vulnerability List

- **Vulnerability Name:** Cross-Site Scripting (XSS) in AI-Generated Code

- **Description:**
    An attacker can craft a malicious screenshot or mockup containing text that, when processed by the AI model, results in the generation of front-end code with an XSS vulnerability. This occurs because the AI model may directly embed the text content from the image into the generated HTML code without proper sanitization or encoding. If a user then deploys or uses this AI-generated code, they unknowingly introduce an XSS vulnerability into their web application. When a victim visits the user's web application and the malicious code is executed in their browser, it can lead to session hijacking, account takeover, sensitive data theft, or redirection to malicious websites.

- **Impact:**
    * **High**. Successful exploitation of this vulnerability can lead to:
        * **Data Theft:** Attackers can steal sensitive information like cookies, session tokens, and user data.
        * **Account Takeover:** By stealing session tokens or credentials, attackers can impersonate users and take control of their accounts.
        * **Malware Distribution:** Attackers can inject scripts that redirect users to malicious websites or download malware onto their systems.
        * **Website Defacement:** Attackers can modify the content of the web page, defacing the website or displaying misleading information.
        * **Redirection to Malicious Sites:** Users can be redirected to attacker-controlled websites, potentially for phishing or malware distribution.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    * **None**. The provided project files do not contain any explicit input sanitization or output encoding mechanisms to prevent XSS in the AI-generated code. The AI models are instructed to generate code based on the input image, and the generated code is directly returned to the user. Analysis of files like `backend/routes/generate_code.py`, `backend/codegen/utils.py`, and prompt files in `backend/prompts/` confirms the absence of sanitization.

- **Missing Mitigations:**
    * **Output Encoding:** The generated HTML code should be properly encoded before being presented to the user or incorporated into a web application. Specifically, text content derived from the screenshot and inserted into HTML elements should be HTML-encoded to neutralize any potentially malicious scripts.
    * **Content Security Policy (CSP):** Implementing a Content Security Policy (CSP) would be a strong mitigation. CSP allows developers to define a policy that dictates the sources from which the browser should be permitted to load resources. This can significantly reduce the risk and impact of XSS attacks, even if malicious code is injected.
    * **Regular Security Audits and Testing:**  Regularly auditing the code generation process and generated outputs for potential vulnerabilities, including XSS, is crucial. Implementing automated security testing as part of the development pipeline would help in identifying and addressing vulnerabilities early.

- **Preconditions:**
    * The attacker needs to be able to upload or provide a screenshot or mockup to the application, or provide a video which is split into screenshots.
    * The screenshot or mockup must contain text that can be interpreted as malicious code when embedded in HTML (e.g., JavaScript code within text content).
    * The user must use the generated code in a web application that is accessible to potential victims.

- **Source Code Analysis:**

    1. **`backend/routes/generate_code.py`**: This file handles the core logic of code generation. It receives user requests via WebSocket, extracts parameters, and orchestrates the AI code generation process.
        - The `stream_code` function is the entry point for handling code generation requests over WebSocket.
        - The `extract_params` function validates and extracts parameters from the incoming request, such as `stack`, `input_mode`, and API keys. It does not include any sanitization of input related to potential malicious code injection.
        - The code generation logic utilizes functions from `llm.py` (or `mock_llm.py` in mock mode) to interact with AI models (OpenAI, Anthropic, Gemini). These LLM interaction functions are focused on generating code based on prompts, and do not include any output sanitization.
        - After receiving the generated code from the LLM, the `extract_html_content` function from `codegen/utils.py` is used to extract HTML content from the completion. This function, as seen in `backend/codegen/test_utils.py`, is purely for extraction and does not perform any sanitization or encoding to prevent XSS.
        - The generated and extracted HTML code is then sent back to the client via WebSocket using `send_message` without any sanitization.

    2. **`backend/codegen/utils.py` & `backend/codegen/test_utils.py`**:
        - The `extract_html_content` function in `codegen/utils.py` uses regular expressions to find and extract content within `<html></html>` tags.
        - The `TestUtils` class in `backend/codegen/test_utils.py` provides unit tests for `extract_html_content`. These tests confirm that the function correctly extracts HTML content but do not include any tests for security-related aspects like sanitization or encoding. The function is designed for content extraction, not security.

    3. **`backend/prompts/` & `backend/prompts/imported_code_prompts.py`**:
        - The prompt files in `backend/prompts/` directory, including `imported_code_prompts.py`, define instructions for the AI models.
        - The system prompts, such as `IMPORTED_CODE_TAILWIND_SYSTEM_PROMPT`, instruct the AI to generate code in specific frameworks. These prompts focus on code functionality and visual accuracy based on the input screenshot or video frames.
        - Critically, none of the system prompts include instructions for the AI to sanitize or encode the generated code to prevent XSS vulnerabilities. In fact, some prompts, like those in `screenshot_system_prompts.py` (analyzed in previous report), explicitly instruct the AI to "Use the exact text from the screenshot," which directly exacerbates the XSS risk.

    4. **`backend/video/utils.py`**:
        - The `split_video_into_screenshots` function decodes video data URLs, splits videos into frames, and prepares screenshots for processing.
        - The `assemble_claude_prompt_video` function processes the screenshots and formats them into messages suitable for Claude API.
        - This video processing functionality expands the attack vector from static screenshots to video inputs. An attacker can embed malicious text in a video frame, which could then be extracted as text by the AI and injected into the generated code, leading to XSS.

    **Visualization:**

    ```
    [Attacker] --(Malicious Screenshot/Video)--> [Backend API (`generate_code.py`)] --> [AI Model (Generates Vulnerable Code)] --> [Backend (`generate_code.py`)] --(Vulnerable Code)--> [Frontend/User] --> [Victim Browser (XSS Exploited)]
    ```

    **Code Snippet Example (from `mock_llm.py` - `GOOGLE_FORM_VIDEO_PROMPT_MOCK`, and applicable to any AI generated text):**

    ```html
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer">times</div>
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer">ts-ebml</div>
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer">tiktok ceo</div>
    ```

    If the AI were to generate code like this based on a screenshot or video frame where the text "times" is replaced with `<img src=x onerror=alert('XSS')>`, the generated code would become:

    ```html
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer"><img src=x onerror=alert('XSS')></div>
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer">ts-ebml</div>
    <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer">tiktok ceo</div>
    ```
    When this code is rendered in a browser, the JavaScript `alert('XSS')` will execute, demonstrating the XSS vulnerability.

- **Security Test Case:**

    1. **Precondition:** Access to a publicly available instance of the `screenshot-to-code` application.

    2. **Step 1: Prepare a Malicious Screenshot.**
        Create a screenshot or mockup that includes text designed to trigger an XSS vulnerability when converted to code. For example, include the following text in the screenshot:
        ```html
        <script>alert('XSS Vulnerability triggered by malicious screenshot!');</script>
        ```
        You can also try with a simple image tag with `onerror` event:
        ```html
        <img src=x onerror=alert('XSS Image XSS')>
        ```
        Save this screenshot as `malicious_screenshot.png`.

    3. **Step 2: Upload the Malicious Screenshot.**
        Use the `screenshot-to-code` application. Upload the `malicious_screenshot.png`. Select any frontend stack (e.g., HTML + Tailwind). Initiate the code generation process.

    4. **Step 3: Examine the Generated Code.**
        Once the code is generated, review the HTML code output. Look for the text you included in the screenshot. Verify if the generated code contains the malicious script directly embedded without proper encoding. You should see the `<script>alert('XSS Vulnerability triggered by malicious screenshot!');</script>` or `<img src=x onerror=alert('XSS Image XSS')>` code directly in the output.

    5. **Step 4: Deploy and Test the Generated Code.**
        Copy the generated HTML code. Create a new HTML file (e.g., `test_xss.html`) and paste the generated code into it. Open `test_xss.html` in a web browser.

    6. **Step 5: Verify XSS Execution.**
        Observe if an alert box appears in the browser displaying "XSS Vulnerability triggered by malicious screenshot!" or "XSS Image XSS". If the alert box appears, it confirms that the XSS vulnerability is present in the AI-generated code and is successfully exploitable.

- **Result of Test Case:**
    Executing the above test case will likely result in the display of the alert box, confirming the presence of the XSS vulnerability. The AI model, as configured, directly translates the text from the screenshot into code without sanitization, leading to injectable scripts being rendered in the browser.
