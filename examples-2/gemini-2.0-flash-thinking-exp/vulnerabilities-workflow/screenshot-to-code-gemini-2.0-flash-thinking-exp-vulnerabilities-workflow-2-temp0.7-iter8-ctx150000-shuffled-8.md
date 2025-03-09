### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code

- Description:
    1. An attacker crafts a malicious screenshot or video input that contains text or visual elements designed to be interpreted by the AI model as HTML or JavaScript code. For example, the attacker includes text like `<img src=x onerror=alert('XSS')>` in the screenshot.
    2. The user uploads this malicious screenshot or video to the application.
    3. The backend processes the input using an AI model (e.g., GPT-4 Vision, Claude 3) to generate HTML, CSS, and JavaScript code.
    4. Due to the nature of AI models and the current prompts, the generated code may directly include the malicious payload from the input screenshot without proper sanitization or encoding. For example, the AI might generate:
        ```html
        <div>
          <img src=x onerror=alert('XSS')>
        </div>
        ```
    5. The backend sends this generated code to the frontend via WebSocket.
    6. The frontend renders the received HTML code in the user's browser.
    7. Because the malicious payload is directly embedded in the HTML, the JavaScript code (`alert('XSS')`) executes when the browser attempts to load the image (`<img src=x>`), resulting in an XSS vulnerability.
    8. An attacker can exploit this XSS to execute arbitrary JavaScript code in the context of the user's browser when they use or preview the generated code. This could lead to session hijacking, cookie theft, or redirection to malicious sites.

- Impact:
    - High
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to account takeover, data theft, malware injection, and other malicious activities.
    - Users who copy and paste the generated code into their own projects are also vulnerable if they do not manually sanitize the code.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None
    - The project does not currently implement any explicit sanitization or encoding of the generated code to prevent XSS vulnerabilities. The code generation process relies on AI models, which are not inherently designed to produce secure output and can include verbatim text from the input image.

- Missing Mitigations:
    - **Output Sanitization/Encoding**: The generated HTML code should be sanitized or encoded before being sent to the frontend or presented to the user. This could involve using a library or function to escape HTML entities or remove potentially malicious JavaScript code. Libraries like DOMPurify (for JavaScript frontend) or Bleach (for Python backend) could be used.
    - **Content Security Policy (CSP)**: Implementing a Content Security Policy (CSP) can help mitigate the impact of XSS by controlling the resources the browser is allowed to load and execute. This should be configured on the frontend to restrict inline scripts and unsafe-inline styles.
    - **Security Audits and Testing**: Regular security audits and penetration testing should be performed to identify and address potential vulnerabilities in the code generation process and the application as a whole.
    - **User Education**: Users should be warned about the potential security risks of using AI-generated code and advised to review and sanitize the code before deploying it in production environments.

- Preconditions:
    - The attacker needs to be able to craft a screenshot or video that includes a malicious payload that the AI model will interpret as code and include in the generated output.
    - The user must upload and process this malicious input using the application.
    - The user or another victim must then render or use the generated code in a browser environment without sanitizing it.

- Source Code Analysis:
    1. **`backend\routes\generate_code.py`**: This file handles the code generation process via the `/generate-code` WebSocket endpoint.
    2. The `stream_code` function receives user input (screenshot/video) and parameters.
    3. It uses `create_prompt` from `backend\prompts\__init__.py` to construct prompts for the AI model based on the input image and selected stack.
    4. It calls `stream_openai_response` or `stream_claude_response` in `backend\llm.py` to get code completions from the AI model.
    5. The raw code completion from the AI model is then passed through `extract_html_content` in `backend\codegen\utils.py`.
    6. **`backend\codegen\utils.py`**: `extract_html_content` function uses a regex `r"(<html.*?>.*?</html>)"` to extract HTML content. This function only extracts content within `<html>` tags but does not perform any sanitization.
        ```python
        def extract_html_content(text: str):
            match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
            if match:
                return match.group(1)
            else:
                return text
        ```
    7. The extracted HTML content is sent back to the frontend via WebSocket using `send_message("setCode", updated_html, index)`.
    8. **Frontend (React/Vite - code not provided)**: The frontend (likely in React components) receives the HTML code and uses `dangerouslySetInnerHTML` or similar methods to render the HTML in the browser. If no sanitization is performed on the frontend before rendering, any malicious JavaScript code in the generated HTML will be executed.

- Security Test Case:
    1. **Prepare Malicious Screenshot**: Create a simple image (e.g., using any image editor or even a basic drawing tool). Embed the following text into the image content:
        ```html
        <img src=x onerror="alert('XSS-Test-Successful')">
        ```
        Save this image as `xss_test.png`.
    2. **Access the Application**: Open the frontend application in a web browser (e.g., `http://localhost:5173`).
    3. **Upload Malicious Screenshot**: In the application, select "Screenshot to Code" functionality. Upload the `xss_test.png` image as input. Choose any stack (e.g., HTML + Tailwind). Click "Generate Code".
    4. **Observe the Output**: Wait for the AI to process the image and generate code. Once the code is generated and displayed in the frontend:
        - **Expected Result (Vulnerable)**: An alert box with the message "XSS-Test-Successful" should pop up in the browser. This indicates that the JavaScript code from the malicious screenshot was successfully injected and executed in the browser, confirming the XSS vulnerability.
        - **If no alert box appears**: Check the generated code in the application's output panel. Verify if the generated HTML code contains the malicious `<img src=x onerror=alert('XSS-Test-Successful')>` payload. If the payload is present in the generated code but the alert doesn't pop up, there might be some other mitigation in place (e.g., browser's built-in XSS filters, though these are often bypassed). However, if the payload is in the code, the vulnerability is still present.
    5. **Code Review (Optional but Recommended)**: Review the generated code to confirm that the malicious `<img>` tag is present in the output. Also, check the frontend code (React components) to verify if any sanitization is being performed before rendering the received HTML. If no sanitization is found in the frontend, the vulnerability is further confirmed.

This test case demonstrates how a malicious screenshot can lead to XSS in the generated code due to the lack of sanitization in the backend and frontend.
