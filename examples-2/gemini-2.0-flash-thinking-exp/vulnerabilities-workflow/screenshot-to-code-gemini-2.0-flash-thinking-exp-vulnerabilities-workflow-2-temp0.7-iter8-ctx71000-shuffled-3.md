### Vulnerability 1

- Vulnerability Name: Cross-Site Scripting (XSS) via AI-Generated Code
- Description:
    1. An attacker crafts a malicious design or screenshot. This design can include text or visual elements that, when interpreted by the AI model, will result in the generation of JavaScript code capable of executing XSS attacks. For example, the attacker could include text in the screenshot that resembles HTML tags with inline JavaScript event handlers or script tags containing malicious code.
    2. A user, intending to generate code from a legitimate design, uploads this attacker-crafted malicious screenshot to the screenshot-to-code tool.
    3. The backend of the tool receives the screenshot and sends it to the configured AI model (e.g., GPT-4 Vision, Claude) for code generation.
    4. The AI model processes the screenshot and, as instructed by the system prompts to reproduce the visual design accurately, unknowingly generates front-end code (HTML, CSS, and potentially JavaScript) that includes the malicious JavaScript injected via the screenshot.
    5. The backend streams this AI-generated code, now containing the XSS vulnerability, back to the frontend and presents it to the user.
    6. The user, unaware that the generated code is malicious, may deploy or use this code directly.
    7. When other users access or interact with the deployed AI-generated code, the embedded malicious JavaScript executes in their browsers.
    8. This execution can lead to various attacks, including session hijacking, theft of sensitive information, website defacement, redirection to malicious sites, or other malicious actions within the context of the user's browser session.
- Impact:
    - Successful exploitation of this vulnerability allows an attacker to perform Cross-Site Scripting (XSS) attacks on users who interact with the AI-generated code.
    - The impact of XSS can be critical, potentially leading to:
        - **Account Takeover**: Attackers can steal session cookies or credentials, gaining unauthorized access to user accounts.
        - **Data Breach**: Sensitive user data or application data can be exfiltrated to attacker-controlled servers.
        - **Malware Distribution**: Users can be redirected to websites hosting malware, leading to system compromise.
        - **Website Defacement**: The visual appearance and functionality of the web application can be altered, damaging the application's reputation and user trust.
        - **Phishing Attacks**: Users can be redirected to fake login pages or other phishing scams to steal credentials or personal information.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - The backend code in `backend\codegen\utils.py` includes a function `extract_html_content`. This function attempts to extract only the HTML content from the AI-generated response by using regular expressions to find content within `<html>` tags.
    - However, this mitigation is insufficient to prevent XSS vulnerabilities because:
        - It only extracts content within `<html>` tags and does not sanitize the HTML content itself. Malicious JavaScript can still be embedded within HTML tags, such as through inline event handlers (e.g., `onload`, `onclick`) or `<script>` tags included within the HTML structure.
        - As demonstrated in `backend\codegen\test_utils.py`, the tests for `extract_html_content` only verify the extraction of HTML tags and do not include any checks for sanitization or XSS prevention.
        - It does not address other potential XSS vectors that might be generated within HTML attributes or other parts of the HTML code.
- Missing mitigations:
    - **Input Sanitization of AI-Generated Code**: Implement robust server-side sanitization of the AI-generated code before it is presented to the user. This should involve parsing the HTML, CSS, and JavaScript code and removing or neutralizing any potentially malicious code. Specifically, the sanitization should:
        - Remove or escape `<script>` tags and inline JavaScript.
        - Remove or neutralize JavaScript event handlers (e.g., `onload`, `onclick`, `onmouseover`, etc.) from HTML attributes.
        - Sanitize or disallow JavaScript URLs (e.g., `javascript:alert('XSS')`).
        - Consider using a well-vetted HTML sanitization library to ensure comprehensive coverage of XSS attack vectors.
    - **Content Security Policy (CSP)**: Implement a Content Security Policy (CSP) to limit the capabilities of the generated web pages and mitigate the impact of XSS. A restrictive CSP should be configured to:
        - Disable inline JavaScript execution (`script-src 'none'`).
        - Restrict script sources to a whitelist of trusted domains (`script-src 'self' https://cdn.example.com`).
        - Disable `eval()` and similar unsafe JavaScript functions (`unsafe-inline`, `unsafe-eval` directives should be avoided or strictly controlled).
    - **User Education and Warnings**: Display clear warnings to users about the inherent security risks associated with deploying AI-generated code without thorough security review and testing. Emphasize that the tool generates code based on visual similarity and may not inherently produce secure code. Recommend manual review and security audits of all generated code before deployment.
- Preconditions:
    - An attacker must be able to create a malicious design or screenshot that can successfully trick the AI model into generating code with XSS vulnerabilities. This may require some experimentation to find effective injection techniques that bypass the AI's intended behavior.
    - A user must upload and generate code from this malicious screenshot using the screenshot-to-code tool.
    - The user must then deploy or utilize the generated code in an environment where it can be accessed and executed by other users' browsers without performing adequate security checks or sanitization of the AI-generated output.
- Source code analysis:
    - `backend\routes\generate_code.py`: This file contains the core logic for handling code generation requests.
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
        - The `stream_code` function in `generate_code.py` is responsible for generating code using the AI model and sending it back to the client.
        - It utilizes `extract_html_content` to process the AI's response. However, as noted before, `extract_html_content` only extracts HTML tags and does not perform any sanitization to prevent XSS.
        - The generated `updated_html` is directly sent to the frontend using `send_message("setCode", updated_html, index)`, and ultimately presented to the user without further security processing.
    - `backend\codegen\utils.py`: This file contains the `extract_html_content` function.
        ```python
        import re
        def extract_html_content(text: str):
            match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
            if match:
                return match.group(1)
            else:
                return text
        ```
        - The `extract_html_content` function uses a regular expression to extract content within `<html>` tags.
        - This function is intended to isolate the HTML code from the full AI response, but it does not perform any sanitization of the HTML itself. It simply returns the matched HTML content or the original text if no `<html>` tags are found.
    - `backend\evals\core.py`: This file shows the core logic for code generation and how prompts are assembled and used to interact with LLMs.
        ```python
        from prompts import assemble_prompt
        # ...
        async def generate_code_for_image(image_url: str, stack: Stack, model: Llm) -> str:
            prompt_messages = assemble_prompt(image_url, stack)
            return await generate_code_core(prompt_messages, model)
        ```
        - The `generate_code_for_image` function in `backend\evals\core.py` demonstrates how the image and stack information are used to assemble prompts. The prompts, as seen in `backend\prompts\imported_code_prompts.py` and `backend\prompts\claude_prompts.py`, are designed to instruct the AI to generate code based on visual input. These prompts, while necessary for functionality, do not include any instructions for the AI to sanitize its output for security vulnerabilities like XSS. The AI is primarily focused on visual accuracy and code functionality, not security.
- Security test case:
    1. **Malicious Screenshot Creation**:
        - Create a new image file (e.g., PNG or JPG).
        - Use an image editor or a simple drawing tool to create a visual element, such as a button or a text field.
        - Embed the following text within the image as part of the visual element: `<img src=x onerror=alert('XSS Vulnerability!')>`
        - Save the image file (e.g., `xss_image.png`).
    2. **Tool Interaction**:
        - Open the screenshot-to-code application in a web browser (e.g., `http://localhost:5173`).
        - Select any available stack (e.g., "HTML + Tailwind").
        - Upload the `xss_image.png` file to the tool.
        - Click the "Generate Code" button.
    3. **Code Inspection**:
        - After the code generation process is complete, examine the generated code displayed in the tool.
        - Search for the injected XSS payload: `<img src=x onerror=alert('XSS Vulnerability!')>`.
        - Verify that the generated code includes this string, likely within an `<img>` tag or as part of a text element, depending on how the AI interpreted the screenshot.
    4. **Exploit Verification**:
        - Copy the generated HTML code.
        - Create a new HTML file (e.g., `xss_test.html`) and paste the copied code into it.
        - Open `xss_test.html` in a web browser.
        - Observe if an alert box appears with the message "XSS Vulnerability!".
        - If the alert box appears, it confirms that the XSS payload was successfully injected into the AI-generated code and is executable in a web browser, thus validating the XSS vulnerability.
