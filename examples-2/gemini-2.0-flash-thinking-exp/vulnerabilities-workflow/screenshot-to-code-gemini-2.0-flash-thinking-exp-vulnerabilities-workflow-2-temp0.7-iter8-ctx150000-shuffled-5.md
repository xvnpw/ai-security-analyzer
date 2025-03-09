### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code
- Description:
    1. An attacker crafts a malicious screenshot. This screenshot is designed to trick the AI model into generating HTML or JavaScript code containing a malicious payload. For example, the screenshot could depict a button with a label that includes an XSS payload such as `<img src=x onerror=alert('XSS')>`.
    2. A user, either intentionally or unknowingly, uploads this malicious screenshot to the "screenshot-to-code" web application.
    3. The application's backend receives the screenshot and sends it to the chosen AI model (e.g., Claude Sonnet 3.7 or GPT-4o) for processing and code generation.
    4. Due to the nature of the malicious screenshot, the AI model interprets the malicious payload as part of the intended UI elements and generates HTML or JavaScript code that includes this payload. For instance, the AI might generate a button element where the button's text content or an attribute contains the `<img src=x onerror=alert('XSS')>` payload.
    5. The backend processes the AI-generated code. Critically, the backend does not sanitize or validate the generated code to remove or neutralize potentially harmful scripts. The function `extract_html_content` in `backend\codegen\utils.py` only extracts HTML content without any sanitization.
    6. The backend then sends this unsanitized generated code to the frontend via a WebSocket connection.
    7. The frontend receives the code and dynamically renders it within the user's web browser. Since the code is not sanitized, the malicious JavaScript payload embedded in the generated HTML is executed by the browser.
    8. As a result, the attacker's JavaScript code is executed in the context of the user's session within the "screenshot-to-code" application, demonstrating a Cross-Site Scripting (XSS) vulnerability.
- Impact:
    - Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code within the browser of any user viewing the AI-generated output.
    - This can lead to a variety of malicious activities, including:
        - **Account Hijacking:** Stealing session cookies or other authentication tokens to gain unauthorized access to user accounts.
        - **Data Theft:** Exfiltrating sensitive information displayed within the application or accessible through the user's session.
        - **Redirection to Malicious Websites:** Redirecting users to attacker-controlled websites, potentially for phishing or malware distribution.
        - **Application Defacement:** Altering the visual appearance or functionality of the web application for the victim user.
        - **Further Exploitation:** Using the XSS vulnerability as a stepping stone for more complex attacks against the application or its users.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided backend code does not include any mechanisms to sanitize or validate the AI-generated code before sending it to the frontend. The function `extract_html_content` in `backend\codegen\utils.py` is purely for extraction and does not perform sanitization.
- Missing Mitigations:
    - **Output Sanitization (Backend):** The most critical missing mitigation is the sanitization of the AI-generated HTML code on the backend. Before sending the generated code to the frontend via WebSocket, the backend should employ a robust HTML sanitization library, such as DOMPurify (or a similar server-side equivalent if DOMPurify is frontend-focused), to parse the generated HTML and remove any potentially malicious JavaScript code or attributes. This would involve:
        - Integrating a sanitization library into the backend code, specifically in `backend\routes\generate_code.py` right before sending the `setCode` message via WebSocket.
        - Configuring the sanitization library to remove JavaScript code, event handlers (e.g., `onerror`, `onload`, `onclick`), and other potentially dangerous HTML attributes and elements from the generated code.
    - **Content Security Policy (CSP) (Frontend):** While not a backend mitigation, implementing a Content Security Policy (CSP) in the frontend would provide an additional layer of defense. CSP headers can be configured to restrict the sources from which the browser is allowed to load resources (scripts, stylesheets, images, etc.) and to prevent the execution of inline JavaScript. This can significantly reduce the impact of XSS vulnerabilities, even if sanitization on the backend is bypassed.
- Preconditions:
    - The "screenshot-to-code" application must be running and accessible to the attacker.
    - The attacker needs the ability to craft a screenshot or video that can influence the AI model to generate HTML or JavaScript code containing a malicious payload. This typically involves including recognizable HTML or JavaScript syntax within the visual representation of the screenshot.
- Source Code Analysis:
    1. File: `backend\routes\generate_code.py`
        ```python
        from codegen.utils import extract_html_content
        # ...
        @router.websocket("/generate-code")
        async def stream_code(websocket: WebSocket):
            # ...
            completions = [extract_html_content(completion) for completion in completions]
            # ...
            await send_message("setCode", updated_html, index)
            # ...
        ```
        - This code snippet from the `/generate-code` WebSocket endpoint demonstrates the vulnerability.
        - The `extract_html_content` function is used to process the AI-generated code.
        - **Crucially, there is no sanitization step applied to the `completions` variable after extracting the HTML content and before sending it to the frontend using `send_message("setCode", updated_html, index)`.**
        - The `updated_html` variable, which is directly derived from the AI's output, is sent to the frontend without any security processing.
    2. File: `backend\codegen\utils.py`
        ```python
        import re

        def extract_html_content(text: str):
            # Use regex to find content within <html> tags and include the tags themselves
            match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
            if match:
                return match.group(1)
            else:
                # Otherwise, we just send the previous HTML over
                print(
                    "[HTML Extraction] No <html> tags found in the generated content: " + text
                )
                return text
        ```
        - The `extract_html_content` function is responsible for extracting the HTML portion from the AI-generated text response.
        - **The function utilizes a regular expression `r"(<html.*?>.*?</html>)"` to identify and extract the HTML content.**
        - **It is important to note that this function performs only extraction and does not include any form of sanitization or security filtering.** It simply returns the matched HTML string as is.
        - The lack of sanitization in this utility function directly contributes to the XSS vulnerability, as it ensures that any malicious scripts present in the AI-generated output are preserved and passed on to the frontend.

- Security Test Case:
    1. **Setup:**
        - Ensure you have the "screenshot-to-code" application running locally or have access to a publicly hosted instance (e.g., using the hosted version link provided in the `README.md`).
        - Open a web browser and navigate to the application's frontend URL (typically `http://localhost:5173` for local development).
    2. **Craft Malicious Screenshot:**
        - Use an image editing tool or simply create a basic HTML page and take a screenshot of it.
        - Embed the following XSS payload within the visual content of the screenshot. For instance, add a button or text element that visually represents the following HTML tag: `<img src=x onerror=alert('XSS-Vulnerability-Test')>`
        - Save the screenshot as a PNG or JPEG file.
    3. **Upload Malicious Screenshot:**
        - In the "screenshot-to-code" application's frontend, locate the image upload area.
        - Upload the crafted malicious screenshot file.
        - Select any supported stack for code generation (e.g., "HTML + Tailwind").
        - Initiate the code generation process by clicking the "Generate Code" button or similar action.
    4. **Observe Application Behavior:**
        - After the AI model processes the screenshot and the backend sends the generated code to the frontend, carefully observe the behavior of the web application in your browser.
        - **Specifically, look for a JavaScript alert dialog box to appear. The alert box should display the message 'XSS-Vulnerability-Test' (or 'XSS' if you used the simpler payload).**
    5. **Verify XSS Confirmation:**
        - **If the alert dialog box appears with the expected message, this confirms the Cross-Site Scripting (XSS) vulnerability.** It indicates that the malicious JavaScript code embedded in the screenshot was successfully generated by the AI, transmitted to the frontend, and executed within your browser's context when rendering the AI-generated output.
        - If the alert box does not appear, re-examine the crafted screenshot, ensure the payload is correctly embedded, and repeat the test. If the issue persists, further investigation of the application's frontend rendering process might be necessary.
