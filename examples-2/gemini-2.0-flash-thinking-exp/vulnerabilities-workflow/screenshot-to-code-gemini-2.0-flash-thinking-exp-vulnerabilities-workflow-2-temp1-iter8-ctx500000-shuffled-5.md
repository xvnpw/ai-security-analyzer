- Vulnerability name: Cross-Site Scripting (XSS) in AI-Generated Code Display

- Description:
    1. A user uploads a screenshot to the application.
    2. The backend uses an AI model to generate code based on the screenshot.
    3. The backend streams the AI-generated code to the frontend via WebSocket.
    4. The frontend receives the code and dynamically renders it in the user's browser, likely within an iframe or similar component to display the generated web application preview.
    5. If the AI model generates malicious JavaScript code (e.g., due to a crafted screenshot containing JavaScript), and the frontend renders this code without proper sanitization, the malicious script will be executed in the user's browser.
    6. An attacker can craft a screenshot that, when processed by the AI and rendered in the frontend, executes arbitrary JavaScript code, leading to XSS.

- Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to:
        - Stealing user session cookies and hijacking user accounts.
        - Defacing the web page displayed in the frontend.
        - Redirecting the user to malicious websites.
        - Performing actions on behalf of the user, if the user is authenticated and interacting with other services through this application.
        - Potentially gaining access to sensitive information accessible within the user's browser context.

- Vulnerability rank: High

- Currently implemented mitigations:
    - There are no explicit sanitization or encoding functions identified in the provided backend code (`codegen/utils.py` and `generate_code.py`) that would prevent XSS. The `extract_html_content` function in `codegen/utils.py` only extracts HTML content using regular expressions but does not sanitize it.

- Missing mitigations:
    - **Input sanitization:** The application is missing sanitization of the AI-generated code before displaying it in the frontend.
    - **Context-aware output encoding:** The frontend should implement context-aware output encoding when rendering the AI-generated code. For HTML context, this means HTML escaping all dynamic content. If rendering JavaScript, then JavaScript escaping is needed, but in this scenario, completely preventing JavaScript execution from the AI-generated code is the most secure approach.
    - **Content Security Policy (CSP):** Implementing a Content Security Policy (CSP) can help mitigate the risk of XSS by controlling the sources from which the browser is allowed to load resources. A restrictive CSP should be implemented to prevent the execution of inline scripts.

- Preconditions:
    - The attacker needs to be able to upload a screenshot to the application.
    - The AI model must generate code that includes malicious JavaScript based on the attacker's crafted screenshot.
    - The frontend must render the AI-generated code without proper sanitization.

- Source code analysis:
    - Backend (`backend/codegen/utils.py`):
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
        - The `extract_html_content` function uses a regular expression to extract content within `<html>` tags. It does not perform any sanitization or encoding of the HTML content. It simply extracts and returns the matched string.

    - Backend (`backend/routes/generate_code.py`):
        ```python
        from codegen.utils import extract_html_content
        # ...
        @router.websocket("/generate-code")
        async def stream_code(websocket: WebSocket):
            # ...
            completions = [extract_html_content(completion) for completion in completions]
            # ...
            for index, updated_html in enumerate(updated_completions):
                await send_message("setCode", updated_html, index)
                # ...
        ```
        - The `generate_code` websocket endpoint in `backend/routes/generate_code.py` calls `extract_html_content` on the AI-generated code.
        - The extracted HTML content is then sent to the frontend using `send_message` with type `"setCode"`.
        - There is no evidence of any sanitization or encoding of the HTML content before it is sent to the frontend.

    - Frontend (React - based on project description, code not provided):
        - Assuming the frontend is a React application, it is likely that the frontend receives the HTML code via WebSocket and updates the UI to display the generated code.
        - If the frontend directly uses `dangerouslySetInnerHTML` in React or similar mechanisms to render the received HTML, it will be vulnerable to XSS if the HTML is not sanitized. Without seeing frontend code, we must assume a vulnerable implementation as direct HTML rendering from untrusted sources is a common pattern leading to XSS.

- Security test case:
    1. Prepare a screenshot image that contains a malicious JavaScript payload. For example, create a simple HTML page, take a screenshot and upload it. The HTML page should include:
        ```html
        <h1>Screenshot with XSS</h1>
        <img src="https://placehold.co/150x150" alt="Test Image">
        <script>alert('XSS Vulnerability')</script>
        ```
        Alternatively, a simpler approach would be to craft a screenshot with an `<img>` tag with an `onerror` attribute that executes JavaScript:
        ```html
        <img src=invalid-url onerror="alert('XSS via Image onerror')" alt="XSS Image">
        ```
    2. Upload this crafted screenshot to the "screenshot-to-code" application using the frontend interface.
    3. Select any supported stack (e.g., HTML + Tailwind).
    4. Click the "Generate Code" button.
    5. Observe the frontend after the code is generated and displayed.
    6. **Expected Result (Vulnerable):** An alert box with the message "XSS Vulnerability" or "XSS via Image onerror" should pop up in the browser, indicating that the JavaScript code from the screenshot was executed. This confirms the XSS vulnerability.
    7. **Expected Result (Mitigated - if mitigations were present, which is not the case):** No alert box should appear. Instead, the generated code should be rendered without executing the malicious script. Inspecting the rendered HTML in the browser's developer tools should show that the `<script>` tag or the `onerror` attribute has been sanitized or escaped.
