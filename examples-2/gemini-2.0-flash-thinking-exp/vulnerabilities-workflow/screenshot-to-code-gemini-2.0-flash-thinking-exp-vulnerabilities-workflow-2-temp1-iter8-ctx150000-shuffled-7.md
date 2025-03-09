### Vulnerability List

* Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code
* Description:
    1. An attacker crafts a malicious screenshot or design mockup that includes text or elements designed to be interpreted as code, for example, including a text field with content like `<img src=x onerror=alert('XSS')>`.
    2. A user, intending to generate code from a legitimate design, is tricked into using this manipulated screenshot or design and uploads it to the application through the frontend interface.
    3. The application's backend, specifically in `backend/routes/generate_code.py`, receives the image and processes it using AI models via functions in `backend/llm.py`. The AI model interprets the manipulated elements in the screenshot as intended content and structure for the target web page.
    4. Consequently, the AI model, without any output sanitization, generates HTML, CSS, or Javascript code that directly incorporates the malicious script or payload from the manipulated screenshot. For example, the generated code might contain `<input value="<img src=x onerror=alert('XSS')>">` or similar constructs directly from the malicious input image.
    5. The application streams this AI-generated, potentially malicious code back to the user's browser via WebSocket, as handled in `backend/routes/generate_code.py`.
    6. The user, unaware of the embedded malicious script, copies and integrates this AI-generated code into their own web project.
    7. When another user accesses the project containing the unknowingly introduced malicious code, their web browser executes the XSS payload. For instance, if the payload was `<img src=x onerror=alert('XSS')>`, the `onerror` event triggers, executing `alert('XSS')` and demonstrating the XSS vulnerability.
* Impact:
    - Execution of arbitrary JavaScript code in the browser of users who access the web project containing the AI-generated code.
    - Potential cookie theft, allowing session hijacking and unauthorized access to user accounts.
    - Redirection of users to attacker-controlled malicious websites, potentially for phishing or malware distribution.
    - Defacement of the web page, damaging the reputation and trustworthiness of the website.
    - Information disclosure if the malicious script accesses and transmits sensitive data from the user's browser or the webpage.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    - None. The provided code does not include any explicit sanitization or validation of the AI-generated code output before presenting it to the user. The application relies on the AI model to produce secure code, which is not a sufficient security measure against intentionally malicious inputs.
* Missing Mitigations:
    - Output Sanitization: Implement robust sanitization of the AI-generated code in the backend, within `backend/routes/generate_code.py` or a dedicated utility function. This sanitization should occur before the code is streamed back to the frontend. Use a security-focused HTML parser library on the backend to parse the generated HTML and remove or neutralize any potentially malicious elements, attributes (like `onerror`, `onload`, `onmouseover`, `style`, `javascript:` URLs in `href` or `src` attributes), and script tags. Libraries like DOMPurify (if available in Python, or a similar secure HTML sanitizer) could be considered.
    - Content Security Policy (CSP) Guidance: Although CSP is implemented in the user's project and not directly in this project, providing guidance or documentation recommending CSP implementation for projects that incorporate AI-generated code would be a beneficial proactive measure. However, as it is documentation, it's excluded based on instructions.
* Preconditions:
    - The user must utilize the screenshot-to-code application to generate code from an uploaded screenshot or design.
    - An attacker must successfully trick the user into using a maliciously crafted screenshot or design as input to the application.
    - The user must then integrate the resulting AI-generated code into a web project that is deployed and accessible to other users.
* Source Code Analysis:
    - Files: `backend/routes/generate_code.py`, `backend/llm.py`, `backend/codegen/utils.py`
    - Step-by-step analysis:
        1. The user uploads a screenshot via the frontend, which sends it to the backend `/generate-code` WebSocket endpoint defined in `backend/routes/generate_code.py`.
        2. The backend, in `backend/routes/generate_code.py`, extracts parameters and input image, and then calls `create_prompt` from `backend/prompts/__init__.py` to assemble the prompt for the AI model.
        3. The prompt, including the potentially malicious screenshot, is sent to the chosen LLM (OpenAI, Claude, Gemini) using functions in `backend/llm.py` such as `stream_openai_response`, `stream_claude_response`, or `stream_gemini_response`.
        4. The LLM processes the image and text prompt, generating code based on the input, which may include the malicious payload embedded in the screenshot.
        5. The raw, AI-generated code, without sanitization, is streamed back to the frontend through the WebSocket. The `process_chunk` function in `backend/routes/generate_code.py` simply forwards the chunks: `await send_message("chunk", content, variantIndex)`.
        6. The frontend receives these chunks and assembles the full code, displaying it to the user.
        7. The `extract_html_content` function in `backend/codegen/utils.py` is used to extract HTML from the AI response, but this function, as seen in `backend\codegen\utils.py`, only uses regex `re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)` to find content within `<html>` tags and does not perform any kind of sanitization.
        8. Because there is no sanitization step after receiving the code from the LLM and before presenting it to the user (or when sending `setCode` message), any malicious script generated by the AI is passed through directly.
    - Visualization:
        ```
        [Malicious Screenshot] --> Frontend --> WebSocket (/generate-code) --> Backend (routes/generate_code.py)
        --> Prompt Assembly (prompts/__init__.py) --> LLM (llm.py) --> [AI-Generated Code WITH XSS]
        --> WebSocket (routes/generate_code.py - process_chunk) --> Frontend --> User Project Integration
        --> [Vulnerable Web Project] <-- User Access
        ```
* Security Test Case:
    1. **Prepare Malicious Screenshot:** Use an image editor or a simple HTML page screenshot tool to create a PNG screenshot. This screenshot should visually resemble a normal web UI element (like a text input field or a button), but it should contain an embedded XSS payload as text within the visual representation of the element. For example, render text that looks like input field text containing: `<input type="text" value="</script><script>alert('XSS-Test')</script>">`. Save this as `malicious_screenshot.png`.
    2. **Upload Malicious Screenshot:**
        - Open the frontend of the screenshot-to-code application in a web browser (typically `http://localhost:5173` if running locally).
        - Use the application's UI to upload `malicious_screenshot.png` as the input image.
        - Select any supported stack, for example, "HTML + Tailwind".
        - Initiate code generation by clicking the "Generate Code" button.
    3. **Inspect Generated Code:**
        - Once the code generation is complete, examine the generated HTML code in the application's output panel.
        - Search for the injected XSS payload. Verify if the `<script>alert('XSS-Test')</script>` or similar malicious script is present within the generated HTML, especially within attribute values of input fields or other elements derived from the malicious content in the screenshot.
        - Example of vulnerable output:
            ```html
            ...
            <input type="text" value="</script><script>alert('XSS-Test')</script>" class="...">
            ...
            ```
    4. **Create Test HTML File:**
        - Copy the generated HTML code from the application's output panel.
        - Create a new text file named `xss_test.html` and paste the copied HTML code into it. Save the file.
    5. **Open Test File in Browser:**
        - Open the `xss_test.html` file in any web browser (e.g., Chrome, Firefox, Safari).
    6. **Verify XSS Execution:**
        - Observe if an alert dialog box appears in the browser window with the message "XSS-Test".
        - If the alert box appears, it confirms that the XSS payload from the malicious screenshot was successfully embedded in the AI-generated code and is executable in a browser, thus validating the XSS vulnerability.
