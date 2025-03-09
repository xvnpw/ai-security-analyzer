- Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code
- Description:
    1. An attacker crafts a screenshot or UI design that includes malicious JavaScript code embedded within it, for example, within the text content of a button or link, or as part of an image's alt text.
    2. A user uploads this crafted screenshot to the application to convert it into frontend code.
    3. The backend AI processes the screenshot and generates HTML, CSS, and JavaScript code based on the visual information in the screenshot. Critically, the AI models (like GPT-4o or Claude Sonnet) will faithfully reproduce the text content from the screenshot, including the malicious JavaScript code, and embed it directly into the generated code.
    4. The backend sends this generated code, which now contains the attacker's malicious script, to the frontend via a WebSocket.
    5. The frontend receives the AI-generated code and dynamically renders it in the user's browser.
    6. Because the malicious JavaScript code from the attacker's screenshot is included in the generated HTML and is not sanitized, it executes within the user's browser as part of the rendered web page.
    7. This allows the attacker to execute arbitrary JavaScript code in the context of the user's session, leading to Cross-Site Scripting.

- Impact:
    - Session Hijacking: An attacker can steal the user's session cookies or tokens, gaining unauthorized access to the application and the user's account.
    - Data Theft: Malicious scripts can extract sensitive data entered by the user or displayed on the page and send it to a server controlled by the attacker.
    - Account Takeover: By hijacking the session, the attacker can fully control the user's account and perform actions on their behalf.
    - Redirection to Malicious Sites: The script can redirect the user to a malicious website, potentially for phishing or malware distribution.
    - Defacement: The attacker can modify the content of the web page, displaying misleading or harmful information to the user.
    - Further Exploitation: XSS is often a stepping stone for more complex attacks, potentially allowing for further compromise of the user's system or data.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - There are no explicit sanitization mechanisms implemented in the provided backend code to sanitize the AI-generated code before sending it to the frontend.
    - The function `extract_html_content` in `backend/codegen/utils.py` only extracts the HTML content and does not perform any sanitization.
    - The code generation logic in `backend/routes/generate_code.py` and `backend/llm.py` focuses on generating code based on the prompt and does not include any output sanitization steps.

- Missing Mitigations:
    - Backend-side HTML Sanitization: Implement a robust HTML sanitization library (e.g., DOMPurify for Python) on the backend. Before sending the AI-generated HTML code to the frontend, sanitize it to remove or neutralize any potentially malicious JavaScript or HTML elements. This should be applied in the `stream_code` function within `backend/routes/generate_code.py` right before sending the `setCode` message to the frontend.
    - Content Security Policy (CSP): Implement a Content Security Policy to limit the sources from which the browser is allowed to load resources and execute scripts. While CSP can help mitigate XSS, it is not a complete solution on its own and should be used in conjunction with output sanitization.

- Preconditions:
    - The application must be running and accessible to the attacker.
    - The user must use the application to upload a screenshot or UI design.
    - The attacker must be able to craft a screenshot containing malicious JavaScript code that will be faithfully reproduced by the AI model.
    - The user's browser must execute JavaScript for the XSS payload to be effective.

- Source Code Analysis:
    1. **File: `backend\codegen\utils.py`**:
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
        - The `extract_html_content` function is used to extract the HTML code from the AI's response. It uses a regular expression to find and return the content within `<html>` tags.
        - **Crucially, this function performs no sanitization.** It simply extracts the HTML string as is, without any checks for malicious scripts or elements.

    2. **File: `backend\routes\generate_code.py`**:
        ```python
        @router.websocket("/generate-code")
        async def stream_code(websocket: WebSocket):
            # ... [code to receive parameters, generate code using AI] ...

            completions = [extract_html_content(completion) for completion in completions]

            # ... [code to send code to frontend via websocket] ...

            for index, updated_html in enumerate(updated_completions):
                await send_message("setCode", updated_html, index)
                # ...
        ```
        - In the `stream_code` WebSocket endpoint, the generated code from the AI models is processed by `extract_html_content`.
        - As highlighted above, `extract_html_content` does not sanitize the HTML.
        - The extracted HTML (`updated_html`) is then directly sent to the frontend using the `setCode` message.
        - **There is no sanitization step before sending the code to the frontend.** This means if the AI generates code containing malicious scripts (because they were present in the input screenshot), these scripts will be sent to the frontend without any modification.

    3. **File: `backend\llm.py` and `backend\prompts\*.py`**:
        - These files are responsible for interacting with the LLMs and crafting prompts. The prompts themselves do not introduce sanitization, and the LLM responses are treated as safe HTML strings, which is a dangerous assumption when dealing with user-provided input screenshots.
        - The LLMs are designed to faithfully reproduce content from the input image, so if malicious scripts are visually present in the screenshot, the LLM will likely include them in the generated code.

    **Visualization:**

    ```
    [Screenshot with XSS] --> [Backend API Endpoint] --> [AI Model (GPT-4o, Claude)] --> [Generated Code (with XSS)] --> [extract_html_content (NO SANITIZATION)] --> [WebSocket 'setCode' Message] --> [Frontend] --> [Browser Renders Code & Executes XSS]
    ```

- Security Test Case:
    1. **Preparation:**
        - Create a simple HTML file named `xss_payload.html` with the following content. This file contains a basic JavaScript alert for testing XSS:
          ```html
          <div id="xss-test">
              <h1>This is a test UI with a button containing XSS payload</h1>
              <button onclick="alert('XSS Vulnerability Triggered!')">Click Me with XSS</button>
          </div>
          ```
        - Take a screenshot of this `xss_payload.html` file. Save the screenshot as `xss_screenshot.png`.

    2. **Application Interaction:**
        - Open the Screenshot to Code application in a web browser (e.g., `http://localhost:5173` if running locally).
        - In the application, select "HTML + Tailwind" (or any other HTML-based stack) as the desired output.
        - Upload the `xss_screenshot.png` file to the application.
        - Click the "Generate Code" button.
        - Wait for the AI to process the screenshot and generate the code.

    3. **Verification:**
        - Once the code generation is complete, observe the preview pane in the application or copy the generated code and open it in a new browser window.
        - **Expected Result:** Upon loading the generated code, or clicking on the "Click Me with XSS" button in the preview, an alert box should appear in the browser window displaying the message "XSS Vulnerability Triggered!".
        - If the alert box appears, this confirms that the malicious JavaScript code from the screenshot was successfully embedded in the AI-generated code and executed in the browser, demonstrating a Cross-Site Scripting vulnerability.

    4. **Cleanup:**
        - Close the alert box and the browser window used for testing.

This test case demonstrates how an attacker can inject JavaScript code via a screenshot, which the application then blindly incorporates into the generated HTML, leading to XSS.
