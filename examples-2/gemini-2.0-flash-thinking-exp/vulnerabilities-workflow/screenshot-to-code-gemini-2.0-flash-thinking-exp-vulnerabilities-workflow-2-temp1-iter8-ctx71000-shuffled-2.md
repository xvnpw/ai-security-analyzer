### Vulnerability List

- Vulnerability Name: Potential XSS in Generated Code due to Unsanitized Screenshot Content
- Description:
    1. An attacker crafts a malicious screenshot image. This image contains text that is actually a JavaScript payload, for example: `<img src=x onerror=alert('XSS Vulnerability!')>`.
    2. The attacker uses the "screenshot-to-code" application and uploads this malicious screenshot.
    3. The attacker selects a technology stack (e.g., HTML + Tailwind) and initiates the code generation process.
    4. The backend processes the screenshot using an AI model (like GPT-4 Vision or Claude).
    5. The AI model, following instructions to "use the exact text from the screenshot", generates HTML code that includes the malicious payload verbatim, for example:
       ```html
       <html>
       <body>
       <p>This is some text <img src=x onerror=alert('XSS Vulnerability!')> on the screenshot.</p>
       </body>
       </html>
       ```
    6. The application returns this generated code to the user.
    7. A user, without carefully reviewing the generated code, copies and integrates it into their web application.
    8. When a user's browser renders the code, the malicious JavaScript payload `<img src=x onerror=alert('XSS Vulnerability!')>` is executed, triggering an alert box that says "XSS Vulnerability!". This demonstrates a stored Cross-Site Scripting (XSS) vulnerability.
- Impact:
    - An attacker can induce the AI to generate code containing XSS vulnerabilities.
    - If a user naively copies and pastes the generated code into their website, they will unknowingly introduce an XSS vulnerability.
    - Successful exploitation of this XSS vulnerability could allow an attacker to:
        - Execute arbitrary JavaScript code in users' browsers.
        - Hijack user sessions.
        - Steal sensitive information.
        - Deface the website.
        - Redirect users to malicious websites.
        - Perform other malicious actions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided project files do not include any explicit mitigations against XSS in the generated code. The focus is on code generation accuracy rather than security. There is no evidence of output encoding or sanitization in the backend code.
- Missing Mitigations:
    - Output Encoding/Escaping: The application should implement output encoding or escaping of any text content extracted from the screenshot before including it in the generated HTML. This would neutralize any potentially malicious HTML or JavaScript code within the screenshot text. For HTML context, HTML entity encoding should be used.
    - Content Security Policy (CSP): The generated HTML code could include a Content Security Policy to limit the capabilities of the generated code. While CSP is not a primary mitigation for XSS, it can significantly reduce the impact of XSS vulnerabilities by restricting the sources from which scripts can be loaded and other actions.
    - User Education and Warnings: The application should display a prominent warning to users, advising them to carefully review the generated code before deploying it. This warning should highlight the potential for security vulnerabilities, including XSS, and recommend manual security review and testing of the generated code.
- Preconditions:
    - The application must be running and accessible to the attacker.
    - The attacker needs to be able to upload a screenshot to the application.
    - The AI model used by the application must be susceptible to including text from the screenshot directly into the generated code without sufficient sanitization.
    - A user must copy and deploy the generated code without proper security review.
- Source Code Analysis:
    1. `backend\prompts\__init__.py`: The `assemble_prompt` function constructs the prompt for the AI model. It includes the `image_data_url` in the prompt's user message.
    2. `backend\prompts\screenshot_system_prompts.py`: System prompts, like `HTML_TAILWIND_SYSTEM_PROMPT`, instruct the AI model with directives such as "Use the exact text from the screenshot." This instruction encourages the AI to directly transcribe text content from the screenshot into the generated code, which can include malicious payloads if the screenshot is crafted maliciously.
    3. `backend\evals\core.py` and `backend\llm.py`: These files handle the interaction with the AI model and retrieve the generated code. The code is then passed back to the frontend without any intermediate sanitization or security checks.
    4. `backend\codegen\utils.py`: The `extract_html_content` function extracts HTML from the AI's response, but it does not sanitize or encode the HTML content. It simply extracts the content within `<html>` tags, or returns the full text if `<html>` tags are not found.
    5. Throughout the code generation pipeline in the backend, there is no evidence of any HTML sanitization or output encoding being performed on the generated code before it's returned to the user. This absence of sanitization makes the application vulnerable to XSS if malicious content is introduced via the screenshot.
- Security Test Case:
    1. **Prepare Malicious Screenshot:**
        - Create a new image (e.g., using an image editor or a simple drawing tool).
        - Add the following text to the image: `<img src=x onerror=alert('XSS Vulnerability!')>` . Ensure this text is clearly visible in the image.
        - Save the image as `malicious_screenshot.png`.
    2. **Start the Application:**
        - Navigate to the `screenshot-to-code\backend` directory in a terminal.
        - Run the backend using `poetry run uvicorn main:app --reload --port 7001` (or the preferred method to start the backend).
        - Navigate to the `screenshot-to-code\frontend` directory in another terminal.
        - Run the frontend using `yarn dev` (or the preferred method to start the frontend).
        - Ensure both backend and frontend are running without errors and accessible.
    3. **Access the Application in Browser:**
        - Open a web browser and go to http://localhost:5173 (or the frontend URL).
    4. **Upload Malicious Screenshot and Generate Code:**
        - In the application, use the image upload functionality.
        - Upload the `malicious_screenshot.png` file.
        - Select any supported technology stack from the dropdown (e.g., "HTML + Tailwind").
        - Click the "Generate Code" button.
    5. **Copy Generated Code:**
        - Once the code generation is complete, locate the generated code output area in the application's frontend.
        - Copy the entire generated HTML code to your clipboard.
    6. **Create and Open Test HTML File:**
        - Create a new text file named `test_xss.html`.
        - Paste the copied generated HTML code into `test_xss.html`.
        - Save the file.
        - Open `test_xss.html` in a web browser (e.g., by double-clicking the file or dragging it into a browser window).
    7. **Observe for XSS:**
        - Check if an alert dialog box appears in the browser window with the message "XSS Vulnerability!".
        - If the alert box appears, it confirms that the XSS payload from the malicious screenshot was successfully included in the generated code and executed by the browser, thus demonstrating the XSS vulnerability.

If the alert box appears, the vulnerability is **confirmed**.
