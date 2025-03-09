- Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code

- Description:
    1. An attacker crafts a malicious design or screenshot. This design contains text fields where the attacker inputs a JavaScript payload instead of regular text. For example, in a text field, the attacker enters: `<img src="x" onerror="alert('XSS')">`.
    2. The user uploads this malicious design or screenshot to the application.
    3. The backend AI model processes the image and generates code based on the design. Because the AI model is designed to faithfully reproduce the input design as code, it includes the attacker's JavaScript payload directly into the generated HTML code without sanitization.
    4. The backend sends the generated code containing the malicious script to the frontend via WebSocket.
    5. The frontend receives the generated HTML code and renders it in the user's browser, typically within an iframe or a similar container used to preview or display the generated code.
    6. As the browser renders the HTML, it executes the embedded JavaScript payload from the attacker. In this example, it would execute `alert('XSS')`, demonstrating the XSS vulnerability. A more sophisticated attacker could inject code that steals cookies, redirects users to malicious sites, or performs other harmful actions within the user's browser context.

- Impact:
    - Execution of malicious JavaScript code in the user's browser.
    - Potential cookie theft, session hijacking, and account compromise.
    - Redirection of users to malicious websites.
    - Defacement of the web page displaying the generated code.
    - Potential for further attacks depending on the context where the generated code is used.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. Reviewing the provided files, including `backend\prompts\screenshot_system_prompts.py`, `backend\prompts\__init__.py`, `backend\prompts\imported_code_prompts.py`, `backend\prompts\claude_prompts.py`, `backend\routes\screenshot.py`, `backend\codegen\test_utils.py`, `backend\image_processing\utils.py`, and `backend\evals\runner.py`, confirms that there are no output sanitization or encoding mechanisms implemented to prevent XSS. The system prompts in `backend\prompts\screenshot_system_prompts.py` and `backend\prompts\imported_code_prompts.py` prioritize visual accuracy and code completeness without any instructions for security. The `extract_html_content` function, as tested in `backend\codegen\test_utils.py`, simply extracts HTML without sanitization.

- Missing Mitigations:
    - Output Sanitization: The generated HTML code should be sanitized on the backend before being sent to the frontend. This can be achieved by using a library like Bleach in Python to escape or remove potentially malicious HTML tags and JavaScript code.
    - Content Security Policy (CSP): Implementing a Content Security Policy (CSP) on the frontend can help mitigate the risk of XSS by controlling the sources from which the browser is allowed to load resources. However, this is a defense-in-depth measure and not a primary mitigation for code generation vulnerabilities.

- Preconditions:
    - The attacker needs to be able to create or manipulate a design or screenshot that includes text-based input fields.
    - The user must upload and process this malicious design using the application.
    - The application must render the generated code in a web browser.

- Source Code Analysis:
    1. File: `backend\evals\core.py` and `backend\routes\generate_code.py`
        - These files contain the core logic for receiving user input (image or video), creating prompts, calling the AI model (OpenAI, Claude, Gemini), and streaming the generated code back to the frontend.
        - The code focuses on generating code accurately based on the input image and prompt, but it lacks any steps to sanitize the AI-generated output before sending it to the frontend.
        - The function `extract_html_content` in `backend\codegen\utils.py` extracts HTML content but does not perform any sanitization. It simply uses regex to find and return the content within `<html>` tags.
    2. File: `backend\prompts\screenshot_system_prompts.py`, `backend\prompts\imported_code_prompts.py`, `backend\prompts\claude_prompts.py`
        - These files define various system prompts for different tech stacks and AI models (including Claude).
        - The prompts instruct the AI to generate code based on the screenshot or imported code, focusing on visual accuracy, code completeness and following detailed instructions.
        - There is no instruction in any of the prompts to ensure output sanitization or to avoid generating potentially unsafe code. The prompts are designed to faithfully reproduce the input as code, which directly contributes to the XSS risk if malicious input is provided.
    3. Visualization:
        ```
        User Input (Malicious Screenshot) --> Backend (AI Model - No Sanitization) --> Frontend (Renders Unsanitized HTML) --> XSS Vulnerability
        ```

- Security Test Case:
    1. Prepare a malicious screenshot:
        - Create a simple image (e.g., using any image editor or even a basic drawing tool).
        - In the image, include a text element and, instead of normal text, write the following XSS payload: `<img src="x" onerror="alert('XSS-Test')">`
        - Save this image as `malicious_screenshot.png`.
    2. Start the `screenshot-to-code` application and access the frontend in your browser (usually http://localhost:5173).
    3. In the application, upload the `malicious_screenshot.png`.
    4. Select any tech stack (e.g., HTML + Tailwind).
    5. Click the "Generate Code" button.
    6. Observe the generated code preview in the application's frontend.
    7. Check if an alert box with "XSS-Test" appears in your browser.
    8. If the alert box appears, it confirms that the XSS payload from the image was successfully injected and executed in the generated code, demonstrating the vulnerability.
    9. To further confirm, inspect the generated code (e.g., using browser developer tools within the iframe or container where code is rendered). You should find the injected `<img src="x" onerror="alert('XSS-Test')">` tag in the HTML output.
