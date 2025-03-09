- **Vulnerability Name**: Uncontrolled AI Code Generation Leading to HTML/JS Injection (XSS)

  - **Description**:
    The backend accepts user‐supplied parameters (for example, in the “image”, “resultImage”, or “history” fields) without proper validation or sanitization. These inputs are used verbatim when constructing prompts for the AI model that generates HTML/JavaScript code. An attacker can craft a malicious payload (for example, a manipulated image data URL or prompt content) that causes the AI to produce output containing injected `<script>` tags or other executable JavaScript. This generated code is then extracted (using functions such as `extract_html_content()` in the codegen flow) and sent directly to the client via WebSocket without any sanitization. When the client renders this HTML (for example, by inserting it into the DOM using `innerHTML`), the malicious code will execute with the privileges of the user’s browser.

  - **Impact**:
    - **Arbitrary JavaScript Execution**: The malicious script may steal session cookies, hijack user sessions, or manipulate the DOM to display or capture sensitive information.
    - **Data Exfiltration and Phishing**: Attackers can direct users to phishing pages or silently capture personal data.
    - **UI Defacement and Redirection**: The attacker could modify the appearance of the page or redirect the user to a malicious site.

  - **Vulnerability Rank**: Critical

  - **Currently Implemented Mitigations**:
    - The code provides a permissive CORS configuration using FastAPI’s CORSMiddleware.
    - However, there is no input validation or sanitization mechanism in place for user-supplied parameters in the prompt construction (see functions in `prompts/__init__.py`) and no output encoding or filtering is applied on the generated code before it is sent to the client.

  - **Missing Mitigations**:
    - **Input Validation/Sanitization**: No checks or sanitization are performed on parameters (such as `image`, `history`, etc.) before they are packaged into prompt messages.
    - **Output Escaping/Sanitization**: The AI-generated HTML/JS is extracted and sent unmodified. There is no use of libraries like DOMPurify or similar mechanisms to strip malicious markup.
    - **Content Security Policy (CSP)**: No CSP headers are applied to mitigate the execution of inline scripts.
    - **Strict Parsing/Encoding**: The system does not enforce proper escaping when constructing the final HTML response.

  - **Preconditions**:
    - The attacker must be able to supply controlled input via the user interface or API (for example, by uploading a crafted image data URL or by manipulating the “history” parameter via imported code flows).
    - The AI model is trusted to generate HTML/JS code based solely on the provided prompt without checks against injection of malicious payloads.
    - The frontend renders the generated code without applying any sanitization or output encoding.

  - **Source Code Analysis**:
    - In **`prompts/__init__.py`**, the function `create_prompt()` constructs the prompt messages based directly on user-provided parameters (such as `params["image"]`, `params["resultImage"]`, and `params["history"]`) without any sanitization.
    - The helper function **`assemble_prompt()`** builds a content array that embeds the unsanitized `image_data_url` along with a static text prompt.
    - In **`backend/routes/generate_code.py`**, after receiving the AI-generated result, the function `extract_html_content()` is used to pull the HTML portion from the model’s response. This message (which could contain malicious scripts) is then sent to clients via the WebSocket channel (using the `send_message()` helper), with no subsequent sanitization.
    - The absence of any escaping or filtering before inserting this HTML into the DOM (in the frontend) makes it possible for injected scripts to execute.

  - **Security Test Case**:
    1. **Setup**:
       - Deploy the backend and frontend so that the code generation endpoint (WebSocket `/generate-code`) is accessible.
       - Intercept a client request (using a proxy tool like Burp Suite) that sends the code generation parameters.
    2. **Test Steps**:
       - Craft a payload where the attacker’s controlled field (for example, an `image` parameter or an entry in `history`) contains a malicious value designed to trick the AI model into outputting HTML containing a `<script>alert("XSS")</script>` snippet.
       - Send this manipulated payload to the `/generate-code` endpoint.
       - Capture the AI-generated output as it is transmitted over the WebSocket.
       - On a test client, simulate rendering the returned HTML (by inserting the content into a page element via `innerHTML`).
    3. **Verification**:
       - Observe if the malicious `<script>` executes (e.g., an alert dialog appears or the browser console logs unexpected script execution).
       - Confirm that the HTML output contains unsanitized script tags.
       - Document that the lack of input/output sanitization leads to client-side XSS.

Implementing proper input validation, output sanitization, and a strict Content Security Policy is recommended to mitigate this vulnerability.
