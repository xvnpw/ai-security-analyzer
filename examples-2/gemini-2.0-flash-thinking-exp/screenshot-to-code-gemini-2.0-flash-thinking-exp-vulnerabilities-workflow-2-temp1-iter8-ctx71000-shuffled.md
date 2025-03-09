## Combined Vulnerability List

This document outlines the identified vulnerabilities in the screenshot-to-code application. Each vulnerability is detailed with its description, potential impact, rank, mitigation status, preconditions, source code analysis, and a security test case.

### 1. API Key Exposure through Client-Side Settings and WebSocket Communication

* **Description:**
    1. The application allows users to input their OpenAI or Anthropic API keys via a settings dialog in the frontend.
    2. These API keys are stored in the browser's local or session storage, making them accessible to client-side scripts.
    3. When a code generation request is initiated, the frontend sends a WebSocket message to the backend.
    4. This WebSocket message includes the API key within the JSON payload as a parameter.
    5. An attacker can compromise the frontend (e.g., via Cross-Site Scripting - XSS) to extract the API key from the browser's storage.
    6. Alternatively, a Man-in-the-Middle (MITM) attacker on the WebSocket communication (if HTTPS is not enforced) can intercept messages and extract the API key from the JSON data.
    7. Once the API key is obtained, the attacker can impersonate the user and make unauthorized requests to the OpenAI or Anthropic APIs, incurring financial costs for the user.

* **Impact:**
    - **Financial Loss:** Attackers can consume the victim's API credits, leading to unexpected charges.
    - **Service Disruption:** Exhaustion of API credits by attackers can prevent legitimate users from using the application.
    - **Potential Data Exposure:** In broader scenarios, compromised API keys could lead to unauthorized access to other services or data linked to the OpenAI/Anthropic account, though less likely in this specific application.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - The application documentation mentions that "Your key is only stored in your browser. Never stored on our servers." This indicates an attempt to limit server-side exposure but relies on inherently insecure client-side storage.

* **Missing Mitigations:**
    - **Backend API Proxy:** Implement a backend proxy to handle all API calls to OpenAI and Anthropic. Securely store API keys on the backend server, preventing frontend exposure and WebSocket transmission. The frontend should communicate with this proxy.
    - **Secure WebSocket Communication (HTTPS):** Enforce HTTPS for all WebSocket communication to prevent MITM attacks that could intercept API keys.
    - **Frontend Security Measures (XSS Prevention):** Implement robust XSS prevention measures in the frontend code, including input validation, output encoding, and Content Security Policy (CSP).
    - **Regular Security Audits and Penetration Testing:** Conduct regular security assessments to identify and remediate vulnerabilities, especially related to API key management and client-side security.

* **Preconditions:**
    - User configuration of OpenAI or Anthropic API key in the application settings.
    - For XSS exploitation: Existence and exploitation of an XSS vulnerability in the frontend.
    - For MITM attack: Unencrypted WebSocket communication (no HTTPS) and attacker's ability to intercept network traffic.

* **Source Code Analysis:**
    - **`backend\routes\generate_code.py`**: The `@router.websocket("/generate-code")` endpoint handles WebSocket connections for code generation. The `extract_params` function retrieves API keys from WebSocket parameters or environment variables using `get_from_settings_dialog_or_env`. These keys are then used in functions like `stream_openai_response` and `stream_claude_response` to interact with LLM APIs.
    - **`backend\config.py`**: API keys are loaded from environment variables. However, the `generate_code.py` logic prioritizes API keys received from the frontend via WebSocket, overriding environment variables.
    - **`frontend` codebase (inferred):** The frontend likely includes a settings dialog for API key input and stores keys in browser storage (localStorage/sessionStorage). During code generation requests, the frontend retrieves the API key from storage and includes it in the WebSocket message payload to `/generate-code`.

* **Security Test Case:**
    1. **Setup:** Deploy the application locally.
    2. **Configuration:** Open the frontend in a browser and access the settings dialog to enter a valid OpenAI API key.
    3. **WebSocket Interception and Key Extraction:** Use browser developer tools to intercept WebSocket communication. Initiate code generation and observe the WebSocket request to `/generate-code`. Inspect the message payload and confirm that the OpenAI API key is transmitted as a parameter in the JSON data.
    4. **Simulate XSS and Local Storage Access (Conceptual):**  (If frontend code was fully available or XSS existed) Simulate XSS by attempting to access `localStorage` (or `sessionStorage`) using JavaScript. For example, `javascript:alert(localStorage.getItem('openAiApiKey'));`. If successful, this demonstrates how an attacker could retrieve the API key via XSS.

### 2. Cross-Site Scripting (XSS) in AI-Generated Code due to Unsanitized Screenshot Content

* **Description:**
    1. An attacker crafts a malicious screenshot containing JavaScript code disguised as text, such as `<img src=x onerror=alert('XSS Vulnerability!')>`.
    2. The attacker uploads this malicious screenshot to the application and initiates code generation.
    3. The backend AI model processes the screenshot, following instructions to "use the exact text from the screenshot".
    4. The AI model generates HTML code that includes the malicious payload verbatim, without sanitization or encoding.
    5. The application returns this generated code to the user.
    6. A user, unaware of the malicious content, copies and integrates the generated code into their web application.
    7. When a user's browser renders the code, the malicious JavaScript payload is executed, demonstrating a stored Cross-Site Scripting (XSS) vulnerability.

* **Impact:**
    - Attackers can induce the AI to generate XSS vulnerabilities.
    - Users unknowingly introduce XSS into their websites by copying and pasting generated code.
    - Exploitation of XSS can lead to:
        - Execution of arbitrary JavaScript code in users' browsers.
        - Session hijacking and cookie theft.
        - Stealing sensitive information.
        - Website defacement.
        - Redirection to malicious websites.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - None. The project lacks explicit mitigations against XSS in generated code. Code generation prioritizes accuracy over security, and there is no evidence of output encoding or sanitization in the backend.

* **Missing Mitigations:**
    - **Output Encoding/Escaping:** Implement output encoding or escaping of all text content extracted from screenshots before inclusion in generated HTML. HTML entity encoding should be used to neutralize potentially malicious HTML or JavaScript.
    - **Content Security Policy (CSP):** Include a Content Security Policy in the generated HTML to limit the capabilities of the generated code and reduce the impact of potential XSS.
    - **User Education and Warnings:** Display prominent warnings advising users to carefully review generated code for security vulnerabilities before deployment.

* **Preconditions:**
    - Application accessibility.
    - Ability to upload screenshots.
    - AI model susceptibility to including screenshot text verbatim without sanitization.
    - User deployment of generated code without security review.

* **Source Code Analysis:**
    - **`backend\prompts\__init__.py`**: The `assemble_prompt` function includes `image_data_url` in the user message to the AI.
    - **`backend\prompts\screenshot_system_prompts.py`, `imported_code_prompts.py`, `test_prompts.py`, `claude_prompts.py`**: System prompts instruct the AI to "Use the exact text from the screenshot," encouraging direct transcription of text content, potentially including malicious payloads.
    - **`backend\evals\core.py`, `backend\llm.py`, `backend\routes\generate_code.py`**: These files manage AI interaction and code retrieval. Code is passed to the frontend without sanitization.
    - **`backend\codegen\utils.py`**: The `extract_html_content` function extracts HTML but does not sanitize it.
    - **Overall Code Generation Pipeline:** No HTML sanitization or output encoding is performed on the generated code before it's sent to the user.

* **Security Test Case:**
    1. **Prepare Malicious Screenshot:** Create an image with the text `<img src=x onerror=alert('XSS Vulnerability!')>`.
    2. **Start Application:** Run backend and frontend.
    3. **Access Application:** Open browser and navigate to frontend URL.
    4. **Upload Malicious Screenshot and Generate Code:** Upload `malicious_screenshot.png`, select a technology stack, and generate code.
    5. **Copy Generated Code:** Copy the generated HTML code.
    6. **Create and Open Test HTML File:** Create `test_xss.html`, paste the generated code, and save. Open `test_xss.html` in a browser.
    7. **Observe for XSS:** Verify if an alert dialog box with "XSS Vulnerability!" appears, confirming the vulnerability.
