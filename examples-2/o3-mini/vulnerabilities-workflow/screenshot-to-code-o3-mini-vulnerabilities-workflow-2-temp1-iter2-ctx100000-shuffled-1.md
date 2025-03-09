1. **Vulnerability Name:** Cross‐Site Scripting (XSS) via Malicious AI‐Generated Code

   - **Description:**
     An attacker can supply a maliciously crafted screenshot or design input (for example, by embedding specially crafted data in the image’s metadata or the “alt” text used when constructing prompts) so that the AI model is tricked into generating HTML/JS code that embeds unexpected script or HTML payloads. When a victim later views or loads the generated code in their browser—such as via the hosted project or a downloaded HTML file—the malicious payload is rendered and executed.
     **Step-by-step trigger:**
     1. The attacker prepares a design mockup (or image file) whose accompanying descriptive text (or injected metadata) includes an XSS payload (e.g. a string containing `<script>alert('XSS');</script>`).
     2. The attacker uploads this image/design input using the project’s front-end interface or API (for example, by using the settings dialog that accepts an image and sending the input via WebSocket to the `/generate-code` endpoint).
     3. During prompt assembly (in functions like `assemble_prompt` in the backend's `prompts/__init__.py`), the malicious text is pasted into the prompt data sent to the AI.
     4. The AI (which is not aware that the input is tainted) generates code that includes the injected script payload.
     5. The backend extracts code between `<html>...</html>` (using for instance the regex in `extract_html_content`) and then sends this code unaltered via WebSocket to the client.
     6. When a victim renders this generated HTML in their browser, the malicious script is executed.

   - **Impact:**
     An attacker who succeeds can force arbitrary JavaScript execution in the context of any user’s browser that loads the resulting page. This could allow hijacking of session data, defacement of the rendered page, theft of cookies or other sensitive information, and further spread of the attack through phishing or drive-by downloads.

   - **Vulnerability Rank:** Critical

   - **Currently Implemented Mitigations:**
     - The project uses a “prompt assembly” mechanism to standardize the generation process (for example by always prepending a fixed system and user prompt).
     - The backend extracts and returns only the content between `<html>...</html>` tags from the AI’s output.

     However, no explicit sanitization or filtering is applied to the user‐supplied image metadata or to the final AI-generated HTML before it is sent to the client.

   - **Missing Mitigations:**
     - **Input validation and sanitization:** There is no mechanism to validate or clean the descriptive text (such as values provided in alt text or embedded in parameters) that is used to build the AI prompt.
     - **Output sanitization:** The generated HTML output is not sanitized or “escaped” before being sent to the browser.
     - **Content Security Policy (CSP):** No strict CSP is enforced at the client side to block inline scripts.
     - **Strict parsing of generated code:** The backend simply uses regex extraction (in `extract_html_content`) and does not verify whether unexpected script tags are present.

   - **Preconditions:**
     - The attacker must be able to supply a design input (screenshot or mockup) with malicious payload embedded in its descriptive text or metadata.
     - The output of the AI model must be rendered in a victim’s browser without subsequent sanitization.
     - The application’s front-end or hosting environment must render or display the AI-generated code (for example, in a live preview or via a downloaded HTML file).

   - **Source Code Analysis:**
     - In `backend/prompts/__init__.py` within the function `assemble_prompt`, the application constructs the prompt messages by combining a system prompt (which is a trusted fixed string) with a user message that includes the image URL and accompanying text (e.g. the default `USER_PROMPT` or `SVG_USER_PROMPT`). There is no sanitation or filtering applied to the “image” parameter or any additional user-supplied properties (such as alt text).
     - Later in the generation flow (for example, in the `/generate-code` WebSocket route in `backend/routes/generate_code.py`), the service passes on the prompt to the AI model and then extracts the code output using a utility (`extract_html_content` in `codegen/utils.py`). This extraction simply searches for a block surrounded by `<html>` and `</html>` without any additional filtering.
     - Finally, the unsanitized code is sent via a WebSocket “setCode” message to the client for rendering. If the AI output includes embedded `<script>` tags (for example, as a result of prompt injection by a malicious image), those tags will be part of the content that the client-side application displays.

   - **Security Test Case:**
     1. **Preparation:**
        - Set up a local or hosted instance of the application with a publicly accessible front-end.
     2. **Triggering the Vulnerability:**
        - Craft an image or mockup file (or simulate one) whose accompanying descriptive text (for example, in the “alt” text field provided during the upload) includes an XSS payload (e.g., `"><script>alert('XSS');</script>`).
        - Upload this image or supply it as input via the settings dialog so that it is used in the prompt to the AI model.
     3. **Observation:**
        - Allow the backend to process the image and generate code using the AI model.
        - Retrieve the generated HTML code (either through the WebSocket channel or by accessing the hosted version’s preview).
     4. **Verification:**
        - Save the generated HTML to a file and open it in a test browser.
        - Confirm that the injected `<script>` block executes (for example, by observing an alert box or by instrumenting the browser’s console).
        - Alternatively, use an automated web-security scanner or manual testing with developer tools to confirm that inline scripts exist in the generated output.
     5. **Cleanup:**
        - Remove the test files and restore any test environment settings.
