- **Vulnerability Name:** Malicious Prompt Injection Leading to XSS via AI Code Generation
  **Description:**
  An attacker can supply a maliciously crafted screenshot or manipulate prompt inputs so that the AI model is induced to generate HTML/JavaScript code containing harmful script payloads. Because the project builds the final application code by embedding the LLM output (using functions such as “assemble_prompt” and “extract_html_content”) without proper sanitization or output encoding, the generated code might include unexpected `<script>` tags or other dangerous markup. When the resulting code is rendered on the client, this can lead to cross‑site scripting (XSS).
  **Impact:**
  - Execution of arbitrary JavaScript in end‑user browsers.
  - Session hijacking, data exfiltration, or defacement of the rendered page.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The code uses a simple extraction method (via the regex‑based function `extract_html_content`) to isolate `<html>`–tag content from the AI response.
  - No additional sanitization is applied once the generated code is received.
  **Missing Mitigations:**
  - No robust input validation/sanitization of the user‑supplied screenshot data or prompt payload modifications.
  - No output encoding or Content Security Policy (CSP) is applied before rendering the generated code in the browser.
  **Preconditions:**
  - The attacker must be able to supply a specially crafted screenshot or manipulate front‑end prompt inputs (via the settings dialog or API) so that the prompt injected to the AI model carries malicious text (for example, including closing HTML tags followed by `<script>` payloads).
  **Source Code Analysis:**
  - In **`backend/prompts/__init__.py → assemble_prompt`**, the provided image “data URL” and a fixed user prompt are directly packaged into a message object sent to the LLM.
  - The generated response is then processed by **`codegen/utils.py → extract_html_content`**, which simply searches for `<html>…</html>` without sanitizing the content inside.
  - Finally, in **`routes/generate_code.py`**, the (potentially dangerous) HTML code is sent over a WebSocket to the client and rendered without further checks.
  **Security Test Case:**
  1. Deploy the application locally (run the backend and frontend as described in the README).
  2. In the screenshot input or settings dialog, submit an image or prompt that embeds malicious text—for example, a crafted image whose associated metadata or “alt” text includes:
     ```
     </html><script>alert('XSS')</script>
     ```
  3. Trigger code generation via the application interface.
  4. When the generated code is returned and rendered in a browser, observe whether the alert box appears (or verify via the console that unexpected script code is present).
  5. Confirm that implementing proper input sanitization and output encoding (or a strict CSP) prevents this script from executing.
