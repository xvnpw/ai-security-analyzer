- **Vulnerability Name:** Prompt Injection Leading to Malicious Code Generation
  **Description:**
  An attacker can supply a specially crafted screenshot “image” input (via its data URL) that is not a regular base64-encoded image but has been manipulated to include extra text or HTML/JavaScript instructions. In the function `assemble_prompt` (located in **backend/prompts/__init__.py**), the user‐supplied `image_data_url` is inserted directly into the “user” message without further sanitization. As a result, a malicious data URL containing payloads (for example, a base64 string ending with `...<script>alert('XSS')</script>`) can “leak” into the prompt sent to the language model. The manipulated prompt may force the AI to generate HTML/JS code that embeds the injected script. When this generated code is subsequently rendered in a user’s browser, the malicious script may execute, causing cross‐site scripting (XSS) attacks or other client‑side compromises.

  **Impact:**
  - **Code generation abuse:** The AI may output code that includes hidden malicious payloads.
  - **Client-side XSS:** If the generated code (possibly containing payloads) is rendered in the browser, it can execute arbitrary JavaScript, allowing session hijacking, data exfiltration, or defacement.
  - **Compromise trust:** Users of the application may be exposed to attacks if malicious generated code is served to them.

  **Vulnerability Rank:** Critical

  **Currently Implemented Mitigations:**
  - The system uses fixed system prompt text (loaded from predefined files in **prompts/screenshot_system_prompts.py**); however, it does not sanitize the variable portion derived from the user input.

  **Missing Mitigations:**
  - No input validation is performed on the user-supplied data URL.
  - The project does not separate trusted system instructions from untrusted user data when forming the final prompt.
  - A whitelist or regular expression check (ensuring only valid base64 image strings are accepted) is missing.

  **Preconditions:**
  - The endpoint that accepts screenshot or design input is publicly accessible.
  - The attacker is able to supply a maliciously crafted “image” value (data URL) via the client (or API request).

  **Source Code Analysis:**
  - In **backend/prompts/__init__.py**, the helper function `assemble_prompt(image_data_url, stack, result_image_data_url)` builds its user message as follows:
    ```python
    user_content = [
        {
            "type": "image_url",
            "image_url": {"url": image_data_url, "detail": "high"},
        },
        {
            "type": "text",
            "text": user_prompt,
        },
    ]
    ```
    There is no verification that `image_data_url` strictly conforms to a proper base64‑encoded image. Consequently, if an attacker crafts a data URL that includes additional text (for example, appended `<script>` tags), that text will be sent unaltered as part of the prompt.
  - The unsanitized input is then passed to the language model, which uses it to generate code. If the model “follows” the injected instructions, the resulting code can embed a malicious payload.

  **Security Test Case:**
  1. Deploy the application and navigate to the code‑generation input area.
  2. Prepare a malicious data URL (ensure it is syntactically valid as a data URL) that, when decoded, includes a payload—for example, use a valid image base64 prefix and append something like `<script>alert('XSS')</script>`.
  3. Submit the request (or use a tool such as Postman to send a request with the “image” parameter set to the crafted data URL).
  4. Intercept the generated output (HTML/JS code) either by monitoring responses or by viewing the generated code in a testing environment.
  5. Verify whether the output code includes the injected script.
  6. Finally, load the generated page in a controlled browser session to check for execution (e.g., an alert box).
  7. Document and report any execution of injected code.
