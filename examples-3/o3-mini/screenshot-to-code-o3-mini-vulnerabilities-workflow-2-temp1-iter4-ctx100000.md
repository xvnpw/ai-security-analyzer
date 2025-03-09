# Combined Vulnerabilities List

Below are the consolidated, high‐severity vulnerabilities extracted from the provided lists. Duplicate findings have been merged so that each unique vulnerability is described only once with all available details.

---

## 1. Prompt Injection Leading to Malicious Code Generation and XSS

### Description
An attacker can supply a specially crafted screenshot or prompt input that is not a standard base64-encoded image but is manipulated to include extra HTML/JavaScript payloads. In the function `assemble_prompt` (located in **backend/prompts/__init__.py**), the user-supplied `image_data_url` is directly embedded into the prompt message without additional sanitization. Consequently, a malicious data URL (for example, one that starts as a valid base64 image string and ends with malicious `<script>` tags) can leak into the prompt sent to the language model. If the AI model “follows” these injected instructions, it may generate HTML/JS code with the dangerous payload. Further downstream, the generated code is processed by utility functions (like the regex‑based function `extract_html_content` in **codegen/utils.py**) and then sent over a WebSocket to be rendered in the user’s browser without proper output encoding, opening the door to client-side cross-site scripting (XSS).

### Impact
- **Code Generation Abuse:** The AI may include hidden malicious payloads in its generated code.
- **Client-side XSS:** When the generated HTML/JS is rendered, it can execute arbitrary JavaScript—leading to session hijacking, data exfiltration, or even complete site defacement.
- **User Trust Compromise:** Users interacting with the application risk exposure to injected code that can alter client behavior, undermine security, and damage the application's reputation.

### Vulnerability Rank
**Critical**

### Currently Implemented Mitigations
- The system loads a fixed system prompt from predefined files (e.g., in **prompts/screenshot_system_prompts.py**) and uses a regex-based extraction (via `extract_html_content`) to isolate `<html>` content from the AI response.
- However, these mitigations do not sanitize the unsanitized, user-driven portion of the prompt nor apply robust output encoding before rendering.

### Missing Mitigations
- **Input Validation:** No verification is performed to ensure the supplied data URL conforms strictly to a valid base64 image format.
- **User/System Separation:** The project does not separate trusted system instructions from untrusted user data when assembling the final prompt.
- **Output Sanitization & CSP:** There is no robust output encoding, whitelisting, or Content Security Policy (CSP) applied when rendering the generated HTML/JavaScript.
- **Strict Data Checks:** A regular expression or whitelist check to enforce image data format is missing.

### Preconditions
- The endpoint that accepts screenshot data or design inputs is publicly accessible.
- The attacker must be able to supply a maliciously crafted “image” (data URL) via the client interface or API.
- In alternative attack scenarios, the attacker might also manipulate prompt inputs via the front‑end settings dialog, allowing malicious text (e.g., closing HTML tags followed by `<script>` payloads).

### Source Code Analysis
1. **Prompt Assembly:**
   In **backend/prompts/__init__.py**, the function `assemble_prompt(image_data_url, stack, result_image_data_url)` constructs the user message as:
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
   There is no check ensuring that `image_data_url` is a proper base64‑encoded image.

2. **LLM Interaction:**
   The unsanitized `image_data_url` is then incorporated into the prompt sent to the AI. Should the payload include injected HTML/JS, the language model may generate code that embeds the malicious script.

3. **Response Processing & Rendering:**
   The generated response is subsequently processed by the function `extract_html_content` (e.g., in **codegen/utils.py**), which uses a basic regex to capture everything between `<html>` tags. Finally, **routes/generate_code.py** transmits the dangerous code over a WebSocket to be rendered in the client’s browser, completing the exploit chain.

### Security Test Case
1. **Deploy the Application:** Run the application in a controlled test environment ensuring the frontend is publicly accessible.
2. **Craft Malicious Input:**
   - Prepare a valid data URL with a proper base64 image prefix.
   - Append a payload such as `<script>alert('XSS')</script>` to the string.
3. **Submit the Request:**
   - Use the application’s screenshot input or settings dialog to submit the crafted data URL.
   - Alternatively, replicate the API call using a tool like Postman.
4. **Monitor the Output:**
   - Capture the AI-generated code (via intercepted responses or logging) and inspect it for the presence of the malicious `<script>` tag.
5. **Test in Browser:**
   - Render the generated code in a controlled browser session.
   - Observe whether the injected script executes (e.g., an alert box appears).
6. **Document Findings:** Confirm if the attack vector allows execution of arbitrary code, and report the vulnerability.

---

## 2. Server‑Side Request Forgery (SSRF) via Configurable API Base URL

### Description
The application reads the API base URL for OpenAI—along with similar endpoints for other providers—from environment variables (or via a settings dialog) and passes it directly into the AI client libraries. Since these values are not validated or sanitized, an attacker with access to the settings interface (or who can forge WebSocket requests with custom parameters) can supply a malicious URL. By replacing a legitimate API endpoint with an internal IP or other internal resource URL (e.g., `http://127.0.0.1:80/v1` or `http://192.168.1.100:8000/v1`), the attacker coerces the backend into sending API calls to unintended destinations. This may facilitate subsequent internal reconnaissance, data exfiltration, or further exploitation of internal services.

### Impact
- **Internal Service Access:** The backend may be manipulated into issuing requests to internal or restricted services not intended for external access.
- **Data Exposure:** Sensitive internal data or information about network structure may be disclosed.
- **Backend Compromise:** An attacker could leverage these unauthorized requests to execute further attacks using the backend as a proxy.

### Vulnerability Rank
**Critical**

### Currently Implemented Mitigations
- The application relies on environment variables (or settings dialogs) to configure the `OPENAI_BASE_URL`. The README and documentation provide configuration guidance, but at runtime, no validation is performed on these values.
- The URL parameter is read and passed directly to the OpenAI client libraries (e.g., via **backend/config.py** and **backend/llm.py**) without enforcing a whitelist or performing any sanitization.

### Missing Mitigations
- **Input Validation:** There is no check to ensure that the provided URL is well-formed or belongs to an allowed list of domains.
- **Endpoint Restrictions:** There is no mechanism to block URLs targeting private, loopback, or internal IP addresses.
- **Network Controls:** Lack of egress filtering means the backend can make outbound requests to arbitrary endpoints.
- **User Override Protections:** In production deployments, the project does not sufficiently restrict or require additional authorization for user-supplied overrides of critical parameters.

### Preconditions
- The attacker must have the ability to modify the `OPENAI_BASE_URL` parameter—either by accessing the frontend settings dialog or by tampering with the deployment’s environment variables.
- The backend must be configured to use the user-supplied API endpoint.
- Network policies permit the backend to reach internal or attacker-controlled endpoints.

### Source Code Analysis
1. **Configuration Retrieval:**
   In **backend/config.py**, the API base URL is obtained without sanitization:
   ```python
   OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", None)
   ```

2. **Client Initialization:**
   In **backend/llm.py**, the function `stream_openai_response()` instantiates the AI client with the supplied base URL:
   ```python
   client = AsyncOpenAI(api_key=api_key, base_url=base_url)
   ```
   No sanity checks are applied to the `base_url` before it is used.

3. **Routing of Parameters:**
   In **backend/routes/generate_code.py**, the value is passed along from user inputs or environment configuration directly to the AI client, enabling an attacker to force the usage of a malicious URL.

### Security Test Case
1. **Prepare a Test Instance:**
   - Deploy the application so that the frontend is publicly accessible.
2. **Supply a Malicious URL:**
   - Via the frontend settings dialog or by modifying the backend’s `.env` file, set the `OPENAI_BASE_URL` to an internal or attacker-controlled endpoint (e.g., `http://127.0.0.1:8000/v1`).
3. **Trigger an API Request:**
   - Initiate a code generation request using the application’s interface.
4. **Monitor Outbound Requests:**
   - Check the logs or network traffic on the attacker-controlled endpoint to verify that the backend is sending API requests to the malicious URL.
5. **Confirm Exploitation:**
   - If the backend directs its API calls to the supplied URL rather than the legitimate OpenAI API, the SSRF vulnerability is validated.
```

---

*Note: Only vulnerabilities with complete descriptions—including step-by-step source code analysis and security test cases—are included. Vulnerabilities that are theoretical, lack detailed mitigation steps, or present as documentation issues have been excluded as per the provided guidelines.*
