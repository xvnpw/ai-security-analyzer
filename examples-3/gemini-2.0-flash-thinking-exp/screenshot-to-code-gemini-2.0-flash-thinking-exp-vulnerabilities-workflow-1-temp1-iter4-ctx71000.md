## Combined Vulnerability List

This document outlines the identified vulnerabilities, combining information from multiple reports and removing duplicates.

### 1. Cross-Site Scripting (XSS) via LLM Generated Code

* **Description:**
    1. An attacker sends a request to the `/generate-code` websocket endpoint, providing an image or video to be converted into code.
    2. The backend application utilizes an LLM (like GPT-4 Vision or Claude) to generate HTML, CSS, and JavaScript code based on the input.
    3. The LLM, in certain scenarios, might generate code containing malicious JavaScript. This can occur if the LLM's training data included XSS vulnerability examples or if the prompt is manipulated (though prompts are hardcoded in this project).
    4. The backend processes the LLM response, extracts HTML code (using regex which is prone to bypasses) with the `extract_html_content` function in `backend\codegen\utils.py`, and sends this generated code to the frontend via websocket.
    5. The frontend renders this generated HTML in the user's browser.
    6. If the HTML contains malicious JavaScript, it executes in the user's browser within the application's origin, potentially enabling actions like stealing cookies, user redirection, or website defacement.

* **Impact:**
    - Account Takeover: Stealing session cookies or sensitive information can lead to account compromise.
    - Data Theft: Malicious scripts can extract application or browser data and send it to attacker-controlled servers.
    - Website Defacement: Attackers can alter webpage content, redirect users, or inject phishing forms.
    - Malware Distribution: Injected scripts can distribute malware to application users.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - None: No explicit sanitization or Content Security Policy (CSP) is in place to prevent XSS. The `extract_html_content` function in `backend\codegen\utils.py` uses regex for HTML extraction, which is not a security measure and is easily bypassed. It is intended for content extraction, not sanitization.

* **Missing Mitigations:**
    - HTML Sanitization: Implement robust HTML sanitization on the backend before sending generated code to the frontend. Libraries like DOMPurify (JavaScript frontend) or bleach (Python backend) can be used to neutralize harmful HTML, CSS, and JavaScript.
    - Content Security Policy (CSP): Implement a strict CSP to control browser resource loading and execution, significantly mitigating XSS by preventing inline script execution and restricting script sources.
    - Input Validation and Output Encoding: While the primary issue is LLM output, input validation for `/generate-code` parameters and output encoding for other dynamic content provides defense-in-depth.

* **Preconditions:**
    - Publicly accessible application with a running backend service handling `/generate-code` websocket requests.
    - User interaction to provide an image or video and trigger the code generation process.

* **Source Code Analysis:**
    1. **Entry Point:** `/generate-code` websocket endpoint in `backend\routes\generate_code.py`.
    2. **Code Generation:** `stream_code` function in `backend\routes\generate_code.py` processes websocket connections, extracts parameters, creates prompts, and uses `stream_openai_response` or `stream_claude_response` from `backend\llm.py` to interact with LLMs and get code.
    3. **HTML Extraction:** `extract_html_content` function in `backend\codegen\utils.py` processes LLM responses (expected HTML code). It uses regex `r"(<html.*?>.*?</html>)"` to extract content within `<html>` tags.
        ```python
        # backend\codegen\utils.py
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
        If the regex fails, the function returns the original text unsanitized. Even if successful, extracted HTML isn't sanitized.
    4. **Image Generation (Optional):** `generate_images` in `backend\image_generation\core.py` replaces placeholder image URLs. Not directly XSS related, but part of the pipeline.
    5. **Frontend Response:** Generated HTML is sent to the frontend via websocket using `setCode` message type in `backend\routes\generate_code.py`.
        ```python
        # backend\routes\generate_code.py
        @router.websocket("/generate-code")
        async def stream_code(websocket: WebSocket):
            # ...
            for index, updated_html in enumerate(updated_completions):
                await send_message("setCode", updated_html, index) # Vulnerable line: sending unsanitized code
            # ...
        ```
    6. **Frontend Rendering (Assumption):** Frontend likely renders received code directly into the DOM (e.g., `iframe`, `div` with `innerHTML`) without sanitization, executing any JavaScript.

* **Security Test Case:**
    1. **Malicious Payload Image:** Create an image designed to induce the LLM to generate HTML with malicious JavaScript (e.g., screenshot of a webpage with XSS payload).
    2. **Environment Setup:** Run the screenshot-to-code application locally or access a public instance.
    3. **WebSocket Connection:** Connect to the `/generate-code` websocket endpoint.
    4. **Malicious Request:** Send a JSON message via websocket:
        ```json
        {
          "inputMode": "image",
          "generatedCodeConfig": "html_tailwind",
          "image": "<base64_encoded_malicious_image>",
          "promptParams": "{}",
          "model": "gpt-4-vision-preview",
          "generationType": "create"
        }
        ```
        Replace `<base64_encoded_malicious_image>` with base64 encoded malicious image.
    5. **WebSocket Message Analysis:** Monitor websocket messages for `type: "setCode"`. Check the `value` field for generated HTML containing malicious JavaScript (e.g., `<img src="invalid-url" onerror="alert('XSS Vulnerability!')">` or `<script>alert('XSS Vulnerability!')</script>`).
    6. **Render Generated Code:** Trigger frontend display or manually render the generated HTML in a browser.
    7. **Verify XSS Execution:** Confirm JavaScript execution (e.g., alert box) to validate the XSS vulnerability.


### 2. Path Traversal Vulnerability in Evaluation File Access

* **Description:**
    1. The application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` allowing users to specify folder paths as query parameters.
    2. These paths are used to read HTML files for evaluation purposes.
    3. The application lacks proper sanitization and validation of these folder paths.
    4. An attacker can manipulate folder paths to traverse the file system and potentially read arbitrary files if the application has sufficient permissions.
    5. For example, using path traversal sequences like `../` in the `folder` parameter of `/evals` to access files outside intended evaluation directories.

* **Impact:**
    - High. Exploitation allows reading arbitrary files from the server's file system that the application process can access.
    - Exposure of sensitive application data: Configuration files, database credentials, API keys, source code, etc.
    - Privilege escalation (potential): Readable configuration files may contain credentials or misconfigurations for privilege escalation.
    - Further attacks: Information gathered can be used for more sophisticated attacks.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - Path existence check: `folder_path.exists()` in `get_evals` and `os.path.exists(folder1/2)` in `get_pairwise_evals` and similar in `get_best_of_n_evals`. This check happens *after* potential traversal and does not prevent it.
    - File extension check: Code checks for `.html` file extensions, limiting file types read but not preventing access to HTML files outside intended directories.

* **Missing Mitigations:**
    - Input sanitization: Sanitize folder paths to remove or escape path traversal sequences like `../` and `./`.
    - Path validation/Canonicalization: Canonicalize paths and validate that resolved paths are within the expected base directory (e.g., under `EVALS_DIR`). Check if resolved paths start with the intended base directory prefix.
    - Principle of least privilege: Run the application process with minimum necessary file system permissions to reduce path traversal impact.

* **Preconditions:**
    - Publicly accessible application.
    - Attacker can send HTTP requests to evaluation endpoints.
    - Application process has read permissions to target files.

* **Source Code Analysis:**
    - **File: `..\screenshot-to-code\backend\routes\evals.py`**

    - **Function: `get_evals`**
        ```python
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str):
            if not folder:
                raise HTTPException(status_code=400, detail="Folder path is required")

            folder_path = Path(folder) # [POINT OF CONCERN] Unsanitized user input to Path
            if not folder_path.exists(): # Existence check after traversal
                raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

            try:
                evals: list[Eval] = []
                # Get all HTML files from folder
                files = {
                    f: os.path.join(folder, f) # [POINT OF CONCERN] Unsanitized folder input in os.path.join
                    for f in os.listdir(folder) # [POINT OF CONCERN] Unsanitized folder input in os.listdir
                    if f.endswith(".html")
                }
                ...
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
        ```
        `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` use user-provided `folder`, `folder1`, `folder2` parameters directly in `Path`, `os.listdir`, and `os.path.join` without sanitization.

* **Security Test Case:**
    1. Deploy application in a test environment.
    2. Choose a target file outside `EVALS_DIR` (e.g., `/app/config/app_config.html` if exists and readable).
    3. Craft GET request to `/evals` with malicious `folder` parameter (e.g., `folder=../../config`). Example URL: `http://<application-url>/evals?folder=../../config`.
    4. Send the crafted request.
    5. Analyze response and server logs. Look for errors or if content from targeted file is returned in `evals` response.
    6. Repeat for `/pairwise-evals` and `/best-of-n-evals` adjusting parameters (`folder1`, `folder2`, etc.).


### 3. Exposure of API Keys via Debug Logs

* **Description:**
    1. Application debug mode is enabled via `IS_DEBUG_ENABLED` environment variable set to `true`.
    2. In debug mode, detailed logs, including LLM prompt messages, are written to files in a debug directory (`DEBUG_DIR` environment variable, defaults to backend's working directory).
    3. If a user includes an API key in input (image description, text prompts), it will be part of the prompt messages sent to the LLM.
    4. Backend logs prompt messages containing API keys to files in the debug directory when in debug mode.
    5. If the debug directory is publicly accessible, attackers can access log files and extract exposed API keys.

* **Impact:**
    - Exposure of sensitive API keys (OpenAI, Anthropic, Gemini, Replicate).
    - Unauthorized API usage leading to cost incurred by application owner (for paid services like OpenAI GPT-4).
    - Potential access to other resources or actions if API key permissions extend beyond code generation.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - API keys loaded from environment variables (`config.py`).
    - Debug mode disabled by default (`IS_DEBUG_ENABLED = False`).
    - Debug logs written to UUID subdirectory (`DebugFileWriter.py`), slightly obfuscating log file location.

* **Missing Mitigations:**
    - Secret redaction in debug logs: No mechanism to redact API keys or sensitive information from debug logs.
    - Restricting debug log directory access: No enforced restrictions on debug directory access by the application, relying on deployment environment security.
    - Warning about sensitive data logging: No warnings to developers/users about risks of including sensitive data in inputs in debug mode.

* **Preconditions:**
    1. Debug mode (`IS_DEBUG_ENABLED`) enabled in backend configuration.
    2. User provides input containing an API key.
    3. Debug directory is publicly accessible due to misconfiguration.

* **Source Code Analysis:**
    1. **File: `backend/config.py`**
        ```python
        IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
        DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
        ```
        Defines debug mode and debug directory settings.
    2. **File: `backend/debug/DebugFileWriter.py`**
        ```python
        class DebugFileWriter:
            # ...
            def write_to_file(self, filename: str, content: str) -> None:
                try:
                    with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
                        file.write(content)
                except Exception as e:
                    logging.error(f"Failed to write to file: {e}")
        ```
        Writes debug files only when `IS_DEBUG_ENABLED` is true, to a UUID subdirectory.
    3. **File: `backend/utils.py`**
        ```python
        from debug.DebugFileWriter import DebugFileWriter
        debug_file_writer = DebugFileWriter()

        def pprint_prompt(prompt_messages: List[ChatCompletionMessageParam]):
            print(json.dumps(truncate_data_strings(prompt_messages), indent=4))
            if IS_DEBUG_ENABLED:
                debug_file_writer.write_to_file("prompt.json", json.dumps(prompt_messages, indent=4))
        ```
        Logs prompt messages to `prompt.json` in debug mode using `DebugFileWriter`.

* **Security Test Case:**
    1. Deploy application in test environment with publicly accessible backend working directory (or `DEBUG_DIR`).
    2. Enable debug mode (`IS_DEBUG_ENABLED=true`).
    3. Access public application instance.
    4. Provide input (screenshot/text prompt) containing a dummy API key (e.g., "My OpenAI API key is DUMMY_API_KEY_12345").
    5. Trigger code generation.
    6. Access debug directory.
    7. Locate `prompt.json` file within the UUID subdirectory.
    8. Verify dummy API key presence in `prompt.json`.
    9. If found, vulnerability is confirmed.
