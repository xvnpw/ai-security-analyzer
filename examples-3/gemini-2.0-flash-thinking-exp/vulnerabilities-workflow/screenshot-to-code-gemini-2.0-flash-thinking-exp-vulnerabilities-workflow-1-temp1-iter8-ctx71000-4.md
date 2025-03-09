### Vulnerability List

- Vulnerability Name: API Key Exposure via Debug Logs

- Description:
    1. An attacker gains access to publicly exposed debug logs of the backend application. This can occur due to misconfigured web server or cloud storage settings, making the `DEBUG_DIR` accessible from the internet.
    2. The application, if configured with `IS_DEBUG_ENABLED=true`, writes detailed debug logs to the directory specified by `DEBUG_DIR`.
    3. When the application interacts with AI services, and debug logging is enabled, it logs the prompts sent to these services using `pprint_prompt`.
    4. If API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `REPLICATE_API_KEY`) are included in the prompts (even inadvertently, for example if they are accidentally passed as part of user input and included in the prompt), these keys will be written to the debug logs in plain text.
    5. The attacker accesses these publicly exposed debug log files.
    6. The attacker extracts the API keys from the logs.
    7. Using the extracted API keys, the attacker can make unauthorized API calls to the respective AI services, potentially incurring costs, accessing AI models without authorization, and causing reputational damage.

- Impact:
    - Unauthorized access to and usage of AI services (OpenAI, Anthropic, Gemini, Replicate).
    - Financial costs incurred due to unauthorized API usage by the attacker.
    - Potential exposure of sensitive data if the attacker uses the compromised API keys to process sensitive information through the AI services.
    - Reputational damage to the application and its developers due to the security breach.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - API keys are stored as environment variables, which is a security best practice to avoid hardcoding.
    - The application is intended to store API keys only client-side when users input them in settings, not on the server persistently (except potentially in logs if debug is enabled).

- Missing Mitigations:
    - **Crucially, restrict access to the `DEBUG_DIR`**: Ensure that the directory specified by `DEBUG_DIR` (and its default location if `DEBUG_DIR` is not set) is not publicly accessible. Web server configurations and cloud storage permissions must be hardened to prevent external access.
    - **Disable debug logging in production**: The default configuration should have `IS_DEBUG_ENABLED` set to `false` in production environments. Enforce this configuration to minimize the risk of accidental debug logging in live deployments.
    - **Sensitive data redaction in logs**: Implement input sanitization or redaction techniques to remove or mask sensitive information, especially API keys, from log messages before they are written to debug files. This would involve modifying `pprint_prompt` or the logging mechanism to filter out or replace API key patterns.
    - **Regular security audits**: Conduct periodic security reviews of the application's configuration and code to identify and remediate potential vulnerabilities, including misconfigurations that could lead to log exposure.

- Preconditions:
    - `IS_DEBUG_ENABLED` environment variable is set to `true` in the backend application's environment.
    - The directory specified by `DEBUG_DIR` (or the default debug log location) is publicly accessible due to misconfiguration of the server or cloud storage.
    - API keys might be present in the prompts sent to the LLM, either intentionally or accidentally (e.g., through user-provided input being incorporated into prompts without proper sanitization).

- Source Code Analysis:
    1. **`backend/config.py`**:
        ```python
        IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
        DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
        ```
        - Defines `IS_DEBUG_ENABLED` based on the environment variable, defaulting to `False` if not set.
        - Defines `DEBUG_DIR` based on the environment variable, defaulting to an empty string if not set, which could resolve to a location within the application's directory or system's temporary directory depending on `os.path.expanduser` in `DebugFileWriter`.

    2. **`backend/debug/DebugFileWriter.py`**:
        ```python
        from config import DEBUG_DIR, IS_DEBUG_ENABLED
        # ...
        class DebugFileWriter:
            def __init__(self):
                if not IS_DEBUG_ENABLED:
                    return
                try:
                    self.debug_artifacts_path = os.path.expanduser(
                        f"{DEBUG_DIR}/{str(uuid.uuid4())}"
                    )
                    os.makedirs(self.debug_artifacts_path, exist_ok=True)
                    print(f"Debugging artifacts will be stored in: {self.debug_artifacts_path}")
                except:
                    logging.error("Failed to create debug directory")

            def write_to_file(self, filename: str, content: str) -> None:
                try:
                    with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
                        file.write(content)
                except Exception as e:
                    logging.error(f"Failed to write to file: {e}")
        ```
        - `DebugFileWriter` is instantiated only when `IS_DEBUG_ENABLED` is true.
        - It creates a directory within `DEBUG_DIR` (or a default location based on empty string expansion by `os.path.expanduser`) to store debug logs.
        - The `write_to_file` method writes provided content to a specified filename within the debug directory.

    3. **`backend/llm.py`**:
        ```python
        from utils import pprint_prompt
        # ...
        async def stream_openai_response(
            messages: List[ChatCompletionMessageParam],
            api_key: str, # Potentially logged as part of messages
            base_url: str | None,
            callback: Callable[[str], Awaitable[None]],
            model: Llm,
        ) -> Completion:
            # ...
            if IS_DEBUG_ENABLED:
                pprint_prompt(messages) # [!] Potential log of API key if in messages
            # ...
        ```
        - If `IS_DEBUG_ENABLED` is true, `pprint_prompt` is called with `messages`.
        - If `messages` contains API keys (which is less likely but theoretically possible if keys are passed around in message structures), they could be logged. More likely prompts themselves, which could contain user input that resembles API keys.

    4. **`backend/utils.py`**:
        ```python
        import json
        from typing import List
        from openai.types.chat import ChatCompletionMessageParam

        def pprint_prompt(prompt_messages: List[ChatCompletionMessageParam]):
            print(json.dumps(truncate_data_strings(prompt_messages), indent=4)) # [!] Logs full JSON, including potential API keys in messages
        ```
        - `pprint_prompt` serializes `prompt_messages` to JSON and prints it to standard output using `print`.
        - If the standard output of the backend application is configured to be logged to files (common in many deployment environments), and `prompt_messages` contains API keys or similar sensitive data, this data will be written to the logs.

    **Visualization:**

    ```
    [Request to Backend] --> backend/llm.py --> pprint_prompt(messages) --> utils.py:print(json.dumps(messages)) --> [Standard Output/Logs] --> [Debug Log Files in DEBUG_DIR (if IS_DEBUG_ENABLED)] --> [Publicly Accessible DEBUG_DIR due to Misconfig] --> Attacker Access --> API Key Extraction
    ```

- Security Test Case:
    1. **Setup**:
        - Deploy the application in a test environment or use a local instance.
        - **Crucially, simulate a misconfiguration that makes debug logs publicly accessible.**  For example, if using a web server like Nginx, configure a location block that serves files from the `DEBUG_DIR` (or a directory where logs are written if `DEBUG_DIR` is not explicitly set and defaults to a predictable location) without authentication. Alternatively, if using cloud storage, make the log bucket or directory publicly readable.
        - Set the environment variable `IS_DEBUG_ENABLED=true` when running the backend.
        - Ensure API keys for AI services are configured so the application can interact with them.
    2. **Trigger**:
        - Send a request to an endpoint that interacts with an LLM. For example, use the screenshot analysis feature or any chat-based feature.  Include text in your input that resembles an API key or might cause the application to include an API key in the prompt it sends to the LLM (though direct inclusion of actual API keys in prompts is less common in typical application flow, the focus is on logging prompts which *could* contain sensitive data inadvertently).
    3. **Access Publicly Exposed Logs**:
        - As an attacker (from outside the server if simulating a public instance), access the publicly exposed debug log files. This step depends on the misconfiguration simulated in setup (e.g., access the Nginx exposed directory via browser, access the public cloud storage bucket).
    4. **Analyze Logs**:
        - Open the log files downloaded from the publicly accessible location.
        - Search for log entries that contain `pprint_prompt` or timestamps corresponding to your interaction with the LLM feature.
        - Look for JSON structures within the logs that represent prompt messages.
    5. **Verify API Key Exposure**:
        - Examine the logged JSON prompt messages. Check if any API keys (e.g., `OPENAI_API_KEY`, `sk-...`, `anthropic.api_key`, etc.) are present in the logged prompts or in any other logged data related to the LLM interaction. If API keys are found in the logs, and these logs were publicly accessible, the vulnerability is confirmed.


- Vulnerability Name: Path Traversal in Evals Endpoint

- Description:
    1. An external attacker sends a crafted HTTP GET request to the `/evals` endpoint of the publicly accessible backend application.
    2. The attacker manipulates the `folder` query parameter in the request, injecting a path traversal sequence like `../../../../etc/passwd`.
    3. The backend application, specifically in the `get_evals` function in `backend\routes\evals.py`, receives this `folder` parameter.
    4. The application uses the provided `folder` path directly in `os.listdir(folder)` and subsequently in `open(filepath, "r")` to read files, without properly validating or sanitizing the input to ensure it stays within the intended evaluation files directory.
    5. Due to the lack of path traversal protection, `os.path.join` used in constructing file paths does not prevent the attacker from escaping the intended directory.
    6. The application attempts to list directory contents and open files based on the attacker-controlled path.
    7. If successful, the attacker can read arbitrary files from the server's filesystem that the application's user has permissions to access. This includes sensitive system files, configuration files, or application source code, depending on server setup and file permissions.

- Impact:
    - **Arbitrary File Read**: Attackers can read any file on the server that the backend application's user has permissions to access.
    - **Confidentiality Breach**: Exposure of sensitive information contained in readable files, such as:
        - System configuration files (e.g., `/etc/passwd`, `/etc/shadow` - if readable).
        - Application configuration files containing database credentials, API keys (if not environment variables and accidentally stored in files).
        - Source code, potentially revealing internal logic, algorithms, or further vulnerabilities.
        - Internal data files, depending on the application's purpose and file storage locations.
    - **Increased Attack Surface**: Successful path traversal can be a stepping stone for more severe attacks. For example, reading configuration files could reveal credentials for database or other services, leading to data breaches or further system compromise.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Directory Existence Check**: The application checks if the provided `folder` exists using `folder_path.exists()`.
    - **File Extension Filter**: The application filters files in the listed directory to only process files ending with `.html`.

- Missing Mitigations:
    - **Robust Input Validation and Sanitization**: The most critical missing mitigation is proper validation of the `folder` parameter. This should include:
        - **Path Normalization**: Convert the user-provided path to a canonical form to resolve path traversal sequences (e.g., `..`).
        - **Path Confinement**: Ensure the normalized path stays within the intended base directory (e.g., `EVALS_DIR/inputs` or a designated "safe" directory).  Reject requests if the path escapes the base directory.
        - **Allowlisting/Denylisting**: Define an allowlist of acceptable directories or a denylist of forbidden path components. However, path confinement to a base directory is generally a more effective approach for path traversal prevention.
    - **Principle of Least Privilege**: Ensure the backend application runs with minimal necessary permissions. This limits the impact of a successful path traversal, as the attacker will only be able to read files accessible to the application's user. However, this is a secondary defense; preventing path traversal is the primary goal.

- Preconditions:
    - The backend application must be deployed and publicly accessible over the network.
    - The `/evals` endpoint must be exposed and reachable without authentication (or with attacker-accessible authentication, though assuming public access for this scenario).

- Source Code Analysis:
    1. **`backend/routes/evals.py`**:
        ```python
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str): # [!] 'folder' parameter from request
            if not folder:
                raise HTTPException(status_code=400, detail="Folder path is required")

            folder_path = Path(folder)
            if not folder_path.exists(): # [!] Insufficient mitigation: only checks if path exists, not if it's safe
                raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

            try:
                evals: list[Eval] = []
                files = {
                    f: os.path.join(folder, f) # [!] Vulnerable: unsanitized 'folder' used in path construction
                    for f in os.listdir(folder) # [!] Vulnerable: unsanitized 'folder' passed to os.listdir
                    if f.endswith(".html")
                }
                # ... (rest of the code processes files) ...
                for base_name in base_names:
                    input_path = os.path.join(EVALS_DIR, "inputs", f"{base_name}.png") # Safe path (within EVALS_DIR/inputs)
                    if not os.path.exists(input_path):
                        continue

                    output_file = None
                    for filename, filepath in files.items():
                        if filename.startswith(base_name):
                            output_file = filepath # [!] Vulnerable: 'filepath' based on unsanitized 'folder'
                            break

                    if output_file:
                        input_data = await image_to_data_url(input_path)
                        with open(output_file, "r", encoding="utf-8") as f: # [!] Vulnerable: 'output_file' path from unsanitized input
                            output_html = f.read()
                        evals.append(Eval(input=input_data, outputs=[output_html]))
                return evals

            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
        ```
        - The `get_evals` function takes the `folder` parameter directly from the query string.
        - `os.listdir(folder)` attempts to list files in the directory specified by the unsanitized `folder`.
        - `os.path.join(folder, f)` constructs file paths using the unsanitized `folder`, and these paths are then used with `open()`.
        - The `folder_path.exists()` check is present but insufficient to prevent path traversal because it only verifies if *some* path exists, not if it's within an allowed directory.

    **Visualization:**

    ```
    [Attacker Request: /evals?folder=../../../etc/passwd] --> backend/routes/evals.py --> get_evals(folder="../../../etc/passwd") --> os.listdir("../../../etc/passwd") --> open("../../../etc/passwd/somefile.html", "r") --> [File Read Attempt Outside Expected Directory] --> [Response with File Content (if successful)]
    ```

- Security Test Case:
    1. **Setup**:
        - Deploy the backend application in a test environment or use a local instance. Ensure the `/evals` endpoint is accessible.
        - Place a sensitive file on the server that the application user *should* be able to read, but should *not* be accessible through the `/evals` endpoint in a legitimate scenario. Examples:
            -  If running as user `webapp` in `/app/backend`, place a file `sensitive.txt` in `/home/webapp/sensitive.txt`.
            - Or, for testing general system file access (more risky in production-like environments), use a well-known file like `/etc/passwd`.  For safer testing, creating a dummy sensitive file in a more restricted location is recommended first.
    2. **Trigger**:
        - Send an HTTP GET request to the `/evals` endpoint with a path traversal payload in the `folder` parameter.  Construct the payload to target the sensitive file created in the setup.
            - Example 1 (accessing `/home/webapp/sensitive.txt` if app runs in `/app/backend` as `webapp` user):
              `GET /evals?folder=../../../../home/webapp/sensitive.txt HTTP/1.1`
            - Example 2 (accessing `/etc/passwd` - use with caution in test environments):
              `GET /evals?folder=../../../../etc/passwd HTTP/1.1`
        3. **Analyze Response**:
            - Examine the HTTP response from the server.
            - **Successful Exploitation**: If the vulnerability is present, the response body will likely contain a JSON structure. Look for the `outputs` field within this JSON. If the content of the targeted sensitive file (e.g., the content of `sensitive.txt` or `/etc/passwd`) is included in the `outputs` array, then the path traversal vulnerability is confirmed. The file content might be HTML-encoded or base64-encoded depending on how the `Eval` model and response serialization are implemented.
            - **Error Response**: If the application returns an error (e.g., 404 File Not Found, 500 Server Error), it might indicate that the path traversal attempt was partially successful but encountered an error during file processing or reading (e.g., file extension filtering might block `/etc/passwd` if it doesn't end in `.html`, but the `os.listdir` might still have executed).  Inspect server-side logs for more detailed error messages in such cases. If you get a 404 "Folder not found", it means even the directory traversal to `/etc` (in the `/etc/passwd` example) was blocked at the `folder_path.exists()` check, which is less likely with `../../../../etc/passwd`.
        4. **Verify File Content**:
            - If you received a successful response containing data in the `outputs`, decode or extract the file content and verify that it matches the content of the sensitive file you were trying to access. This confirms arbitrary file read via path traversal.
