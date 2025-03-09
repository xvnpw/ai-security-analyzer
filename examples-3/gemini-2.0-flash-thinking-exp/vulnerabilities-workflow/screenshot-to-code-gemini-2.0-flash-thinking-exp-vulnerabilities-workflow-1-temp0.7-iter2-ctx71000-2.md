### Vulnerability List:

- **Vulnerability Name:** Debug Mode Enabled in Production

- **Description:**
    1. The application can be run in debug mode by setting the `MOCK` or `IS_DEBUG_ENABLED` environment variables to `true`.
    2. Debug mode enables functionalities like mock AI responses and writing debug artifacts to disk.
    3. If debug mode is unintentionally enabled in a production environment, it can lead to information disclosure and potentially other security risks.

- **Impact:**
    - **Information Disclosure:** Debug mode can write detailed logs, including prompts sent to LLMs and responses received. This could expose sensitive information about application functionality, prompts used, and potentially partial responses from LLMs. In the `DebugFileWriter.py`, it is mentioned that debugging artifacts will be stored in a directory, which suggests detailed logs are written. Specifically, in `llm.py`, when `IS_DEBUG_ENABLED` is true, the code writes intermediate HTML and thinking process to files. This can expose internal application logic and potentially user-provided data used in prompts.
    - **Exposed Mock Responses:** In mock mode, the application streams pre-recorded responses. While intended for debugging, if enabled in production, it could lead to unexpected behavior or allow attackers to understand application responses without triggering actual LLM calls, potentially aiding in reconnaissance.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `config.py` file reads the `MOCK` and `IS_DEBUG_ENABLED` variables from environment variables. This implies that debug mode is not enabled by default and requires explicit configuration.

    ```python
    # backend\config.py
    SHOULD_MOCK_AI_RESPONSE = bool(os.environ.get("MOCK", False))
    IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
    DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
    ```

- **Missing Mitigations:**
    - **Explicitly Disable in Production:** The project should have a clear configuration setting or environment variable that *explicitly disables* debug mode in production, regardless of the presence or value of `MOCK` or `IS_DEBUG_ENABLED`.  This could be enforced in the application startup logic.
    - **Warning on Startup:** The backend application should log a warning message at startup if debug mode is detected as enabled, especially if `IS_PROD` is set to `True`. This would provide an immediate visual cue to operators that a potentially insecure configuration is active.
    - **Remove/Restrict Debug Artifacts in Production:** In production, the debug functionality should be either completely removed or heavily restricted. Writing debug files to disk in a publicly accessible environment is inherently risky. If debug logging is necessary in production for operational reasons, it should be directed to secure logging systems and not written to the filesystem in an uncontrolled manner.

- **Preconditions:**
    - The application must be deployed in a production environment.
    - The environment variables `MOCK` or `IS_DEBUG_ENABLED` must be set to a truthy value (e.g., "true", "1", "yes") in the production environment's configuration. This could happen due to misconfiguration during deployment or if configuration settings are not properly managed.

- **Source Code Analysis:**
    1. **`backend\config.py`**: Defines configuration variables, including `SHOULD_MOCK_AI_RESPONSE` and `IS_DEBUG_ENABLED`, which are read from environment variables.

    ```python
    # backend\config.py
    SHOULD_MOCK_AI_RESPONSE = bool(os.environ.get("MOCK", False))
    IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
    DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
    IS_PROD = os.environ.get("IS_PROD", False)
    ```

    2. **`backend\llm.py`**: Uses `IS_DEBUG_ENABLED` to control debug logging via `DebugFileWriter`.

    ```python
    # backend\llm.py
    from config import IS_DEBUG_ENABLED
    from debug.DebugFileWriter import DebugFileWriter

    # ...

    async def stream_claude_response_native(
        # ...
    ) -> Completion:
        # ...
        debug_file_writer = DebugFileWriter() # DebugFileWriter is instantiated based on IS_DEBUG_ENABLED

        while current_pass_num <= max_passes:
            # ...
            # Write each pass's code to .html file and thinking to .txt file
            if IS_DEBUG_ENABLED: # Debug logging is conditional based on IS_DEBUG_ENABLED
                debug_file_writer.write_to_file(
                    f"pass_{current_pass_num - 1}.html",
                    debug_file_writer.extract_html_content(response_text),
                )
                debug_file_writer.write_to_file(
                    f"thinking_pass_{current_pass_num - 1}.txt",
                    response_text.split("</thinking>")[0],
                )
            # ...

        if IS_DEBUG_ENABLED: # Debug logging is conditional based on IS_DEBUG_ENABLED
            debug_file_writer.write_to_file("full_stream.txt", full_stream)
        # ...
    ```

    3. **`backend\mock_llm.py`**: Mock responses are used if mock mode is enabled. This is controlled by `SHOULD_MOCK_AI_RESPONSE` from `config.py`.

    ```python
    # backend\mock_llm.py
    from config import SHOULD_MOCK_AI_RESPONSE

    async def mock_completion(
        process_chunk: Callable[[str, int], Awaitable[None]], input_mode: InputMode
    ) -> Completion:
        if SHOULD_MOCK_AI_RESPONSE: # Mock completion is conditional based on SHOULD_MOCK_AI_RESPONSE
            code_to_return = (
                TALLY_FORM_VIDEO_PROMPT_MOCK
                if input_mode == "video"
                else NO_IMAGES_NYTIMES_MOCK_CODE
            )
        # ...
    ```

    4. **`backend\Debug\DebugFileWriter.py`**: `DebugFileWriter` class controls writing debug information to files.

    ```python
    # backend\debug\DebugFileWriter.py
    from config import DEBUG_DIR, IS_DEBUG_ENABLED


    class DebugFileWriter:
        def __init__(self):
            if not IS_DEBUG_ENABLED: # DebugFileWriter initialization is conditional based on IS_DEBUG_ENABLED
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
            # ... writes content to file in debug_artifacts_path
    ```

- **Security Test Case:**
    1. Deploy the `screenshot-to-code` application in a test environment that mimics production (e.g., publicly accessible).
    2. Configure the backend deployment to set the environment variable `IS_DEBUG_ENABLED=true`. Do *not* set `IS_PROD=true` to simulate a misconfiguration where debug is left on in production.
    3. Access the application through a web browser as an external attacker would.
    4. Use the application to convert a screenshot to code.
    5. Check the server's filesystem in the directory specified by `DEBUG_DIR` (or the default if not set).
    6. **Expected Result:** Debug files (e.g., `pass_1.html`, `thinking_pass_1.txt`, `full_stream.txt`) should be present in the debug directory, containing potentially sensitive information like prompts, intermediate code, and the AI's "thinking" process. This confirms that debug mode is active and writing artifacts to disk in the "production-like" environment, demonstrating information disclosure vulnerability.

- **Vulnerability Name:** Path Traversal in Evaluation File Access

- **Description:**
    1. The `get_evals` endpoint in `evals.py` takes a `folder` parameter from the query string.
    2. This `folder` parameter is used to construct file paths to read evaluation files using `os.path.join` and `os.listdir`.
    3. The application does not properly validate or sanitize the `folder` input.
    4. An attacker can manipulate the `folder` parameter by including path traversal sequences like `../` to access directories outside the intended evaluation folders.
    5. By crafting a malicious `folder` path, an attacker can potentially read arbitrary files from the server's filesystem, assuming the backend process has sufficient permissions.

- **Impact:**
    - **Arbitrary File Read:** Successful path traversal allows an attacker to read files on the server that the backend application has access to. This could lead to the disclosure of sensitive information such as configuration files, source code, environment variables, or other data stored on the server.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `get_evals` function checks if the provided `folder` path exists using `folder_path.exists()`. However, this check only verifies the existence of the directory and does not prevent path traversal, as a valid path can still point to a location outside the intended scope.

    ```python
    # backend\routes\evals.py
    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
    ```

- **Missing Mitigations:**
    - **Input Path Sanitization:** Implement robust input validation and sanitization on the `folder` parameter. This should include:
        - **Path Canonicalization:** Convert the user-provided path to its canonical form to resolve symbolic links and remove redundant separators and traversal elements (e.g., using `os.path.realpath` or similar).
        - **Path Restriction:**  Ensure that the resolved path stays within the intended base directory for evaluations. This can be achieved by:
            - Defining a base directory for evaluations (e.g., `EVALS_DIR`).
            - Using `os.path.commonpath` to check if the user-provided path is a subdirectory of the base directory. If `os.path.commonpath([EVALS_DIR, resolved_user_path])` is not equal to `EVALS_DIR`, then the path is trying to traverse outside the allowed directory.
            - Alternatively, use string prefix checking after canonicalization to ensure the path starts with the allowed base directory.
    - **Error Handling and Logging:** Implement proper error handling and logging for path traversal attempts. Log suspicious or invalid path inputs for security monitoring and incident response.

- **Preconditions:**
    - The application must be deployed and the `/evals` endpoint must be accessible to an attacker.
    - The attacker needs to know or guess the existence of the `/evals` endpoint and its parameters.

- **Source Code Analysis:**
    1. **`backend\routes\evals.py` - `get_evals` function:**
        ```python
        # backend\routes\evals.py
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str):
            if not folder:
                raise HTTPException(status_code=400, detail="Folder path is required")

            folder_path = Path(folder) # [POINT OF VULNERABILITY 1] Path object is created directly from user input 'folder'
            if not folder_path.exists():
                raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

            try:
                evals: list[Eval] = []
                # Get all HTML files from folder
                files = {
                    f: os.path.join(folder, f) # [POINT OF VULNERABILITY 2] Path is joined directly using user input 'folder'
                    for f in os.listdir(folder) # [POINT OF VULNERABILITY 3] Directory listing is performed directly on user input 'folder'
                    if f.endswith(".html")
                }
                # ... rest of the code to read files
        ```
        The code directly uses the user-provided `folder` string to create `Path` objects and in `os.path.join` and `os.listdir` without any validation against path traversal attacks. An attacker can provide a `folder` value like `../../../../../` to attempt to access files and directories outside the intended `EVALS_DIR`.

- **Security Test Case:**
    1. Deploy the `screenshot-to-code` application in a test environment.
    2. Identify the absolute path to the application's root directory on the server (e.g., `/app/screenshot-to-code`). Assume the `EVALS_DIR` is within this root, for example, `/app/screenshot-to-code/evals`.
    3. Create a test file named `test_file.html` in the application's root directory (e.g., `/app/screenshot-to-code/test_file.html`) with some harmless content (e.g., `<html><body>Test File</body></html>`).
    4. Send a GET request to the `/evals` endpoint with the `folder` parameter crafted to traverse to the root directory and access the test file. For example, if `EVALS_DIR` is one level deep inside root, use `/evals?folder=../`. If `EVALS_DIR` is deeper, adjust the number of `../` accordingly.  If you are unsure of the depth, try a long traversal like `/evals?folder=../../../../../../../../../`.
    5. Observe the server's response.
    6. **Expected Result:** If the application is vulnerable to path traversal, the response should include the content of `test_file.html` within the `evals` array. This indicates that the attacker successfully traversed out of the intended `EVALS_DIR` and accessed a file in a parent directory, confirming the arbitrary file read vulnerability. If the test file content is returned, the vulnerability is confirmed. If an error is returned, further investigation is needed to determine if path traversal is still possible but not directly exploitable in this specific test case or if there is some other error preventing access.
