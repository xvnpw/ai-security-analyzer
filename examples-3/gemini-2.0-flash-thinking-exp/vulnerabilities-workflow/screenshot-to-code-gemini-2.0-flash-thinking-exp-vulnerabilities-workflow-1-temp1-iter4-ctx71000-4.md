- Vulnerability name: Exposure of API Keys via Debug Logs
- Description:
    1. The application has a debug mode, enabled by setting the `IS_DEBUG_ENABLED` environment variable to `true`.
    2. When debug mode is enabled, detailed logs, including prompt messages sent to LLMs, are written to files in a debug directory. The location of this directory is configurable via the `DEBUG_DIR` environment variable, defaulting to the backend's working directory if not set.
    3. If a user, either maliciously or accidentally, includes an API key within the input image description or text prompts (e.g., by typing "My OpenAI key is sk-...") that are processed by the application, this API key will be included in the prompt messages sent to the LLM.
    4. When the backend processes this input in debug mode, the prompt messages, containing the embedded API key, are logged to a file within the debug directory.
    5. If the debug directory is publicly accessible (e.g., due to misconfiguration of the web server or container deployment), a threat actor can access these log files and extract the exposed API key.
- Impact:
    - Exposure of sensitive API keys (OpenAI API key, Anthropic API key, Gemini API key, Replicate API key) to unauthorized parties.
    - If the exposed API key is for a paid service (like OpenAI GPT-4), the threat actor could use the key to make calls to the API, incurring costs for the application owner.
    - Depending on the permissions associated with the API key, the threat actor might be able to access other resources or perform actions beyond just generating code, if the key is reused across services.
- Vulnerability rank: High
- Currently implemented mitigations:
    - API keys are loaded from environment variables (`config.py`), which is a standard security practice to avoid hardcoding secrets in the code.
    - The debug mode is disabled by default (`IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))`).
    - Debug logs are written to a subdirectory with a UUID (`DebugFileWriter.py`), making it slightly harder to guess the log file location compared to a fixed filename.
- Missing mitigations:
    - **Secret redaction in debug logs:** The application lacks any mechanism to redact or mask sensitive information like API keys from debug logs.
    - **Restricting debug log directory access:** The application does not enforce restrictions on access to the debug directory. It relies on the deployment environment to properly secure this directory.
    - **Warning about logging sensitive data:** There is no explicit warning to developers or users about the risks of including sensitive information in inputs when debug mode is enabled.
- Preconditions:
    1. Debug mode (`IS_DEBUG_ENABLED`) must be enabled in the backend configuration (e.g., by setting the environment variable `MOCK=true IS_DEBUG_ENABLED=true poetry run uvicorn main:app --reload --port 7001`).
    2. A user must provide input (screenshot description or text prompt) that contains an API key.
    3. The debug directory, where logs are written, must be publicly accessible to external attackers. This could happen due to misconfiguration in the deployment environment (e.g., exposed Docker volume, misconfigured web server).
- Source code analysis:
    1. File: `backend/config.py`
        ```python
        IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
        DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
        ```
        - `IS_DEBUG_ENABLED` flag controls debug mode.
        - `DEBUG_DIR` sets the debug log directory.
    2. File: `backend/debug/DebugFileWriter.py`
        ```python
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
        - `DebugFileWriter` is used to write debug files only when `IS_DEBUG_ENABLED` is true.
        - Debug files are written to a subdirectory of `DEBUG_DIR` (or backend's working directory if `DEBUG_DIR` is empty).
    3. File: `backend/utils.py`
        ```python
        from debug.DebugFileWriter import DebugFileWriter
        debug_file_writer = DebugFileWriter()

        def pprint_prompt(prompt_messages: List[ChatCompletionMessageParam]):
            print(json.dumps(truncate_data_strings(prompt_messages), indent=4))
            if IS_DEBUG_ENABLED:
                debug_file_writer.write_to_file("prompt.json", json.dumps(prompt_messages, indent=4))
        ```
        - `pprint_prompt` is used to print and log prompt messages when debug mode is enabled.
        - Prompt messages are logged in JSON format to `prompt.json` file in the debug directory.
    4. Visualization:
        ```
        [User Input with API Key] --> [Backend with IS_DEBUG_ENABLED=true] --> pprint_prompt() --> DebugFileWriter --> [Debug Directory]/prompt.json --> [Publicly Accessible Debug Directory] --> [Threat Actor Accesses Log File] --> API Key Exposed
        ```
- Security test case:
    1. Deploy the application in a test environment where the backend's working directory (or `DEBUG_DIR` if configured) can be made publicly accessible (for testing purposes only, do not do this in production).
    2. Enable debug mode by setting the environment variable `IS_DEBUG_ENABLED=true` for the backend service (e.g., in `docker-compose.yml` or the deployment configuration).
    3. As an external attacker, access the publicly exposed application instance.
    4. In the application UI, upload a screenshot or provide a text prompt that includes a clearly identifiable, but *dummy* API key (e.g., "My OpenAI API key is DUMMY_API_KEY_12345").
    5. Trigger code generation using this input.
    6. As an external attacker, attempt to access the debug directory. The method to access the directory depends on how it's exposed in the test environment (e.g., directly via HTTP if misconfigured webserver, or by listing files in an exposed Docker volume if applicable).
    7. Once you gain access to the debug directory, look for a file named `prompt.json` within the directory structure created by `DebugFileWriter` (subdirectory with UUID).
    8. Open `prompt.json` and verify if the dummy API key ("DUMMY_API_KEY_12345") is present in the logged prompt messages.
    9. If the dummy API key is found in the log file, the vulnerability is confirmed.
- Vulnerability name: Path Traversal in Evaluation Folder Access
- Description:
    1. The application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` that allow users to retrieve evaluation results.
    2. These endpoints take folder paths as query parameters (`folder`, `folder1`, `folder2`, etc.) to specify the location of evaluation output files.
    3. The application uses `os.path.exists()` and `os.listdir()` to check for folder existence and list files within the provided folder path, but it **does not sufficiently validate or sanitize these paths** to prevent path traversal attacks.
    4. An attacker can provide a crafted folder path (e.g., "../", "../../", absolute paths like "/etc/") in the query parameters to access directories and files outside the intended evaluation directories.
    5. By exploiting this path traversal vulnerability, an attacker could potentially read sensitive files on the server, depending on the file system permissions and the application's execution context.
- Impact:
    - **Information Disclosure:** An attacker can read arbitrary files from the server's file system that the application process has access to. This could include application source code, configuration files, environment variables (if stored on disk), or other sensitive data.
    - **Potential for further exploitation:** In certain scenarios, if the attacker gains access to writable directories through path traversal (less likely in this specific code but a general risk of path traversal), they might be able to upload malicious files and potentially achieve remote code execution.
- Vulnerability rank: High
- Currently implemented mitigations:
    - The application checks if the provided folder exists using `os.path.exists()` before attempting to list files. This prevents errors if a non-existent path is provided, but it does not prevent path traversal within existing paths.
- Missing mitigations:
    - **Path Sanitization and Validation:** The application lacks proper input validation and sanitization for the folder paths received in the query parameters. It should implement checks to ensure that the provided paths are within the intended evaluation directories (e.g., by using allow lists, or by resolving paths to a canonical form and ensuring they are within a safe base directory like `EVALS_DIR`).
    - **Restricting Access:** Even with path sanitization, consider implementing stricter access controls to the evaluation result directories to minimize the impact of a path traversal vulnerability. The web server configuration should also prevent direct access to sensitive directories.
- Preconditions:
    1. The application must be deployed and accessible to external attackers.
    2. An attacker needs to identify and access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
    3. The attacker must be able to manipulate the `folder`, `folder1`, `folder2`, etc., query parameters in the request.
- Source code analysis:
    1. File: `backend/routes/evals.py`
        - **Functions affected**: `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
        - **Code snippet in `get_evals`**:
            ```python
            @router.get("/evals", response_model=list[Eval])
            async def get_evals(folder: str):
                if not folder:
                    raise HTTPException(status_code=400, detail="Folder path is required")

                folder_path = Path(folder)
                if not folder_path.exists():
                    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

                try:
                    evals: list[Eval] = []
                    # Get all HTML files from folder
                    files = {
                        f: os.path.join(folder, f)
                        for f in os.listdir(folder)
                        if f.endswith(".html")
                    }
                    # ... rest of the code ...
            ```
        - **Vulnerability**: The `folder` parameter from the query string is directly used with `Path(folder)` and `os.listdir(folder)` without any sanitization or validation to ensure it stays within allowed directories. An attacker can provide paths like `../`, `../../`, or absolute paths to traverse the directory structure.
        - **Similar code patterns** exist in `get_pairwise_evals` and `get_best_of_n_evals` functions, where `folder1`, `folder2`, etc., parameters are used in the same insecure manner.
    2. Visualization:
        ```
        [Attacker crafted URL with malicious folder path] --> [Backend API Endpoint (/evals, /pairwise-evals, /best-of-n-evals)] --> [os.listdir(folder_path)] --> [File System Access based on attacker-controlled path] --> [Information Disclosure if attacker traverses to sensitive files]
        ```
- Security test case:
    1. Deploy the application in a test environment.
    2. As an external attacker, access the `/evals` endpoint with a path traversal payload in the `folder` query parameter. For example: `http://<app-url>/evals?folder=../../../etc/`.
    3. Observe the application's response. If the application attempts to list files in `/etc/` (which may result in an error depending on file permissions and content, but the attempt indicates path traversal), or if it returns an error message that suggests it tried to access files in a directory outside the intended path, the vulnerability is likely present.
    4. To confirm file reading, try to access a known file that the application user might have read access to, for example, try to access the application's configuration files if their location is predictable relative to the application's working directory using paths like `../config`, `../../config`, etc.
    5. If you can successfully list or read the content of files outside of the expected evaluation directories using path traversal techniques via the `folder` parameter (and similarly for `folder1`, `folder2` in other eval endpoints), then the path traversal vulnerability is confirmed.
    6. For a less intrusive test, you can try paths like `evals?folder=./` or `evals?folder=..`, and observe the directory listing or errors to infer if directory traversal is occurring based on the application's behavior and error messages. Note that depending on the deployment environment and security configurations, direct listing of `/etc/` might be restricted, but even the attempt to access it, and error responses related to such attempts, are indicative of the vulnerability.
