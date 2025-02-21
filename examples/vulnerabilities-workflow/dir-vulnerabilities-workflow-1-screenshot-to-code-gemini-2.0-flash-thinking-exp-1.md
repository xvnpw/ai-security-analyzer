### Vulnerability List

- **Vulnerability Name:** Information Disclosure via Debug Logs

- **Description:**
    - Step 1: An attacker identifies that the application might be running in debug mode in a production environment. This could be inferred through error messages, verbose logging, or by observing unexpected behavior that suggests debugging features are active.
    - Step 2: The attacker attempts to access the debug directory, potentially by guessing common debug directory names or by identifying the configured `DEBUG_DIR` through misconfiguration (if exposed). For example, if `DEBUG_DIR` is set to `/tmp/debug-logs` and the web server configuration exposes `/tmp` directory, the attacker could try to access `/debug-logs`.
    - Step 3: If the debug directory is accessible via the web server, the attacker can browse and download debug log files. These files, as written by `DebugFileWriter.py`, contain generated HTML code and the "thinking process" of the LLM. This "thinking process" could reveal sensitive information about the application's internal workings, prompts used, and potentially snippets of user-provided data processed by the LLM.

- **Impact:**
    - Exposure of generated HTML code: This might not be critical on its own, but could reveal details about the application's functionality and structure that an attacker could use to find other vulnerabilities.
    - Exposure of LLM "thinking process": This is more serious as it could reveal the prompts used to interact with the LLMs, internal logic of the application, and potentially expose details about how user inputs are processed and sent to the LLMs. This information can be leveraged to craft more targeted attacks, including prompt injection attacks (though prompt injection is not a direct vulnerability of *this* application as per instructions, understanding the prompts is still valuable for attackers).
    - Depending on the content of the debug logs and the application's context, more sensitive information might be unintentionally logged and exposed.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The code checks `IS_DEBUG_ENABLED` in `DebugFileWriter.__init__` to determine if debug logging should be active.
    ```python
    class DebugFileWriter:
        def __init__(self):
            if not IS_DEBUG_ENABLED:
                return
    ```
    - This mitigation depends on the `IS_DEBUG_ENABLED` environment variable being correctly set to `False` in production environments.

- **Missing Mitigations:**
    - **Ensure `IS_DEBUG_ENABLED` is always `False` in production:** The primary missing mitigation is a robust deployment process that guarantees `IS_DEBUG_ENABLED` is set to `False` in production. This could involve infrastructure-as-code, configuration management, or CI/CD pipelines with environment-specific configurations.
    - **Restrict web server access to debug directory:** Even if debug mode is accidentally enabled, the web server should be configured to prevent public access to the `DEBUG_DIR`. This is a crucial security measure. Web server configuration (like Nginx or Apache) should explicitly deny access to this directory.
    - **Securely manage `DEBUG_DIR` location:** The `DEBUG_DIR` should be located outside the web server's document root and in a location that is not easily guessable.
    - **Regularly review and sanitize debug logs:** Implement processes to regularly review debug logs and ensure no sensitive information is inadvertently being logged. Consider log sanitization techniques to remove or mask sensitive data before it's written to logs.
    - **Consider removing debug logging in production builds:** For enhanced security, consider conditional compilation or build processes that completely remove debug logging code from production builds instead of relying solely on a configuration flag.

- **Preconditions:**
    - `IS_DEBUG_ENABLED` environment variable is set to `True` in the production environment.
    - The web server is configured to serve files from the `DEBUG_DIR` or a parent directory, making the debug logs accessible via HTTP requests.

- **Source Code Analysis:**
    - **File: `backend\config.py`**
        ```python
        IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
        DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
        ```
        - `IS_DEBUG_ENABLED` is controlled by the `IS_DEBUG_ENABLED` environment variable, defaulting to `False`.
        - `DEBUG_DIR` is controlled by the `DEBUG_DIR` environment variable, defaulting to an empty string, which might resolve to the current working directory depending on how `os.path.expanduser` is used.

    - **File: `backend\debug\DebugFileWriter.py`**
        ```python
        import os
        import logging
        import uuid

        from config import DEBUG_DIR, IS_DEBUG_ENABLED


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

            def extract_html_content(self, text: str) -> str:
                return str(text.split("<html>")[-1].rsplit("</html>", 1)[0] + "</html>")
        ```
        - The `DebugFileWriter` class is responsible for writing debug information to files.
        - The `__init__` method checks `IS_DEBUG_ENABLED`. If `False`, it effectively disables debug logging.
        - If `IS_DEBUG_ENABLED` is `True`, it creates a directory using `DEBUG_DIR` and a UUID.
        - `write_to_file` method writes content to a file within the debug directory.
        - `extract_html_content` method extracts HTML, which suggests HTML code is being logged.

    - **File: `backend\llm.py`**
        ```python
        from debug.DebugFileWriter import DebugFileWriter
        # ...
        debug_file_writer = DebugFileWriter()
        # ...
        if IS_DEBUG_ENABLED:
            debug_file_writer.write_to_file(
                f"pass_{current_pass_num - 1}.html",
                debug_file_writer.extract_html_content(response_text),
            )
            debug_file_writer.write_to_file(
                f"thinking_pass_{current_pass_num - 1}.txt",
                response_text.split("</thinking>")[0],
            )
        ```
        - In `stream_claude_response_native` function, if `IS_DEBUG_ENABLED` is true, `DebugFileWriter` is used to write HTML code and thinking process to files.

    - **Visualization:**

    ```mermaid
    graph LR
        A[Request to Backend] --> B{IS_DEBUG_ENABLED == True?};
        B -- Yes --> C[DebugFileWriter Created];
        B -- No --> NoDebug[No Debug Logging];
        C --> D{stream_claude_response_native};
        D -- During LLM Stream --> E[DebugFileWriter.write_to_file (HTML & Thinking)];
        E --> F[Debug Logs in DEBUG_DIR];
        F --> G[Web Server Serves DEBUG_DIR?];
        G -- Yes --> H[Information Disclosure Vulnerability];
        G -- No --> NoVuln[No Vulnerability (in this path)];
    ```

- **Security Test Case:**
    - Step 1: Deploy the `screenshot-to-code` application in a test environment, ensuring that `IS_DEBUG_ENABLED=True` environment variable is set. Configure the web server (e.g., Nginx, Apache) to serve the directory specified by `DEBUG_DIR` (e.g., `/tmp/debug-logs`) at a publicly accessible URL path, for example, `/debug-logs`.
    - Step 2: Use the application to convert a screenshot to code. This will trigger the debug logging in `llm.py`.
    - Step 3: As an external attacker, try to access the debug log directory through the web browser by navigating to the configured URL path (e.g., `http://<your-app-domain>/debug-logs`).
    - Step 4: If directory listing is enabled, you should see a list of directories corresponding to UUIDs created by `DebugFileWriter`.
    - Step 5: Enter one of the UUID directories. You should see files like `pass_1.html`, `thinking_pass_1.txt`, `full_stream.txt`.
    - Step 6: Open and examine the content of these files. Verify that they contain generated HTML code and the thinking process of the LLM, confirming information disclosure.

This test case, if successful, proves that debug logs are being written and are accessible via the web, validating the information disclosure vulnerability.

- **Vulnerability Name:** Directory Traversal in Evals Routes

- **Description:**
    - Step 1: An attacker identifies the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
    - Step 2: The attacker crafts a malicious request to one of these endpoints, providing a manipulated `folder`, `folder1`, `folder2`, etc. query parameter containing directory traversal sequences like `../` to access directories outside of the intended evaluation directory.
    - Step 3: The backend application uses `os.listdir` and `os.path.join` to process files within the user-provided folder path without proper sanitization or validation.
    - Step 4: If successful, the attacker can read files and directories outside the intended evaluation directory, potentially gaining access to sensitive information, application code, or configuration files.

- **Impact:**
    - Information Disclosure: Attackers can read arbitrary files on the server file system that the application has access to. This could include source code, configuration files, environment variables, or other sensitive data.
    - Potential for further exploitation: Depending on the server configuration and accessed files, directory traversal can be a stepping stone for more severe attacks like Remote Code Execution (if they can access configuration files with credentials or upload files - although upload functionality is not directly visible in provided files).

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None in the provided code. The application checks if the folder exists using `folder_path.exists()`, but not if the path is within allowed boundaries or sanitized against directory traversal.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:**  The application must validate and sanitize the `folder` parameters in `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints to prevent directory traversal. This should include:
        - Whitelisting allowed base directories for evaluations.
        - Using secure path manipulation functions that prevent traversal outside of the intended directories (e.g., `os.path.abspath` and checking if it starts with the allowed base path).
        - Rejecting paths containing directory traversal sequences like `../`.
    - **Principle of Least Privilege:** Ensure that the application process runs with minimal necessary privileges to reduce the impact of a successful directory traversal attack.

- **Preconditions:**
    - The application must be running and accessible to external attackers.
    - The attacker must be able to send HTTP GET requests to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.

- **Source Code Analysis:**
    - **File: `backend\routes\evals.py`**
        - **`get_evals` function:**
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
                    # ... rest of the code
            ```
            - The `folder` parameter from the query is directly used in `os.path.join` and `os.listdir` without any sanitization. An attacker can inject `../` sequences in the `folder` parameter to traverse directories.
        - **`get_pairwise_evals` and `get_best_of_n_evals` functions:** These functions have similar code patterns and are also vulnerable as they process `folder1`, `folder2` etc. parameters in the same insecure way.

- **Security Test Case:**
    - Step 1: Deploy the application in a test environment.
    - Step 2: As an external attacker, craft a malicious GET request to `/evals` endpoint with a directory traversal payload in the `folder` parameter. For example: `http://<your-app-domain>/evals?folder=../../backend/config.py` (assuming `backend/config.py` is outside the intended eval directory).
    - Step 3: Send the request and observe the response.
    - Step 4: If the vulnerability exists, the response body might contain an error because it tries to process `config.py` as an HTML file, or it might list files from the directory where `config.py` is located, or in some cases, if the web server is configured to serve static files, it might even serve the content of `config.py` directly if it's in a served directory. A successful test would be if you can observe access to files or directories outside the expected evaluation directory.
    - Step 5: Try to access sensitive files like application configuration files to confirm information disclosure. For example: `http://<your-app-domain>/evals?folder=../../backend/config.py`.
