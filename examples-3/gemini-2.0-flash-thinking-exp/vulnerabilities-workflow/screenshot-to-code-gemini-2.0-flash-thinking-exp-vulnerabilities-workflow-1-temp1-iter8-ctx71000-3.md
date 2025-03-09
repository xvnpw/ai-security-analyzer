### Vulnerability List for screenshot-to-code Project

* Vulnerability Name: API Key Exposure via Debug Logs

* Description:
    1. The application has a debug mode enabled via the `IS_DEBUG_ENABLED` environment variable.
    2. When debug mode is active, the `DebugFileWriter` class in `backend/debug/DebugFileWriter.py` is instantiated.
    3. The `DebugFileWriter` class is used in `backend/llm.py` within the `stream_claude_response_native` function.
    4. Inside `stream_claude_response_native`, when `IS_DEBUG_ENABLED` is true, the complete LLM stream (`full_stream`) is written to a file named `full_stream.txt` in the debug directory.
    5. If the system prompt or messages sent to the LLM inadvertently include API keys or other sensitive information (e.g., through environment variables not properly filtered or logged requests containing keys), these secrets will be logged in plain text to the debug files.
    6. If the debug directory is publicly accessible or can be accessed by an attacker, these log files could be read, leading to the exposure of sensitive API keys.

* Impact:
    Compromise of API keys. If OpenAI, Anthropic, Gemini or Replicate API keys are exposed, an attacker could:
    - Consume the victim's API credits.
    - Potentially gain access to other services or data associated with the exposed API keys, depending on the permissions and scope of the keys.
    - Incur significant costs for the application owner due to unauthorized API usage.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None in the code itself to prevent logging of sensitive information.
    - The README.md mentions setting API keys via environment variables or UI settings dialog, suggesting secure key management is intended, but the debug logging mechanism undermines this intention in debug mode.

* Missing Mitigations:
    - **Secure logging practices:** Implement filtering or scrubbing of sensitive data from debug logs before writing them to disk. Specifically, API keys and any other credentials should be identified and removed or replaced with placeholders in the logs.
    - **Restrict access to debug logs:** Ensure that the debug directory (`DEBUG_DIR`) is not publicly accessible in production environments. Implement proper access controls to limit access to these files to authorized personnel only.
    - **Disable debug mode in production:**  `IS_DEBUG_ENABLED` should be set to `False` by default and explicitly disabled in production deployments to minimize the risk of accidental exposure through debug logs.

* Preconditions:
    - `IS_DEBUG_ENABLED` environment variable is set to `True` in a publicly accessible instance.
    - Sensitive information (API keys) is inadvertently included in the prompts or messages sent to the LLM, or in other data processed during the LLM call within debug scope.
    - The debug directory specified by `DEBUG_DIR` is accessible to external attackers (e.g., due to misconfiguration of web server or file permissions).

* Source Code Analysis:
    1. **`backend/config.py`**:
       ```python
       IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
       DEBUG_DIR = os.environ.get("DEBUG_DIR", "")
       ```
       - `IS_DEBUG_ENABLED` is controlled by environment variable `IS_DEBUG_ENABLED`.
       - `DEBUG_DIR` is controlled by environment variable `DEBUG_DIR`.

    2. **`backend/debug/DebugFileWriter.py`**:
       ```python
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
       ```
       - `DebugFileWriter` is active only if `IS_DEBUG_ENABLED` is true.
       - Writes content to files within `DEBUG_DIR`.

    3. **`backend/llm.py`**:
       ```python
       from debug.DebugFileWriter import DebugFileWriter
       # ...
       async def stream_claude_response_native( ... ):
           # ...
           full_stream = ""
           debug_file_writer = DebugFileWriter()
           # ...
           async with client.messages.stream( ... ) as stream:
               async for text in stream.text_stream:
                   print(text, end="", flush=True)
                   full_stream += text
                   await callback(text)
           # ...
           if IS_DEBUG_ENABLED:
               debug_file_writer.write_to_file("full_stream.txt", full_stream)
           # ...
       ```
       - `DebugFileWriter` is instantiated in `stream_claude_response_native`.
       - The entire `full_stream` variable, which contains the raw response from Claude API (potentially including prompts if echoed back, or sensitive data in error messages), is written to `full_stream.txt` if `IS_DEBUG_ENABLED` is true.

    **Visualization:**

    ```
    [Request to /generate-code endpoint] --> backend/main.py --> backend/routes/generate_code.py --> backend/evals/core.py --> backend/llm.py (stream_claude_response_native)
                                                                                                                    |
                                                                                                                    | [IS_DEBUG_ENABLED = True]
                                                                                                                    V
    DebugFileWriter (backend/debug/DebugFileWriter.py) --> Writes full_stream to full_stream.txt in DEBUG_DIR
    ```

* Security Test Case:
    1. **Setup:** Deploy the `screenshot-to-code` application in a test environment and ensure that `IS_DEBUG_ENABLED` is set to `True`.  Make sure the `DEBUG_DIR` is within the accessible web root or simulate an attacker gaining access to files in that directory.
    2. **Trigger Vulnerability:** Send a request to the application to generate code. Ensure that the environment variables (including API keys) are set such that they *could* potentially be logged if included in the prompt (even though the prompts are designed to not include them directly, this step simulates a scenario where sensitive info *could* end up in logs).  For example, trigger code generation using Claude models, as the vulnerable logging is in `stream_claude_response_native`.
    3. **Access Debug Logs:** As an attacker, attempt to access the debug log file `full_stream.txt` within the `DEBUG_DIR`. This could be through direct file access if the directory is publicly served, or by exploiting other vulnerabilities to read files from the server.
    4. **Verify API Key Exposure:** Open `full_stream.txt` and examine its contents. Check if the OpenAI, Anthropic, Gemini or Replicate API keys are present in the log file. If API keys or other sensitive information are found in the log file, the vulnerability is confirmed.

This vulnerability allows for potential exposure of sensitive API keys if debug mode is inadvertently left enabled in production and if logs become accessible to attackers.

* Vulnerability Name: Path Traversal in Evals Endpoints

* Description:
    1. The application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` which take user-controlled folder paths as input through the `folder` query parameter.
    2. In `backend/routes/evals.py`, the application uses the user-provided `folder` path directly with `os.listdir()` and `os.path.join()` to access files.
    3. There are no checks to validate or sanitize the `folder` path to ensure it stays within the intended directories (e.g., under `EVALS_DIR`).
    4. An attacker can manipulate the `folder` parameter to include directory traversal sequences like `../` to access files and directories outside the intended evaluation folders.
    5. By crafting malicious `folder` paths, an attacker can read arbitrary files from the server's filesystem that the application process has access to.

* Impact:
    Arbitrary File Read. An attacker can read sensitive files on the server, such as configuration files, application source code, or other data, potentially leading to information disclosure and further attacks.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The application checks if the provided `folder` exists using `folder_path.exists()`. This is not a security mitigation for path traversal, as it only verifies the existence of the potentially traversed path.

* Missing Mitigations:
    - **Path Sanitization and Validation:** Implement robust path sanitization to remove or neutralize directory traversal characters (e.g., `..`, `/`, `\`).
    - **Path Allowlisting/Denylisting:**  Validate the user-provided `folder` path against an allowlist of allowed directories or a denylist of forbidden patterns. Ensure the path is within a safe base directory, like `EVALS_DIR`.
    - **Secure Path Manipulation:** Utilize secure path manipulation functions provided by the operating system or libraries that prevent traversal (e.g., `os.path.abspath` and checking if it starts with the allowed base path).

* Preconditions:
    - The application is deployed and accessible to an external attacker.
    - The attacker identifies the vulnerable endpoints: `/evals`, `/pairwise-evals`, or `/best-of-n-evals`.

* Source Code Analysis:
    1. **`backend/routes/evals.py`**:
       ```python
       @router.get("/evals", response_model=list[Eval])
       async def get_evals(folder: str):
           folder_path = Path(folder) # User-controlled path is directly used
           if not folder_path.exists():
               raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

           files = {
               f: os.path.join(folder, f) # User-controlled path is joined with filenames
               for f in os.listdir(folder) # User-controlled path is used for listing directory
               if f.endswith(".html")
           }
           # ... rest of the code
       ```
       - The `folder` parameter, directly from user input, is used to create a `Path` object, list directory contents with `os.listdir()`, and construct file paths using `os.path.join()`.
       - No path sanitization or validation is performed to prevent directory traversal.
       - Similar vulnerable code patterns exist in `/pairwise-evals` and `/best-of-n-evals` endpoints in the same file.

* Security Test Case:
    1. **Setup:** Deploy the `screenshot-to-code` application in a test environment. Assume `EVALS_DIR` is `/app/backend/evals`. Create a folder `/tmp/test_evals_outside` and place a file named `test.html` with content `<h1>External Eval File</h1>` inside it (`/tmp/test_evals_outside/test.html`). Also ensure there is an input image at `/app/backend/evals/inputs/test_outside.png`.
    2. **Trigger Vulnerability:** Send a GET request to the `/evals` endpoint with the `folder` parameter pointing to the externally created folder: `/evals?folder=/tmp/test_evals_outside`.
    3. **Analyze Response:** Examine the response from the `/evals` endpoint. If the vulnerability is present, the response should include an `Eval` object. This `Eval` object should contain the content of `/tmp/test_evals_outside/test.html` as one of its outputs, and an input from a corresponding image if found based on filename logic (or a default image if not, but the output HTML content is the key indicator here).
    4. **Verify Arbitrary File Read:** If step 3 is successful, it demonstrates that the application is reading files from a location outside the intended `EVALS_DIR` based on user input. This confirms the Path Traversal vulnerability. For further confirmation and to assess impact, attempt to access more sensitive files, if possible within the test environment, being mindful of ethical testing boundaries.

This vulnerability allows an attacker to read arbitrary files from the server by manipulating the folder path provided to the evals endpoints.
