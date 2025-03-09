### Vulnerability List:

- **Vulnerability Name:** API Key Exposure via Misconfigured Debug Mode

- **Description:**
    If the `IS_DEBUG_ENABLED` environment variable is set to `True` in a production environment, the application will write debug artifacts, including the prompts sent to the LLMs, to a publicly accessible directory if `DEBUG_DIR` is not properly configured and secured. These prompts could potentially contain sensitive information, including API keys if they are inadvertently included in the prompt construction logic or logged during debugging. While the current code does not explicitly log API keys in prompts, future modifications or less careful prompt engineering could lead to accidental inclusion.

- **Impact:**
    High. Exposure of API keys could lead to unauthorized usage of the LLM services, resulting in financial costs for the project owner and potential misuse of the LLM services by malicious actors. Depending on the scope of access granted by the exposed API keys, attackers might be able to perform actions beyond the intended use of the `screenshot-to-code` application, such as training models or accessing other data associated with the API accounts.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The code reads API keys from environment variables, which is a standard practice to avoid hardcoding secrets in the source code.
    - The `IS_DEBUG_ENABLED` flag is intended to be used only in development environments.

- **Missing Mitigations:**
    - **Secure Default for `DEBUG_DIR`:** The default value for `DEBUG_DIR` is an empty string, which might resolve to a location within the application's working directory, potentially making debug artifacts publicly accessible if the web server is misconfigured or serving static files from the application root. A more secure default, outside the web server's document root, should be enforced.
    - **Strict Configuration Validation:** The application should validate that `IS_DEBUG_ENABLED` is set to `False` in production environments and potentially log a warning or refuse to start if it is set to `True` in production.
    - **API Key Sanitization in Debug Logs:** Implement a mechanism to sanitize or redact API keys and other sensitive information from debug logs before writing them to files.
    - **Access Control for Debug Directory:**  Ensure that the directory specified by `DEBUG_DIR` is properly secured with appropriate access controls to prevent unauthorized access, even if it's not intended to be publicly accessible.

- **Preconditions:**
    - `IS_DEBUG_ENABLED` environment variable is set to `True` in a production deployment.
    - `DEBUG_DIR` is not securely configured and points to a publicly accessible directory, or defaults to a location within the web server's document root.
    - The web server is configured to serve static files from the `DEBUG_DIR` location.
    - Prompts constructed for LLM calls, or debug logging, inadvertently includes API keys or other secrets.

- **Source Code Analysis:**
    1. **`backend\config.py`:**
        - The `IS_DEBUG_ENABLED` flag is read from the environment variable `MOCK`. It's converted to a boolean using `bool(os.environ.get("MOCK", False))`.
        - `DEBUG_DIR` is read from the environment variable `DEBUG_DIR`.
    2. **`backend\debug\DebugFileWriter.py`:**
        - The `DebugFileWriter` class is initialized only if `IS_DEBUG_ENABLED` is `True`.
        - `self.debug_artifacts_path` is constructed using `DEBUG_DIR` and a UUID. If `DEBUG_DIR` is empty, it will default to the current working directory of the backend application.
        - `write_to_file` method writes content to files within `self.debug_artifacts_path`.
    3. **`backend\llm.py` & other backend modules using DebugFileWriter:**
        - If `IS_DEBUG_ENABLED` is `True`, `DebugFileWriter` instance is created and used to write debug information, including prompts and generated code, to files in the `DEBUG_DIR`. For example, `stream_claude_response_native` in `llm.py` uses `DebugFileWriter` to log intermediate outputs and full streams.
    4. **`docker-compose.yml` & Dockerfiles:**
        - The Docker setup does not explicitly prevent setting `MOCK=true` or `IS_DEBUG_ENABLED=true` in production. If the `.env` file used in production contains `MOCK=true` or if `IS_DEBUG_ENABLED=true` is set directly in the environment, debugging will be enabled.

- **Security Test Case:**
    1. **Setup:** Deploy the `screenshot-to-code` application using Docker Compose, ensuring that the backend and frontend are running in a publicly accessible environment.
    2. **Modify `.env` in the backend:** Set `MOCK=true` in the `.env` file used by the backend Docker container. This will set `IS_DEBUG_ENABLED` to `True`. Also, ensure `DEBUG_DIR` is set to a publicly accessible path within the web server's root or leave it empty to default to the working directory.
    3. **Trigger Code Generation:** Use the frontend to upload a screenshot and trigger the code generation process. This will cause the backend to generate code and, due to `IS_DEBUG_ENABLED=True`, write debug artifacts to the `DEBUG_DIR`.
    4. **Access Debug Directory:** Attempt to access the `DEBUG_DIR` path via a web browser. If the web server is misconfigured to serve static files from this location, you should be able to list the files and download the debug artifacts.
    5. **Inspect Debug Artifacts:** Download and inspect the debug artifact files (e.g., `full_stream.txt`, `pass_1.html`). Check if any of these files contain sensitive information, such as API keys, or parts of the prompts that could reveal sensitive data if prompts are modified to include such information in the future.
    6. **Expected Result:** If the setup is vulnerable, you should be able to access and download debug artifacts and potentially find sensitive information within them. If the setup is secure, you should not be able to access the debug directory or find sensitive data in publicly accessible locations even with debug mode enabled.

This vulnerability highlights a risk associated with enabling debug mode in production and misconfiguring the debug output directory, potentially leading to information disclosure. While not directly exposing API keys in the current code, it creates a pathway for potential future exposure and information leakage through debug logs.

- **Vulnerability Name:** Path Traversal in Evaluation Routes

- **Description:**
    The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` routes in `backend\routes\evals.py` are vulnerable to path traversal. These routes accept user-provided folder paths as query parameters and use them to read files.  Insufficient validation of these folder paths allows an attacker to provide paths like `../../../../` to access files outside the intended evaluation directories. This can lead to arbitrary file reading on the server.

- **Impact:**
    High. An attacker can read arbitrary files on the server, potentially gaining access to sensitive information such as configuration files, source code, environment variables, or other application data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The code checks if the provided folder exists using `os.path.exists()`. However, this check does not prevent path traversal as it doesn't validate if the path is within an allowed directory or sanitize the path for traversal sequences.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation for the `folder`, `folder1`, `folder2`, and `folder{i}` parameters in the evaluation routes. Sanitize these paths to prevent path traversal sequences (e.g., `../`).
    - **Path Restriction:** Restrict the allowed folder paths to a predefined set of directories or enforce that the provided paths are within a specific base directory. Use secure path manipulation functions that prevent traversal, rather than relying on `os.path.join` alone without validation.

- **Preconditions:**
    - The backend application is deployed and publicly accessible.
    - The `/evals`, `/pairwise-evals`, or `/best-of-n-evals` routes are exposed and accessible to external users.

- **Source Code Analysis:**
    1. **`backend\routes\evals.py`:**
        - **`/evals` route:**
            - The `get_evals` function takes a `folder` query parameter.
            - It uses `Path(folder).exists()` to check if the folder exists.
            - It uses `os.listdir(folder)` and `os.path.join(folder, f)` to access files within the provided folder.
        - **`/pairwise-evals` route:**
            - The `get_pairwise_evals` function takes `folder1` and `folder2` query parameters.
            - It uses `os.path.exists(folder1)` and `os.path.exists(folder2)` to check if the folders exist.
            - It uses `os.listdir(folder1)`, `os.listdir(folder2)`, `os.path.join(folder1, f)`, and `os.path.join(folder2, f)` to access files within the provided folders.
        - **`/best-of-n-evals` route:**
            - The `get_best_of_n_evals` function takes multiple `folder{i}` query parameters.
            - It uses `os.path.exists(folder)` to check if each folder exists.
            - It uses `os.listdir(folder)`, `os.path.join(folder, f)` to access files within the provided folders.
    2. **Vulnerability Point:** In all three routes, the lack of input validation and sanitization on the folder paths before using them in `os.listdir` and `os.path.join` creates a path traversal vulnerability. An attacker can manipulate the `folder` parameters to access directories outside the intended evaluation folders.

- **Security Test Case:**
    1. **Setup:** Deploy the `screenshot-to-code` application in a publicly accessible environment.
    2. **Identify Target File:** Assume there's a file on the server you want to read, for example, a file named `test_traversal.txt` in the root directory of the application backend, or try to access `/etc/passwd` if possible in the deployment environment.
    3. **Send Path Traversal Request to `/pairwise-evals`:**
        - Construct a GET request to `/pairwise-evals` endpoint.
        - Set `folder1` to a valid existing folder within the intended evaluation directory (e.g., you might need to create a dummy folder with some `.html` files if the route expects to process them). If you know the `EVALS_DIR` from `evals.config.py`, you can use a subdirectory within it. Otherwise, any existing folder in the application directory might work temporarily.
        - Set `folder2` to the path traversal payload to access the target file. For example: `folder2=../../test_traversal.txt` or `folder2=../../../../../../etc/passwd`.
        - Send the crafted GET request to the `/pairwise-evals` endpoint.
    4. **Analyze the Response:**
        - Examine the HTTP response. If successful path traversal occurs, the server might attempt to process the content of the traversed file (e.g., `/etc/passwd` or `test_traversal.txt`) as HTML, leading to errors or unexpected behavior in the response. Look for error messages that might indicate the server tried to read or process the content of the file you attempted to access via path traversal.
        - If you placed `test_traversal.txt` within the application root, and you can induce the application to attempt to read and process it (even if it results in an error because it's not HTML), it confirms the path traversal vulnerability.  The goal is to demonstrate that you can influence the file paths used by the application to access files outside of the intended directories.
    5. **Expected Result:** If the application is vulnerable, you should observe behavior indicating that the server attempted to access or process the file specified by the path traversal payload. This might manifest as errors related to file processing, or in some cases, if the application directly returns file content, you might even retrieve the content of the traversed file (though less likely in this specific application context, it confirms the vulnerability). The key is to show that the path traversal attempt was successful in making the application access a file outside of its intended scope based on user-controlled input.
