### Vulnerability List:

- Vulnerability Name: API Key Exposure through Client-Side Settings

- Description:
    1. The application allows users to configure API keys for OpenAI, Anthropic, and Replicate services via a settings dialog in the frontend.
    2. These API keys, once entered by the user, are stored in the browser's local storage.
    3. Local storage in web browsers is accessible to JavaScript code running within the same origin (domain, protocol, and port).
    4. Malicious browser extensions, cross-site scripting (XSS) vulnerabilities (if present in the frontend, though not evident in provided files), or malware running on the user's machine could potentially access and exfiltrate these API keys from the browser's local storage.
    5. An attacker who obtains these API keys can then impersonate the user and make API requests to OpenAI, Anthropic, or Replicate services using the user's credentials.

- Impact:
    - **Unauthorized API Access:** An attacker can use the stolen API keys to access the AI services (OpenAI, Anthropic, Replicate) without the user's authorization.
    - **Financial Impact:** If the compromised API keys are linked to a paid account, the attacker could incur significant costs by making requests to the AI services, which will be billed to the legitimate user's account.
    - **Data Access (Potentially Limited):** While primarily for screenshot-to-code functionality, the API keys might grant broader access to the user's AI service account depending on the permissions associated with the key. If the keys are not restricted to this specific application, attackers might access other data or functionalities within the AI service account.
    - **Reputational Damage:** If user accounts are compromised and costs are incurred, it can lead to negative user sentiment and damage the reputation of the screenshot-to-code tool.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None evident from the provided backend files regarding secure storage of API keys entered via the settings dialog. The README mentions "Your key is only stored in your browser. Never stored on our servers.", indicating intended client-side storage without server-side handling.

- Missing Mitigations:
    - **Backend Key Management:** API keys should ideally be managed securely on the backend server, not stored directly in the client-side browser storage. The frontend should send requests to the backend, which in turn uses the server-side stored API keys to interact with the AI services.
    - **Secure Credential Storage:** If client-side storage is absolutely necessary, consider using more secure browser storage mechanisms like the browser's Credential Management API, although local storage is used as stated in README.
    - **API Key Scoping and Restrictions:** Users should be guided to create API keys specifically scoped and restricted for use with this application, limiting potential damage if keys are compromised. Documenting best practices for API key creation and management is essential.
    - **Regular Security Audits:** Conduct regular security audits and penetration testing to identify and address potential vulnerabilities, including client-side security issues.

- Preconditions:
    - User must enter their OpenAI API key, Anthropic API key or Replicate API token into the settings dialog of the screenshot-to-code application.
    - An attacker needs to be able to access the user's browser local storage. This could be achieved through:
        - Malicious browser extension installed by the user.
        - Cross-Site Scripting (XSS) vulnerability in the frontend application (not confirmed in provided files, but a possibility for web applications).
        - Malware or unauthorized access to the user's computer.

- Source Code Analysis:
    1. **`backend\routes\generate_code.py`**:
        - The `get_from_settings_dialog_or_env` function is used to retrieve API keys. This function checks for keys in the `params` dictionary, which are received from the frontend (settings dialog).
        - ```python
          def get_from_settings_dialog_or_env(
              params: dict[str, str], key: str, env_var: str | None
          ) -> str | None:
              value = params.get(key)
              if value:
                  print(f"Using {key} from client-side settings dialog") # Indicates keys can come from client
                  return value

              if env_var:
                  print(f"Using {key} from environment variable")
                  return env_var

              return None
          ```
        - This confirms that the application is designed to accept API keys from the "client-side settings dialog".
    2. **`..\screenshot-to-code\README.md`**:
        - The README file in the root directory, under "🛠 Getting Started" and "You can also set up the keys using the settings dialog on the front-end (click the gear icon after loading the frontend).", explicitly documents the settings dialog as a method to input API keys, suggesting client-side storage is the intended approach.
        - In "Troubleshooting.md" under step 7: "Go to Screenshot to code and paste it in the Settings dialog under OpenAI key (gear icon). Your key is only stored in your browser. Never stored on our servers." - explicitly states client-side browser storage.

- Security Test Case:
    1. **Precondition:** Have a running instance of the screenshot-to-code application.
    2. **Step 1:** Open the screenshot-to-code application in a web browser (e.g., `http://localhost:5173`).
    3. **Step 2:** Open the application's settings dialog (usually accessible by clicking a gear icon as mentioned in README).
    4. **Step 3:** Enter a valid OpenAI API key into the "OpenAI API Key" field in the settings dialog. Save the settings.
    5. **Step 4:** Open the browser's developer tools (usually by pressing F12).
    6. **Step 5:** Navigate to the "Application" tab (or "Storage" tab in some browsers) in the developer tools.
    7. **Step 6:** In the sidebar of the "Application" tab, select "Local Storage" and then the origin of the screenshot-to-code application (e.g., `http://localhost:5173`).
    8. **Step 7:** Look for keys that might store the API key (e.g., keys with names like `openAiApiKey`, `anthropicApiKey`, `replicateApiKey`, or similar).
    9. **Step 8:** If the API key entered in Step 3 is found in the local storage in plain text or easily decodable format, the vulnerability is confirmed.
    10. **Step 9 (Optional - further impact validation):** Copy the extracted API key. Use a tool like `curl` or the OpenAI Python library to make an API request to OpenAI using the stolen key (e.g., list models or create a simple chat completion). If the API request is successful, it further confirms that the exposed key is valid and can be used by an attacker.

This test case demonstrates that an attacker with access to the browser's local storage can retrieve the API keys entered by the user, confirming the vulnerability.

- Vulnerability Name: Path Traversal in Evals Folder Paths

- Description:
    1. The application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` that allow users to retrieve evaluation results from specified folders.
    2. These endpoints, as implemented in `backend\routes\evals.py`, take folder paths as input parameters (`folder`, `folder1`, `folder2`, `folder{i}`).
    3. The application uses these folder paths directly with functions like `os.listdir()` and `os.path.join()` without sufficient validation or sanitization to prevent path traversal attacks.
    4. An attacker can manipulate these folder path parameters by injecting path traversal sequences like `../` or `../../` to navigate outside the intended evaluation directories (under `EVALS_DIR`) and access arbitrary files or directories on the server's filesystem.
    5. By exploiting this vulnerability, an attacker could read sensitive configuration files, source code, or other application data that the server process has access to.

- Impact:
    - **Unauthorized File Access:** An attacker can read arbitrary files and directories on the server's filesystem that the backend application has permissions to access.
    - **Information Disclosure:** Sensitive information, such as configuration files, application source code, environment variables, or data files, could be exposed to the attacker.
    - **Potential for Further Exploitation:** Access to sensitive files could be a stepping stone for further attacks, such as escalating privileges, modifying application behavior, or compromising the entire server.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code uses `os.path.exists()` to check if the folder exists, but this does not prevent path traversal as an attacker can still provide a path that exists after traversal. There is no input sanitization or validation of the folder paths to prevent traversal beyond intended directories.

- Missing Mitigations:
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for all folder path parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints.
        - **Path Canonicalization:** Convert user-provided paths to their canonical form using `os.path.realpath()` or similar functions and then check if the canonical path is within the allowed base directory (e.g., `EVALS_DIR`).
        - **Path Filtering/Validation:** Implement checks to ensure that the provided paths do not contain path traversal sequences like `../`. Alternatively, use a whitelist approach to only allow predefined or expected folder paths.
    - **Principle of Least Privilege:** Ensure that the backend application process runs with the minimum necessary privileges to reduce the impact of potential vulnerabilities. Avoid running the application with root or overly permissive user accounts.

- Preconditions:
    - The screenshot-to-code application must be running, and the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints must be accessible to the attacker.
    - The attacker must be able to send HTTP GET requests to these endpoints.
    - The server's filesystem must contain files or directories outside the intended `EVALS_DIR` that the attacker wishes to access and that the backend process has permissions to read.

- Source Code Analysis:
    1. **`backend\routes\evals.py`**:
        - The functions `get_evals`, `get_pairwise_evals`, and `get_best_of_n-evals` in `evals.py` handle the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` routes respectively.
        - All of these functions take folder paths as input from query parameters (`folder`, `folder1`, `folder2`, `folder{i}`).
        - For example, in `get_evals`, the `folder` parameter is directly used to construct file paths:
        ```python
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str):
            # ...
            folder_path = Path(folder) # Path object is created, but no sanitization
            if not folder_path.exists(): # Only existence is checked, not path validity
                raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
            # ...
            files = {
                f: os.path.join(folder, f) # User-provided folder is directly joined
                for f in os.listdir(folder) # User-provided folder is directly used for listing
                if f.endswith(".html")
            }
            # ...
        ```
        - Similarly, `get_pairwise_evals` and `get_best_of_n_evals` also directly use the provided folder paths in `os.listdir()` and `os.path.join()`:
        ```python
        @router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
        async def get_pairwise_evals(folder1: str = Query("...", description="Absolute path to first folder"), folder2: str = Query("..", description="Absolute path to second folder")):
            # ...
            files1 = {
                f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html")
            } # folder1 is directly used
            files2 = {
                f: os.path.join(folder2, f) for f in os.listdir(folder2) if f.endswith(".html")
            } # folder2 is directly used
            # ...
        ```
        - The code only checks if the folder exists using `os.path.exists()`, but it does not validate if the path is within the intended directories or sanitize it to prevent path traversal.

- Security Test Case:
    1. **Precondition:** Have a running instance of the screenshot-to-code application backend. Assume `EVALS_DIR` is set to `/app/evals` within the container, and there is a sensitive file located at `/app/sensitive.txt`.
    2. **Step 1:** Identify the base URL of the backend API (e.g., `http://localhost:8000`).
    3. **Step 2:** Craft a GET request to the `/evals` endpoint with a path traversal payload in the `folder` parameter to access the sensitive file. For example:
       `http://localhost:8000/evals?folder=../../../sensitive.txt`
    4. **Step 3:** Send the crafted request to the backend server using a tool like `curl` or a web browser.
    5. **Step 4:** Analyze the response from the server.
        - **Expected Vulnerable Behavior:** If the application is vulnerable to path traversal, the server might attempt to process the path `../../../sensitive.txt`. If `sensitive.txt` exists and the backend process has read permissions, the server might throw an error while trying to list files in a file (as it's trying to `listdir` on a file path) or, in a worst-case scenario, attempt to read the contents of `sensitive.txt` as if it were an HTML file, potentially causing an error during HTML parsing but indicating file access. A successful exploit might be harder to directly confirm via response in this specific `/evals` endpoint because it expects HTML files, but errors indicating file operations outside of expected directories would suggest the vulnerability.
        - **Improved Test for Confirmation:** To more directly confirm unauthorized file *reading*, a better test case would involve modifying the code to *return* the contents of the file if it were successfully opened (for testing purposes only and not for production).  Alternatively, monitor server-side logs to see if file access attempts are made outside of the expected directories when the path traversal payload is sent.
    6. **Step 5 (Log Analysis - more practical for this case):** Examine the server-side application logs. Look for log entries that indicate file system operations (like `os.listdir` or `open`) being performed on paths that include the traversal sequences (`../../../`) or point outside the expected evaluation directories. If such log entries are found when the malicious request is sent, it confirms that the path traversal is occurring on the server.

This test case, especially with log analysis, will demonstrate if the application attempts to access files outside the intended directories using the user-provided path, thus confirming the path traversal vulnerability.
