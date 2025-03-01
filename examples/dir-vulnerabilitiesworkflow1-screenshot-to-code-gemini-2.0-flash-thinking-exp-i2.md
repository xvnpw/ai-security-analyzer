## Combined Vulnerability List

### Vulnerability Name: Path Traversal in Evaluation Folder Access

* Description:
    1. An attacker identifies the API endpoints related to evaluations, such as `/evals`, `/pairwise-evals`, or `/best-of-n-evals` in `backend/routes/evals.py`. These endpoints accept folder paths as parameters (e.g., `folder`, `folder1`, `folder2`, etc.) to read evaluation files.
    2. The attacker sends a GET request to one of these endpoints, such as `/evals`.
    3. The attacker crafts a malicious folder path parameter, attempting to traverse directories, for example: `../../../../etc/passwd`. For `/evals` endpoint, the parameter is `folder`, resulting in a request like `/evals?folder=../../../../etc/passwd`.
    4. The backend application receives this request and uses the provided folder path directly with `os.listdir()` and `os.path.join()` without proper validation or sanitization. Specifically, in functions like `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals`, the code constructs file paths using `os.path.join(folder, f)` and `os.path.join(EVALS_DIR, "inputs", f"{base_name}.png")` where `folder` is directly taken from the query parameter.
    5. `os.listdir()` lists files and directories within the path specified by the attacker, and `os.path.join()` constructs file paths based on the attacker-controlled `folder` parameter.
    6. If the attacker-provided path leads to a directory containing `.html` files (for `/evals`) or other expected files and is readable by the application, the application proceeds to read these files.
    7. If successful, the attacker can potentially read the content of arbitrary files on the server's filesystem, depending on file permissions and the application's execution context. This is because the application might try to access files outside of the intended `EVALS_DIR`.

* Impact:
    - **Information Disclosure**: Successful exploitation allows an attacker to read arbitrary files from the server. This could include sensitive data such as configuration files, application source code, internal application data, or even system files if permissions allow.
    - Unauthorized file access: Attackers can read sensitive files on the server, potentially including configuration files, source code, data files, or credentials, depending on file system permissions and the application's access rights.
    - Exposure of sensitive information can lead to further attacks or compromise the application's security and user data.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The code checks if the provided folder exists using `folder_path.exists()` in the `/evals` endpoint, but this does not prevent path traversal as it doesn't validate if the path is within an allowed base directory.  In general, across evaluation endpoints, there is no apparent validation or sanitization against path traversal attacks.

* Missing Mitigations:
    - **Input Validation and Sanitization**: Implement robust validation for all folder path parameters received from user requests. Sanitize paths to remove path traversal sequences (e.g., `../`, `..\\`) and ensure that the paths stay within the intended directories (e.g., within `EVALS_DIR`). This could involve:
        - **Whitelisting**: Define a set of allowed base directories (like `EVALS_DIR`) and verify that the provided path is a subdirectory of one of these allowed directories.
        - **Path Canonicalization**: Convert both the user-provided path and the allowed base directory to their canonical forms (e.g., by resolving symbolic links and removing redundant separators like `..`) and check if the user-provided path starts with the allowed base directory.
        - **Blacklisting dangerous characters**: Although less robust than whitelisting, blacklisting characters like `../` could offer a basic level of protection but is generally not recommended as it can be bypassed.
    - **Secure Path Manipulation**: Utilize secure path manipulation functions that prevent path traversal, ensuring that any file access remains within the intended boundaries. Use secure file path handling techniques to prevent path traversal. For example, use functions that resolve paths to their canonical form and check if they are within the allowed base directory.
    - **Principle of least privilege**: Ensure that the backend process runs with the minimum necessary file system permissions to limit the impact of potential path traversal vulnerabilities.

* Preconditions:
    - The application must be deployed and publicly accessible.
    - The evaluation API endpoints (like `/evals`, `/pairwise-evals`, `/best-of-n-evals`) must be exposed and reachable by external users.
    - The backend application must have file system read permissions to the files that the attacker attempts to access via path traversal.

* Source Code Analysis:
    - File: `backend/routes/evals.py`
    - Functions: `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
    - Vulnerable code snippets:
        - In `get_evals`:
            ```python
            @router.get("/evals", response_model=list[Eval])
            async def get_evals(folder: str):
                if not folder:
                    raise HTTPException(status_code=400, detail="Folder path is required")

                folder_path = Path(folder) # [POINT OF VULNERABILITY 1] User-provided path is directly converted to Path object without sanitization.
                if not folder_path.exists(): # Existence check is insufficient to prevent traversal.
                    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

                try:
                    evals: list[Eval] = []
                    # Get all HTML files from folder
                    files = {
                        f: os.path.join(folder, f) # [POINT OF VULNERABILITY 2] User-provided 'folder' is used in path construction without validation.
                        for f in os.listdir(folder) # [POINT OF VULNERABILITY 3] User-provided 'folder' is used in os.listdir without validation.
                        if f.endswith(".html")
                    }
                    # ... rest of the code ...
            ```
        - In `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals`:
            ```python
            input_path = os.path.join(EVALS_DIR, "inputs", f"{base_name}.png") # EVALS_DIR is a config, but base_name is derived from folder content
            ```
    - Visualization:
        ```
        User Request (folder param: "../../../etc") --> Backend API Endpoint (/evals, /pairwise-evals, /best-of-n-evals) -->
        os.listdir("../../../etc") --> File system access to /etc directory (potentially) -->
        Information Disclosure
        ```
    - The vulnerability lies in the direct use of the `folder` parameter from the query string in `os.listdir()` and `os.path.join()` without any validation to ensure that the path stays within the intended evaluation directories. The `folder_path.exists()` check in `/evals` is insufficient as it only verifies if the path exists, not if it's a safe or intended path. An attacker can manipulate the `folder` parameter to traverse up the directory structure and access files outside the intended scope. The use of `Path(folder)` does not prevent path traversal vulnerabilities in this context because it is still used in `os.listdir(folder)` and `os.path.join(folder, f)`.

* Security Test Case:
    1. Deploy the application to a test environment or a publicly accessible instance and ensure the evaluation endpoints are accessible (e.g., `/evals?folder=`, `/pairwise-evals?folder1=`, `/best-of-n-evals?folder=`).
    2. Identify the base directory where evaluation folders are expected to be located on the server.
    3. Craft a GET request to one of the evaluation endpoints, such as `/evals`. In the `folder` query parameter, insert a path traversal string to target a sensitive file on the server, such as `/etc/passwd` on Linux-based systems or `C:\Windows\win.ini` on Windows-based systems. For example:
        ```
        GET /evals?folder=../../../../etc/passwd
        ```
        or for other endpoints:
        ```
        GET /pairwise-evals?folder1=../../../../etc/passwd
        ```
    4. Send the crafted GET request to the application.
    5. Analyze the HTTP response from the server.
        - **Successful Exploitation**: If the vulnerability is successfully exploited, the server's response might contain the content of the targeted sensitive file (e.g., `/etc/passwd` or `win.ini`) within the response, especially if there happens to be an HTML file in the traversed directory (which is unlikely for `/etc/passwd` but possible for other paths for `/evals` endpoint). Even if no HTML file is found in the traversed directory for `/evals` or other required files for other endpoints, an error message different from "Folder not found" or "Error processing evals" could indicate successful traversal and an attempt to access the directory.
        - **Error Response**: If the application returns an error such as "Folder not found" (HTTP 404) or "Error processing evals" (HTTP 500) and the error message or logs indicate a file system error related to accessing the traversed path, this could also indicate successful path traversal attempt, even if the file content is not directly returned in the response.
    6. Examine the server-side logs for any file access errors or unusual activity related to the path traversal attempt.
    7. If the response or server logs indicate successful access to the sensitive file or directory outside the intended scope, the path traversal vulnerability is confirmed. To further validate, try accessing other sensitive files or directories that the backend process might have read access to. Note that successful exploitation depends on file system permissions and the operating system. On some systems, accessing `/etc/passwd` might be restricted. You may need to adjust the target path based on the server environment. For testing purposes in a controlled environment (e.g., development setup), you can try to access files within the application's directory or other predictable locations to confirm the vulnerability before attempting to access system files.

### Vulnerability Name: API Key Leakage via Client-Side Storage and Potential Interception

* Description:
    1. The application's frontend allows users to configure API keys for OpenAI, Anthropic, and Gemini through a settings dialog.
    2. These API keys are stored in the browser's local storage for persistence.
    3. A malicious actor can access these API keys using browser developer tools (available in all modern browsers) by inspecting the local storage of the application's origin.
    4. Alternatively, if the attacker can inject and execute JavaScript code in the user's browser session while using the application, they can programmatically access the local storage and retrieve the API keys.
    5. Once the API keys are obtained, the attacker can directly use these keys to make unauthorized requests to the respective LLM APIs (OpenAI, Anthropic, Gemini) outside the context of the application. This could lead to financial charges for the legitimate user, service disruption, or other malicious activities using the user's API credentials.

* Impact:
    - Unauthorized usage of user's LLM API credits, leading to unexpected financial charges.
    - Potential suspension or termination of user's LLM API accounts due to attacker's activities.
    - Possible exposure of other services if the user reuses the compromised API keys across different platforms.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The application stores API keys only in the user's browser local storage and not on the server, as stated in the `README.md`. This client-side storage limits the exposure compared to server-side plaintext storage compared to server-side storage.

* Missing Mitigations:
    - **Encryption of API Keys**: API keys are likely stored in plaintext in local storage. Client-side encryption of these keys before storing them would significantly increase the security by making direct extraction from local storage less useful without the decryption key.
    - **Backend Proxy for API Calls**: A more secure architecture would involve the frontend sending requests to the backend, and the backend securely managing and using the API keys. The frontend should not directly handle or store sensitive API keys.
    - **User Security Awareness**: Lack of explicit warnings or guidelines to users about the security implications of storing API keys in the browser and best practices for managing API keys.

* Preconditions:
    - User must configure and save their API keys within the application's settings.
    - Attacker needs to have a way to access the user's browser local storage, either through physical access, remote access to the user's machine, or by injecting malicious JavaScript in the browser session.

* Source Code Analysis:
    - Configuration files (`backend/config.py`, `frontend/.env.local`): These files show the usage of environment variables for API keys in the backend and frontend, indicating the application's reliance on API keys for functionality.
    - Frontend code (not provided in detail, but based on description): The frontend settings dialog is responsible for taking user input for API keys and storing them in `localStorage`. The API call logic in the frontend would then retrieve these keys from `localStorage` to authenticate requests to the backend or directly to LLM APIs.
    - Backend code (`backend/llm.py`, `backend/main.py`, `backend/routes/generate_code.py`): Backend uses the API keys to interact with LLM services. The backend configuration relies on environment variables, but the frontend is responsible for providing these keys in the user's session. The `get_from_settings_dialog_or_env` function in `backend/routes/generate_code.py` shows how API keys are retrieved from either the settings dialog (client-side, likely local storage) or environment variables.

* Security Test Case:
    1. Open the `screenshot-to-code` application in a web browser (e.g., `http://localhost:5173` if running locally).
    2. Access the settings panel by clicking the gear icon.
    3. Enter a valid OpenAI API key into the "OpenAI key" field and save the settings.
    4. Open the browser's developer tools (usually by pressing F12).
    5. Navigate to the "Application" tab (in Chrome) or "Storage" tab (in Firefox).
    6. Select "Local Storage" from the sidebar and choose the application's origin (e.g., `http://localhost:5173`).
    7. Look for keys such as `OPENAI_API_KEY`. You should find the API key you entered in plaintext as the value for this key.
    8. Copy the plaintext API key.
    9. Open a terminal and use `curl` to make a request to the OpenAI API (e.g., to list models) using the copied API key:
        ```bash
        curl https://api.openai.com/v1/models \
          -H "Authorization: Bearer <YOUR_COPIED_API_KEY>"
        ```
    10. If the `curl` command successfully returns a list of OpenAI models, it confirms that the API key stored in the browser's local storage can be extracted and used to make unauthorized API calls.
