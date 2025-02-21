- Vulnerability Name: API Key Leakage via Client-Side Storage and Potential Interception
- Description:
    - Step 1: The application's frontend allows users to configure API keys for OpenAI, Anthropic, and Gemini through a settings dialog.
    - Step 2: These API keys are stored in the browser's local storage for persistence.
    - Step 3: A malicious actor can access these API keys using browser developer tools (available in all modern browsers) by inspecting the local storage of the application's origin.
    - Step 4: Alternatively, if the attacker can inject and execute JavaScript code in the user's browser session while using the application, they can programmatically access the local storage and retrieve the API keys.
    - Step 5: Once the API keys are obtained, the attacker can directly use these keys to make unauthorized requests to the respective LLM APIs (OpenAI, Anthropic, Gemini) outside the context of the application. This could lead to financial charges for the legitimate user, service disruption, or other malicious activities using the user's API credentials.
- Impact:
    - Unauthorized usage of user's LLM API credits, leading to unexpected financial charges.
    - Potential suspension or termination of user's LLM API accounts due to attacker's activities.
    - Possible exposure of other services if the user reuses the compromised API keys across different platforms.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The application stores API keys only in the user's browser local storage and not on the server, as stated in the `README.md`. This client-side storage limits the exposure compared to server-side plaintext storage compared to server-side storage.
- Missing Mitigations:
    - Encryption of API Keys: API keys are likely stored in plaintext in local storage. Client-side encryption of these keys before storing them would significantly increase the security by making direct extraction from local storage less useful without the decryption key.
    - Backend Proxy for API Calls: A more secure architecture would involve the frontend sending requests to the backend, and the backend securely managing and using the API keys. The frontend should not directly handle or store sensitive API keys.
    - User Security Awareness: Lack of explicit warnings or guidelines to users about the security implications of storing API keys in the browser and best practices for managing API keys.
- Preconditions:
    - User must configure and save their API keys within the application's settings.
    - Attacker needs to have a way to access the user's browser local storage, either through physical access, remote access to the user's machine, or by injecting malicious JavaScript in the browser session.
- Source Code Analysis:
    - Configuration files (`backend/config.py`, `frontend/.env.local`): These files show the usage of environment variables for API keys in the backend and frontend, indicating the application's reliance on API keys for functionality.
    - Frontend code (not provided in detail, but based on description): The frontend settings dialog is responsible for taking user input for API keys and storing them in `localStorage`. The API call logic in the frontend would then retrieve these keys from `localStorage` to authenticate requests to the backend or directly to LLM APIs.
    - Backend code (`backend/llm.py`, `backend/main.py`, `backend/routes/generate_code.py`): Backend uses the API keys to interact with LLM services. The backend configuration relies on environment variables, but the frontend is responsible for providing these keys in the user's session. The `get_from_settings_dialog_or_env` function in `backend/routes/generate_code.py` shows how API keys are retrieved from either the settings dialog (client-side, likely local storage) or environment variables.
- Security Test Case:
    - Step 1: Open the `screenshot-to-code` application in a web browser (e.g., `http://localhost:5173` if running locally).
    - Step 2: Access the settings panel by clicking the gear icon.
    - Step 3: Enter a valid OpenAI API key into the "OpenAI key" field and save the settings.
    - Step 4: Open the browser's developer tools (usually by pressing F12).
    - Step 5: Navigate to the "Application" tab (in Chrome) or "Storage" tab (in Firefox).
    - Step 6: Select "Local Storage" from the sidebar and choose the application's origin (e.g., `http://localhost:5173`).
    - Step 7: Look for keys such as `OPENAI_API_KEY`. You should find the API key you entered in plaintext as the value for this key.
    - Step 8: Copy the plaintext API key.
    - Step 9: Open a terminal and use `curl` to make a request to the OpenAI API (e.g., to list models) using the copied API key:
        ```bash
        curl https://api.openai.com/v1/models \
          -H "Authorization: Bearer <YOUR_COPIED_API_KEY>"
        ```
    - Step 10: If the `curl` command successfully returns a list of OpenAI models, it confirms that the API key stored in the browser's local storage can be extracted and used to make unauthorized API calls.

- Vulnerability Name: Path Traversal in Evaluation Folder Access
- Description:
    - Step 1: An attacker identifies the API endpoints related to evaluations, such as `/evals`, `/pairwise-evals`, or `/best-of-n-evals` in `backend/routes/evals.py`. These endpoints accept folder paths as parameters (e.g., `folder`, `folder1`, `folder2`, etc.) to read evaluation files.
    - Step 2: The attacker crafts a malicious request to one of these endpoints, replacing the expected folder path with a path traversal string. For example, in a GET request to `/evals`, the attacker might set the `folder` parameter to `../../../../`.
    - Step 3: The backend application, without proper validation of the `folder` parameter, attempts to access files based on the attacker-controlled path. For instance, in `get_evals` function, the code constructs file paths using `os.path.join(folder, f)` and `os.path.join(EVALS_DIR, "inputs", f"{base_name}.png")` where `folder` is directly taken from the query parameter. If `folder` is `../../../../`, the application might try to access files outside of the intended `EVALS_DIR`.
    - Step 4: If the server's file system permissions allow and the path resolves to an existing file, the application reads the content of the file and includes it in the response.
    - Step 5: The attacker can then use this vulnerability to read arbitrary files on the server that the backend process has access to, by adjusting the path traversal string in the request.
- Impact:
    - Unauthorized file access: Attackers can read sensitive files on the server, potentially including configuration files, source code, data files, or credentials, depending on file system permissions and the application's access rights.
    - Information disclosure: Exposure of sensitive information can lead to further attacks or compromise the application's security and user data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None: The code in `backend/routes/evals.py` directly uses the user-provided folder paths without any apparent validation or sanitization against path traversal attacks.
- Missing Mitigations:
    - Input validation and sanitization: Implement robust validation for all folder path parameters received from user requests. Sanitize paths to remove path traversal sequences (e.g., `../`, `..\\`) and ensure that the paths stay within the intended directories (e.g., within `EVALS_DIR`).
    - Secure file path handling: Use secure file path manipulation techniques to prevent path traversal. For example, use functions that resolve paths to their canonical form and check if they are within the allowed base directory.
    - Principle of least privilege: Ensure that the backend process runs with the minimum necessary file system permissions to limit the impact of potential path traversal vulnerabilities.
- Preconditions:
    - Publicly accessible instance of the application with the evaluation API endpoints exposed.
    - The backend application must have file system read permissions to the files that the attacker attempts to access via path traversal.
- Source Code Analysis:
    - File: `backend/routes/evals.py`
    - Functions: `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
    - Vulnerable code snippets:
        - In `get_evals`:
            ```python
            folder_path = Path(folder) # folder is from query parameter
            files = {
                f: os.path.join(folder, f) # folder is directly used in path join
                for f in os.listdir(folder) # folder is directly used in listdir
                if f.endswith(".html")
            }
            input_path = os.path.join(EVALS_DIR, "inputs", f"{base_name}.png") # EVALS_DIR is a config, but base_name is derived from folder content
            ```
        - Similar patterns exist in `get_pairwise_evals` and `get_best_of_n_evals`.
    - Visualization:
        ```
        User Request (folder param: "../../../etc") --> Backend API Endpoint (/evals) -->
        os.listdir("../../../etc") --> File system access to /etc directory (potentially) -->
        Information Disclosure
        ```
    - The code directly uses the `folder` parameter from the request to construct file paths using `os.listdir` and `os.path.join` without any validation. This allows an attacker to manipulate the `folder` parameter to traverse directories outside the intended evaluation folders and potentially access sensitive files. The use of `Path(folder)` does not prevent path traversal vulnerabilities in this context because it is still used in `os.listdir(folder)` and `os.path.join(folder, f)`.
- Security Test Case:
    - Step 1: Deploy the `screenshot-to-code` application and ensure the evaluation endpoints are accessible (e.g., `/evals?folder=`).
    - Step 2: Craft a GET request to the `/evals` endpoint with a path traversal payload in the `folder` parameter. For example:
        ```
        GET /evals?folder=../../../../etc/passwd HTTP/1.1
        Host: <application-hostname>
        ```
    - Step 3: Send the request to the application.
    - Step 4: Examine the response. If the application is vulnerable, the response body might contain the content of the `/etc/passwd` file (or a portion of it), or an error message indicating that the application tried to access or list files in the `/etc/passwd` directory.
    - Step 5: If you can successfully retrieve content from `/etc/passwd` or other system files using path traversal, it confirms the path traversal vulnerability. To further validate, try accessing other sensitive files or directories that the backend process might have read access to. Note that successful exploitation depends on file system permissions and the operating system. On some systems, accessing `/etc/passwd` might be restricted. You may need to adjust the target path based on the server environment. For testing purposes in a controlled environment (e.g., development setup), you can try to access files within the application's directory or other predictable locations to confirm the vulnerability before attempting to access system files.
