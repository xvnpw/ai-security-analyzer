## Vulnerability List:

- Path Traversal Vulnerability in `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` Endpoints

### Path Traversal Vulnerability in `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` Endpoints

- **Vulnerability Name:** Path Traversal in `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` Endpoints
- **Description:**
    The `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` endpoints in `evals.py` are vulnerable to path traversal attacks. These endpoints accept user-provided folder paths as input parameters (`folder`, `folder1`, `folder2`, `folder{i}`). The application uses these paths to list files and read HTML content. However, there is no validation to ensure that the provided folder paths are within the intended directories. An attacker can exploit this by providing malicious paths like `../../../../etc` to access files outside the intended directory structure, potentially reading sensitive files on the server.
- **Impact:**
    An attacker can read arbitrary files from the server's file system that the application process has access to. This can lead to:
    - **Information Disclosure:** Exposure of sensitive data such as configuration files, application source code, internal documentation, or even system files.
    - **Further Exploitation:**  Reading configuration files might reveal database credentials, API keys, or other sensitive information that can be used for further attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    None. The code only checks if the provided folder exists using `os.path.exists()` but does not validate if the path is within allowed boundaries.
- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust path validation to ensure that user-provided folder paths are restricted to the intended directories. This can be achieved by:
        - Defining an allowed base directory (e.g., the `EVALS_DIR` or a subdirectory within it).
        - Using absolute paths (`os.path.abspath`) to resolve the user-provided path and the allowed base directory.
        - Checking if the resolved user-provided path starts with the allowed base directory using `startswith()`.
        - Rejecting requests if the path is outside the allowed base directory.
- **Preconditions:**
    - The application must be deployed and accessible to external attackers.
    - The attacker needs to know the API endpoints and parameter names:
        - `/evals?folder=<malicious_path>`
        - `/pairwise-evals?folder1=<malicious_path>&folder2=<another_path>`
        - `/best-of-n-evals?folder1=<malicious_path>&folder2=<path2>&folder3=<path3>...`
- **Source Code Analysis:**
    - **File:** `..\screenshot-to-code\backend\routes\evals.py`
    - **Function:** `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
    - **Vulnerable Code Snippet (from `get_evals`):**
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
                    f: os.path.join(folder, f) # [VULNERABLE LINE] - Path is directly joined without validation
                    for f in os.listdir(folder)
                    if f.endswith(".html")
                }

                # ... rest of the code ...
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
        ```
    - **Explanation:**
        1. The `get_evals` function takes a `folder` path as a query parameter.
        2. It creates a `Path` object from the input `folder` and checks if the folder exists using `folder_path.exists()`.
        3. If the folder exists, it proceeds to list files within this `folder` using `os.listdir(folder)`.
        4. **Vulnerability:** The code directly uses the user-provided `folder` path in `os.listdir(folder)` and `os.path.join(folder, f)` without any validation to ensure it's within allowed directories. If an attacker provides a path like `../../../../etc`, `os.listdir` will attempt to list files in `/etc`, and `os.path.join` will construct paths like `/etc/passwd`, leading to path traversal.
        5. The content of the HTML files found in the potentially traversed path is then read and returned in the API response.
    - The `get_pairwise_evals` and `get_best_of_n_evals` functions have similar vulnerabilities in how they handle `folder1`, `folder2`, and `folder{i}` parameters.

- **Security Test Case:**
    1. **Target Endpoint:** `/evals`
    2. **Method:** `GET`
    3. **Parameters:** `folder`
    4. **Malicious Input:** `folder=../../../../etc`
    5. **Steps:**
        - Send a GET request to the `/evals` endpoint with the `folder` parameter set to `../../../../etc`. For example:
          ```bash
          curl "http://<application_url>/evals?folder=../../../../etc"
          ```
        - Observe the response.
    6. **Expected Vulnerable Response:**
        - If the vulnerability exists, the response might return a list of `Eval` objects. If there are `.html` files in the `/etc` directory (which is unlikely but possible, or if the attacker targets other directories with HTML files), the response might include their content. More likely, if there are no HTML files, the response will be an empty list of `Eval` objects `[]`, but without any error indicating path traversal prevention. However, the key is that the application attempts to access files under `/etc` based on user input.
    7. **Expected Mitigated Response:**
        - If path traversal is mitigated, the application should either:
            - Return an error (e.g., 400 Bad Request or 404 Not Found) indicating that the requested path is invalid or not allowed.
            - Return an empty list or a specific error message if the path is considered outside the allowed base directory, without attempting to access or list files in the traversed path.

    **Note:** For a more definitive test that proves arbitrary file reading, you can try to access a known file that is likely to exist and accessible to the application process, but outside the intended `EVALS_DIR`. For instance, if there's a readable configuration file in a parent directory or a common system file (though accessing system files might be restricted by OS permissions). However, testing with `../../../../etc` serves to demonstrate the path traversal attempt effectively.
