## Vulnerability List for screenshot-to-code Project

Based on the provided project files, the following high-rank vulnerabilities introduced by the project itself and triggerable by an external attacker on a publicly available instance were identified:

* Path Traversal in Evals Endpoints

### Path Traversal in Evals Endpoints
* Vulnerability Name: Path Traversal in Evals Endpoints
* Description:
    The application exposes several endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) that allow users to specify folder paths as parameters. These endpoints are intended to retrieve evaluation files (HTML and image inputs) from specified folders. However, the application lacks proper validation and sanitization of the folder paths provided by the user. This allows an attacker to craft malicious folder paths containing path traversal sequences (e.g., `../`, `../../`) to access files and directories outside of the intended evaluation directories on the server's file system.

    Step-by-step trigger:
    1. An attacker identifies the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints as potential targets.
    2. The attacker crafts a malicious URL request to one of these endpoints. For example, targeting `/evals` endpoint, the attacker might use a URL like `/evals?folder=../../../../etc/passwd`.
    3. The backend application, upon receiving this request, uses the provided `folder` parameter without proper validation in `os.listdir` and `os.path.join` functions.
    4. Due to the path traversal sequences (`../../../../`), the application attempts to list and read files from the `/etc/passwd` directory (or other system files depending on the path).
    5. If successful, the application might return the content of the accessed files in the response, or leak information about the file system structure through error messages or unexpected behavior.

* Impact:
    High. Successful exploitation of this vulnerability allows an attacker to read arbitrary files from the server's file system. This could include sensitive data such as:
    - Application source code
    - Configuration files containing API keys, database credentials, or other secrets
    - System files, potentially revealing information about the operating system and installed software
    - User data or other confidential information stored on the server

    The impact is considered high because it leads to information disclosure, which can have severe consequences depending on the sensitivity of the exposed data. In some scenarios, it might even be a stepping stone to further attacks.

* Vulnerability Rank: high
* Currently Implemented Mitigations:
    None. The code checks for the existence of the folder, but it does not validate or sanitize the folder path to prevent path traversal.

* Missing Mitigations:
    - **Input validation and sanitization:** Implement robust input validation on the `folder`, `folder1`, `folder2`, etc. parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints.
        - Validate that the provided paths are within the intended evaluation directories.
        - Sanitize the input paths to remove or neutralize path traversal sequences like `../` and prevent access to parent directories.
        - Consider using absolute paths and verifying that the resolved path is still within the allowed base directory.
    - **Principle of least privilege:** Ensure that the application's user account has the minimum necessary permissions to access files and directories. This can limit the scope of a path traversal attack even if input validation is bypassed.

* Preconditions:
    - The backend application is deployed and publicly accessible.
    - The `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints are exposed without authentication or access control (or accessible to the attacker).

* Source Code Analysis:
    File: `backend/routes/evals.py`

    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder)
        if not folder_path.exists(): # Check if folder exists, but no path traversal prevention
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # Vulnerable: using user-provided 'folder' directly in path join
                for f in os.listdir(folder) # Vulnerable: using user-provided 'folder' directly in listdir
                if f.endswith(".html")
            }
            # ... rest of the code ...
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
    ```

    **Vulnerability Explanation:**
    1. The `get_evals` function takes the `folder` parameter directly from the query string.
    2. It uses `Path(folder)` and `folder_path.exists()` to check if the folder exists. However, this check does not prevent path traversal. An attacker can still provide a path like `../../../../etc/passwd` which might exist (depending on the server's OS) and bypass this check in some scenarios.
    3. The code then uses `os.listdir(folder)` and `os.path.join(folder, f)` directly with the user-provided `folder` parameter. This is where the path traversal vulnerability occurs. If the `folder` parameter contains path traversal sequences (like `../`), `os.listdir` and `os.path.join` will operate outside the intended directory, allowing access to arbitrary files and directories on the server.

    The same vulnerability pattern exists in `get_pairwise_evals` and `get_best_of_n_evals` functions where `folder1`, `folder2` and `folders` parameters are used respectively without proper validation.

* Security Test Case:
    1. Deploy the application to a test environment or use a local instance.
    2. Identify the URL for the `/evals` endpoint (e.g., `http://localhost:8000/evals`).
    3. Craft a malicious URL to attempt to access a sensitive file, such as `/etc/passwd` on a Linux-based system. For example: `http://localhost:8000/evals?folder=../../../../etc/passwd`.
    4. Send the crafted request to the application using a browser or a tool like `curl`.
    5. Observe the response.
        - **If vulnerable:** The response might contain an error message related to file processing, but importantly, it might indicate that the application attempted to access or list files in the `/etc/passwd` directory. In a more severe case, if the application is configured to read and return file contents, the response might even contain parts of the `/etc/passwd` file (although less likely due to the file type check for `.html`). Even without direct file content, error messages or changed application behavior can confirm the path traversal.
        - **If mitigated:** The application should either return an error indicating an invalid folder path or behave as if the folder is empty, without attempting to access files outside the intended directories.

    **Expected Result (if vulnerable):** The application attempts to access files outside of the intended directory, potentially leading to error messages indicating attempts to access files like those in `/etc/passwd`, or in a worst case, leaking file content if the application was designed to return file contents. A successful test would demonstrate that the path traversal sequences are not being properly handled, confirming the vulnerability.
