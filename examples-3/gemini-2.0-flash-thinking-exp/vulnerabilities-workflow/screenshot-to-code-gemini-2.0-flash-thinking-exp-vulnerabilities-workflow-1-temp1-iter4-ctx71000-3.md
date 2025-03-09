- Vulnerability name: Path Traversal in Evaluation File Access

- Description:
    1. The backend application in `backend/routes/evals.py` exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` that allow users to specify folder paths to access evaluation files.
    2. The application uses `os.listdir` and `os.path.join` to list files and construct file paths based on user-provided folder paths.
    3. Input validation is insufficient, allowing an attacker to potentially provide a manipulated folder path (e.g., using `..`) to traverse the file system outside the intended evaluation directories.
    4. By crafting a malicious folder path, an attacker could read arbitrary files on the server, including sensitive configuration files, source code, or data.
    5. For example, an attacker could use a path like `../../../../etc/passwd` to attempt to read the system's password file, or navigate to application configuration directories to access sensitive information.

- Impact:
    - High: Successful path traversal can lead to unauthorized access to sensitive files on the server. This can include application source code, configuration files (potentially containing credentials or API keys), and other sensitive data. In the worst case, it can compromise the entire server if sensitive system files are accessed.

- Vulnerability rank: high

- Currently implemented mitigations:
    - None: The code directly uses user-provided paths with `os.listdir` and `os.path.join` without any sanitization or validation to prevent path traversal.

- Missing mitigations:
    - Implement robust input validation and sanitization for the `folder` parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints.
    - Validate that the provided path is within the expected base directory for evaluations.
    - Use secure path manipulation functions that prevent traversal outside of allowed directories. For example, using `os.path.abspath` and checking if the resolved path is still within the allowed base directory.

- Preconditions:
    - The backend application must be publicly accessible.
    - The evaluation endpoints `/evals`, `/pairwise-evals`, or `/best-of-n-evals` must be accessible without authentication (or attacker has valid credentials if authentication is required, though based on provided code there is no authentication implemented).

- Source code analysis:
    ```python
    # File: ..\screenshot-to-code\backend\routes\evals.py
    import os
    from fastapi import APIRouter, Query, Request, HTTPException
    from pydantic import BaseModel
    from pathlib import Path

    router = APIRouter()

    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str): # folder parameter is user controlled
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # Path object is created, but not validated for traversal
        if not folder_path.exists(): # Only existence is checked, not path validity
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # os.path.join with user controlled folder
                for f in os.listdir(folder) # os.listdir with user controlled folder
                if f.endswith(".html")
            }
            # ... rest of the code ...

    @router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
    async def get_pairwise_evals(
        folder1: str = Query( # folder1 parameter is user controlled
            "...",
            description="Absolute path to first folder",
        ),
        folder2: str = Query( # folder2 parameter is user controlled
            "..",
            description="Absolute path to second folder",
        ),
    ):
        if not os.path.exists(folder1) or not os.path.exists(folder2): # Only existence is checked, not path validity
            return {"error": "One or both folders do not exist"}

        # ... rest of the code ...
        files1 = {
            f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html") # os.path.join and os.listdir with user controlled folder1
        }
        files2 = {
            f: os.path.join(folder2, f) for f in os.listdir(folder2) if f.endswith(".html") # os.path.join and os.listdir with user controlled folder2
        }
        # ... rest of the code ...

    @router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
    async def get_best_of_n_evals(request: Request):
        # Get all query parameters
        query_params = dict(request.query_params)

        # Extract all folder paths (folder1, folder2, folder3, etc.)
        folders = []
        i = 1
        while f"folder{i}" in query_params: # folder parameters are user controlled
            folders.append(query_params[f"folder{i}"])
            i += 1

        if not folders:
            return {"error": "No folders provided"}

        # Validate folders exist
        for folder in folders:
            if not os.path.exists(folder): # Only existence is checked, not path validity
                return {"error": f"Folder does not exist: {folder}"}

        # ... rest of the code ...
        files_by_folder = []
        for folder in folders:
            files = {
                f: os.path.join(folder, f) # os.path.join with user controlled folder
                for f in os.listdir(folder) # os.listdir with user controlled folder
                if f.endswith(".html")
            }
            files_by_folder.append(files)
        # ... rest of the code ...
    ```
    - The code in `get_evals`, `get_pairwise_evals`, and `get_best_of_n-evals` directly uses the `folder`, `folder1`, `folder2`, etc., parameters from the query string in `os.listdir` and `os.path.join`.
    - There is no validation to ensure that these paths are within the intended directory or to sanitize them against path traversal attacks.
    - The `Path(folder).exists()` check only verifies if the path exists but does not prevent traversal to parent directories using `..`.

- Security test case:
    1. Deploy the `screenshot-to-code` backend to a publicly accessible server (e.g., `http://backend.example.com:7001`).
    2. Identify the absolute path of the `EVALS_DIR` on the server. Assume it is `/app/screenshot-to-code/evals` for this example.
    3. Craft a malicious URL to access a file outside of the intended `EVALS_DIR`. For instance, to access `/etc/passwd`, use a path like `../../../../../etc/passwd` relative to the assumed `EVALS_DIR`.
    4. Send a GET request to the `/evals` endpoint with the crafted `folder` parameter:
       `http://backend.example.com:7001/evals?folder=../../../../../etc/passwd`
    5. Observe the response. If the vulnerability exists, the server might attempt to list files in `/etc/passwd` (which is unlikely to contain `.html` files and may result in an empty response or error depending on file contents), or more likely error out because `/etc/passwd` is not a directory.
    6. To confirm read access to a readable file, try to access a known readable file relative to the application root. For example, if there is a readable file named `config.ini` in the root directory of the application, try to access it using:
       `http://backend.example.com:7001/evals?folder=../../../../config.ini` (adjust the number of `../` to match the relative path from `EVALS_DIR` to the application root). In this case, since endpoint expects to find `.html` files, this specific test case might not return file content directly.
    7. A more successful test within the scope of the application is to attempt to list the parent directory of `EVALS_DIR`. If `EVALS_DIR` is `/app/screenshot-to-code/evals`, try:
       `http://backend.example.com:7001/evals?folder=../`. This would attempt to list files in `/app/screenshot-to-code/`. Observe the response. If successful, you might see files and directories within `/app/screenshot-to-code/`, confirming path traversal vulnerability.
    8. To further exploit, if you know the structure inside `/app/screenshot-to-code/`, you might try to access source code files or other sensitive non-`.html` files by adjusting the attack path and potentially modifying the backend code to return file contents directly if needed for full exploit demonstration, though just listing directory content outside of intended directories is enough to confirm the vulnerability.
