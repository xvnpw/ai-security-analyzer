- Vulnerability Name: Path Traversal in Evaluation File Access
- Description:
    - The application allows users to specify a folder path to retrieve evaluation files through the `/evals` and `/pairwise-evals` endpoints in `backend/routes/evals.py`.
    - An attacker could potentially provide a maliciously crafted folder path (e.g., containing "../" sequences) to bypass directory restrictions and access files or directories outside the intended evaluation directory.
    - By manipulating the `folder` parameter in the `/evals` endpoint or `folder1` and `folder2` parameters in `/pairwise-evals` endpoint, an attacker could read arbitrary files from the server's file system, depending on the application's file system permissions.
    - For example, an attacker could try to access sensitive configuration files, source code, or other application data.
- Impact:
    - High. Successful exploitation of this vulnerability could allow an attacker to read sensitive files from the backend server.
    - This could lead to exposure of confidential data, including source code, configuration files, environment variables (potentially containing API keys or credentials if stored in files accessible through path traversal), and other sensitive information, depending on server's file system layout and permissions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The code checks if the provided `folder_path` exists using `folder_path.exists()` in `get_evals` and `os.path.exists(folder1)` and `os.path.exists(folder2)` in `get_pairwise_evals`.
    - However, it does not validate or sanitize the input folder path to prevent path traversal attempts. It directly uses the user-provided folder path to list files and access them using `os.path.join`.
- Missing Mitigations:
    - Input validation and sanitization: Implement robust validation and sanitization of the folder path provided by the user.
        - Use functions like `os.path.abspath` to resolve the path and `os.path.commonprefix` to ensure that the resolved path is still within the intended base directory (e.g., `EVALS_DIR`).
        - Sanitize the input to remove or neutralize path traversal sequences like "../" before using it in file system operations.
    - Principle of least privilege: Ensure that the backend process runs with minimal file system permissions necessary for its operation. This limits the impact of a path traversal vulnerability, as the attacker would only be able to access files readable by the backend process.
- Preconditions:
    - The backend must be accessible to the attacker.
    - The application must have the `/evals` or `/pairwise-evals` endpoints exposed.
    - The server's file system must contain sensitive files accessible to the backend process outside the intended `EVALS_DIR`.
- Source Code Analysis:
    - File: `backend/routes/evals.py`
    ```python
    import os
    from fastapi import APIRouter, Query, Request, HTTPException
    from pydantic import BaseModel
    from evals.utils import image_to_data_url
    from evals.config import EVALS_DIR
    # ...

    router = APIRouter()

    # ...

    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # User provided folder is directly used
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # User provided folder is directly used in path join
                for f in os.listdir(folder) # User provided folder is directly used in listdir
                if f.endswith(".html")
            }
            # ...
    ```
    - Step-by-step analysis:
        1. The `get_evals` function takes a `folder` string as input from the query parameter.
        2. `folder_path = Path(folder)` creates a Path object directly from the user-provided `folder` string.
        3. `if not folder_path.exists():` checks if the path exists, but this does not prevent path traversal. It only checks existence of the potentially traversed path.
        4. `files = {f: os.path.join(folder, f) ...}` uses `os.path.join(folder, f)` to construct file paths within the user-provided `folder`. This is vulnerable as `folder` is not validated and can contain path traversal sequences.
        5. `os.listdir(folder)` lists files in the user-provided `folder`. This is also vulnerable because the `folder` input is not sanitized.

    - Visualization:
        ```
        Attacker Input (folder = "../../sensitive_dir") --> /evals endpoint --> get_evals function
                                                                  |
                                                                  V
                                                    os.listdir(folder) [Path Traversal] --> Read files in "../../sensitive_dir"
                                                                  |
                                                                  V
                                                           Return file contents
        ```

- Security Test Case:
    - Precondition: Access to the application's backend.
    - Steps:
        1. Identify a sensitive file or directory on the backend server that is outside the intended `EVALS_DIR` but accessible to the backend process (e.g., a configuration file in the parent directory, assuming appropriate file permissions). For example, assuming there is a file named `sensitive.txt` in the parent directory of the application's working directory.
        2. Construct a malicious folder path that uses path traversal to target the sensitive file. For example, if the eval files are expected to be in `/app/evals`, and the sensitive file is in `/app/sensitive.txt`, the malicious path would be `../`.
        3. Send a GET request to the `/evals` endpoint with the crafted folder path as a query parameter: `GET /evals?folder=../`
        4. Observe the response. If the vulnerability is successfully exploited, the response might contain an error indicating inability to find HTML files if there are no HTML files in the traversed directory, but importantly, no error indicating invalid path format, which would suggest path traversal was attempted.
        5. To confirm file reading, adjust the path to target a specific file if listing directory is not sufficient. Assuming there's a readable file at `/etc/passwd`, try `GET /evals?folder=../../../../../../etc/`. While listing `/etc` might be restricted, direct file access might be possible with different variations of path traversal depending on OS and permissions. A more targeted test would be to try to read a file you know exists relative to the application root, adjusting the `../` count accordingly.
        6. If successful, the attacker might be able to infer the server's directory structure and access files outside of the intended evaluation directory. Depending on the server setup and file permissions, this could lead to reading sensitive application files.
