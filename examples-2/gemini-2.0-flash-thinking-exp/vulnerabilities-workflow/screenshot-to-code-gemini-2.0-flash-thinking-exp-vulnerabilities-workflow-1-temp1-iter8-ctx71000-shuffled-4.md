### Vulnerability List:

- Vulnerability Name: Path Traversal in Evaluation Endpoints
- Description:
    1. The application exposes several endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) in the `/evals` router that are intended for internal evaluation purposes.
    2. These endpoints accept user-controlled input in the form of `folder`, `folder1`, `folder2`, etc. query parameters, which represent paths to directories containing evaluation output files.
    3. The application uses these folder paths directly in `os.listdir()` and `os.path.join()` without sufficient sanitization or validation to ensure that the paths remain within the intended `EVALS_DIR` or its subdirectories.
    4. A malicious attacker could craft a request to these endpoints with a crafted `folder` parameter, such as `../../`, to traverse up the directory structure and access files outside of the designated evaluation directories.
    5. For example, by sending a request to `/evals?folder=../../backend`, an attacker might be able to list files in the backend directory, potentially exposing sensitive source code or configuration files.
- Impact:
    - An attacker can read arbitrary files on the server's filesystem that the application process has access to.
    - This could lead to the disclosure of sensitive information, such as source code, configuration files, internal documentation, or API keys if they are stored in files accessible through path traversal.
    - In the context of this project, it could expose backend source code, potentially revealing further vulnerabilities or business logic.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application checks if the folder exists using `folder_path.exists()`, but this does not prevent path traversal if a valid path outside of the intended directory is provided.
- Missing Mitigations:
    - Implement path sanitization and validation to ensure that the provided `folder` parameters are always within the intended `EVALS_DIR` and its subdirectories.
    - Use secure path manipulation functions that prevent traversal outside of the intended directory. For example, using `os.path.abspath` and checking if the resolved path starts with the intended base directory.
    - Restrict access to the evaluation endpoints to authenticated administrators only or completely remove these endpoints from production instances as they are intended for development/evaluation purposes.
- Preconditions:
    - The application must be deployed and accessible to external attackers.
    - The attacker needs to identify and target the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
- Source Code Analysis:
    - **File:** `backend/routes/evals.py`
    - **Function:** `get_evals(folder: str)`
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [POINT OF VULNERABILITY] User-provided folder path is directly used.
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [POINT OF VULNERABILITY] User-provided folder path is directly used in path join.
                for f in os.listdir(folder) # [POINT OF VULNERABILITY] User-provided folder path is directly used in listdir.
                if f.endswith(".html")
            }
            # ... rest of the code ...
    ```
    - The `get_evals` function takes the `folder` query parameter and directly uses it with `Path(folder)`, `os.listdir(folder)`, and `os.path.join(folder, f)`.
    - There is no validation to ensure that `folder` is within the `EVALS_DIR` or any permitted subdirectory.
    - Similar vulnerability exists in `get_pairwise_evals` and `get_best_of_n-evals` functions which also take folder paths as query parameters and use them in `os.listdir` and `os.path.join` without validation.

- Security Test Case:
    1. Deploy the `screenshot-to-code` application.
    2. Identify the base URL of the deployed application. Let's assume it is `http://example.com`.
    3. Craft a malicious URL for the `/evals` endpoint that attempts to traverse to the parent directory and access the backend directory: `http://example.com/evals?folder=../../backend`.
    4. Send a GET request to the crafted URL.
    5. Observe the response. If the vulnerability exists, the response will likely be a list of `Eval` objects. If path traversal is successful and the backend directory contains HTML files (which it should not ideally), the response might contain data related to files within the backend directory, or an error indicating file listing if directory structure does not match expected evaluation output.
    6. To further confirm, try to access a known file in the backend directory, for example, `http://example.com/evals?folder=../../backend/main.py`. If the response does not result in a "Folder not found" error and potentially gives an error related to processing evals, it further indicates path traversal is possible, although the endpoint is designed to list HTML files and `main.py` is not an HTML file. A successful file read is not guaranteed to be directly visible due to the expected file type processing in the endpoint, but error behavior or server logs can confirm path traversal.
    7. For a more direct test, place an HTML file named `test.html` in the backend directory temporarily. Then access `http://example.com/evals?folder=../../backend`. If the response lists an Eval object with `test.html`, it confirms the vulnerability.
