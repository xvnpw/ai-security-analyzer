- Path Traversal in Evals Endpoints

Description:
The application exposes multiple endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) that allow users to retrieve evaluation files based on a provided folder path. These endpoints use the `folder` query parameter to specify the directory from which files should be read. However, the application lacks proper validation and sanitization of the input `folder` parameter. This allows an attacker to manipulate the `folder` parameter to traverse the file system outside the intended evaluation directories and potentially access sensitive files on the server.

Step-by-step description of how to trigger:
1. An attacker sends a crafted HTTP GET request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoint.
2. In the query parameters of the request, the attacker provides a malicious `folder` path designed to traverse directories, such as `folder=../../../../etc/passwd` for the `/evals` endpoint.
3. The backend application, without proper validation, uses the attacker-provided path to construct file paths using `os.path.join` and `os.listdir`.
4. Due to the path traversal payload, the application attempts to access files outside the intended `EVALS_DIR` directory, potentially reaching sensitive system files like `/etc/passwd`.
5. If successful, the application may read and return the contents of the targeted file in the response, or throw an error that reveals file existence or access issues, confirming the vulnerability.

Impact:
High. Successful exploitation of this vulnerability allows an external attacker to read arbitrary files from the server's file system that the application process has access to. This could include sensitive configuration files, application source code, data files, or even system files, potentially leading to раскрытие sensitive information, further exploitation, or complete compromise of the server and application.

Vulnerability Rank: high

Currently implemented mitigations:
None. The code checks if the provided folder exists using `folder_path.exists()`, but it does not validate if the path is within an allowed or expected base directory. There is no path sanitization or restriction in place to prevent traversal outside of intended directories.

Missing mitigations:
- Input validation: Implement strict validation on the `folder` parameter to ensure it is a valid path within the expected evaluation directories. This can include:
    - Whitelisting allowed base directories for evaluations.
    - Canonicalizing the input path and the allowed base directory paths and verifying that the input path is a subdirectory of an allowed base directory.
    - Using secure path manipulation functions that prevent traversal outside of the intended directory.
- Path sanitization: Sanitize the input path to remove any path traversal sequences (e.g., `../`, `..\\`) before using it to access files.

Preconditions:
- The backend application must be running and accessible to the attacker.
- The attacker needs to know the API endpoint paths (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) and the query parameter name (`folder`, `folder1`, `folder2`, `folder{i}`).

Source code analysis:
File: `backend/routes/evals.py`

Endpoint: `/evals` (and similar endpoints `/pairwise-evals`, `/best-of-n-evals`)

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder) # [POINT OF VULNERABILITY] - Path object created from user input without validation
    if not folder_path.exists(): # Check if folder exists, but not if it's within allowed paths
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    try:
        evals: list[Eval] = []
        # Get all HTML files from folder
        files = {
            f: os.path.join(folder, f) # [POINT OF VULNERABILITY] - os.path.join with unvalidated user input
            for f in os.listdir(folder) # [POINT OF VULNERABILITY] - os.listdir with unvalidated user input
            if f.endswith(".html")
        }
        ...
```
In the code snippet above, the `folder` parameter received from the request is directly used to create a `Path` object and in `os.path.join` and `os.listdir` without any validation to ensure it stays within the intended directories.
1. The `folder = Path(folder)` line creates a Path object directly from the user-provided string. If the string contains path traversal sequences like `../../`, the `Path` object will represent a path outside of the intended directory.
2. `os.listdir(folder)` and `os.path.join(folder, f)` then operate on this potentially malicious path, listing files and joining paths based on the attacker-controlled input.
3. The check `if not folder_path.exists():` only verifies if the resulting path exists, but not if it's a safe path.

Security test case:
1. Deploy the backend application to a test environment.
2. Identify the base URL of the backend application (e.g., `http://localhost:8000`).
3. Construct a malicious URL to test for path traversal in the `/evals` endpoint. For example: `http://localhost:8000/evals?folder=../../../../etc/`. Note: accessing `/etc/passwd` directly might be restricted by OS permissions, so accessing the `/etc/` directory to list files within it is a safer initial test.
4. Send a GET request to the constructed URL using a tool like `curl` or a web browser:
   ```bash
   curl "http://localhost:8000/evals?folder=../../../../etc/"
   ```
5. Analyze the response.
   - If the vulnerability exists, the response might contain a list of files from the `/etc/` directory (or an error message confirming access to `/etc/`). This indicates successful path traversal.
   - To further confirm and attempt to read a specific sensitive file, try accessing `/etc/passwd`:
     ```bash
     curl "http://localhost:8000/evals?folder=../../../../etc/passwd"
     ```
     If the response contains (or indicates access to) the content of `/etc/passwd`, the vulnerability is confirmed. Note that the application is looking for `.html` files, so this specific test might not directly return `/etc/passwd` content, but error messages or changes in behavior can still indicate successful traversal. A more direct test would involve creating a dummy `.html` file in `/tmp` and trying to access it via path traversal if `/tmp` is accessible. For instance if `/tmp/test.html` exists: `curl "http://localhost:8000/evals?folder=../../../../tmp/"` and expect to see `test.html` being processed if traversal to `/tmp` is successful. If listing files is not directly exposed in successful scenario, error messages indicating file not found in unexpected locations after path traversal attempts can also hint at the vulnerability.
6. Repeat steps 3-5 for the `/pairwise-evals` and `/best-of-n-evals` endpoints, adjusting the query parameters accordingly (`folder1=`, `folder2=`, `folder{i}=`).
