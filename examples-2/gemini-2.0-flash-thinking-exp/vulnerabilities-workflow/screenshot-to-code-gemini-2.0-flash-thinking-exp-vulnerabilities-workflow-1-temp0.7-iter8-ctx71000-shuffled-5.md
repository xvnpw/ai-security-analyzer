### Vulnerability 1: Path Traversal in Evals Routes

- Vulnerability Name: Path Traversal in Evals Routes
- Description:
    An attacker can exploit the `folder` parameter in the `/evals` route to access files and directories outside of the intended evaluation directory. This is possible because the application does not properly sanitize or validate the folder path provided by the user. By crafting a malicious folder path, such as "../../../", an attacker can navigate up the directory tree and access sensitive files or directories on the server.

    Steps to trigger vulnerability:
    1. Access the `/evals` endpoint with a crafted `folder` query parameter.
    2. Set the `folder` parameter to a path that traverses outside the intended `evals_data` directory, for example, `folder=../../../`.
    3. The application will attempt to list files in the attacker-specified directory. If successful, the attacker can confirm path traversal. By examining the server responses or logs (if accessible), the attacker can identify if files from outside the intended directory are being accessed. Deeper exploitation would require further steps to access and retrieve file content, which might be possible depending on the application's file handling logic in other parts of the evals routes.

- Impact:
    Successful path traversal can allow an attacker to:
    - List directories outside of the intended `evals_data` directory.
    - Potentially read sensitive files on the server if the application logic allows further file access based on the traversed path.
    - Gain unauthorized information about the server's file system structure.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
    None. The code uses `os.path.join` and `os.listdir` on the user-provided `folder` input without any validation to ensure it stays within the intended directory.
- Missing Mitigations:
    - Input validation: Implement server-side validation to sanitize and verify the `folder` parameter. Ensure that the provided path is within the intended `EVALS_DIR` and does not contain path traversal sequences like `../`.
    - Path sanitization: Use secure path manipulation functions to resolve and canonicalize the user-provided path and compare it against the allowed base directory (`EVALS_DIR`).
- Preconditions:
    - The application must be running and accessible to external attackers.
    - The `/evals` route must be exposed and reachable.

- Source Code Analysis:
    File: `backend/routes/evals.py`

    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [LINE 1]
        if not folder_path.exists(): # [LINE 2]
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [LINE 3]
                for f in os.listdir(folder) # [LINE 4]
                if f.endswith(".html")
            }
            # ... rest of the code ...
    ```
    - **LINE 1**: `folder_path = Path(folder)`:  Creates a Path object from the user-provided `folder` string. While using `Path` is generally good practice, it doesn't inherently prevent path traversal if the base path is not enforced.
    - **LINE 2**: `if not folder_path.exists():`: Checks if the provided `folder_path` exists. This check prevents errors if a non-existent folder is provided, but it does not prevent traversal to legitimate folders outside of `EVALS_DIR`.
    - **LINE 3 & 4**: `files = {f: os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html")}`:  Uses `os.listdir(folder)` to list files in the directory specified by the user-controlled `folder` variable and then joins the path using `os.path.join(folder, f)`. If the `folder` variable contains path traversal characters like `../`, `os.listdir` and `os.path.join` will operate outside the intended `EVALS_DIR` if the resulting path is still valid on the filesystem.

    **Visualization:**

    Imagine `EVALS_DIR` is `/app/backend/evals_data`.
    If an attacker provides `folder = '../../../'`, then:
    - `folder_path` becomes a Path object representing `../../../`.
    - `folder_path.exists()` might return `True` if directories above `/app/backend/evals_data` exist.
    - `os.listdir(folder)` becomes `os.listdir('../../../')`, which will list directories from the root of the application or even system depending on the deployment.
    - `os.path.join(folder, f)` will join `../../../` with filenames, still resulting in paths outside of `EVALS_DIR`.

- Security Test Case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible instance.
    2. As an external attacker, open a web browser and navigate to the `/evals` endpoint of the deployed application.
    3. Craft a malicious URL by appending the query parameter `?folder=../../../`. For example: `http://<deployed-application-url>/evals?folder=../../../`.
    4. Send the crafted request to the server.
    5. Observe the server's response. If the vulnerability exists, the server might return an error message indicating it could not find files, or in some cases, it might unexpectedly list files or directories from a higher level in the file system (depending on directory permissions and application behavior).
    6. To further verify, try to access a known file outside the intended directory but within the application's or system's reach using path traversal, e.g., `?folder=../../backend`. If the application attempts to process this path and the server response changes (e.g., different error, or logs indicate file access attempts in the backend directory), it further confirms the path traversal vulnerability.
