### Vulnerability list:

* Path Traversal in Evals Endpoints
    * Description: The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in `evals.py` take folder paths as input parameters (`folder`, `folder1`, `folder2`, etc.) and use them to access files using `os.listdir` and `os.path.join`. There is validation to check if the folder exists using `os.path.exists()`, but there is no sanitization or restriction on the folder path itself. An attacker can provide a malicious folder path like `../../../../etc/passwd` to potentially list files outside of the intended `EVALS_DIR`. In the current implementation, it lists `.html` files and reads their content if they match certain criteria. Even listing directory content outside of the intended directory is a form of information disclosure and path traversal.
    * Impact: High. An attacker can potentially list directory contents outside of the intended evaluation directories, leading to information disclosure. Depending on how the application processes files in these directories, there might be potential for further exploitation like reading sensitive files if the code is extended to handle more file operations in the future.
    * Vulnerability rank: high
    * Currently implemented mitigations: Checking if the folder exists using `os.path.exists()`.
    * Missing mitigations: Input sanitization and validation of the folder path. Restricting the folder path to be within the intended `EVALS_DIR` or using a whitelist approach to only allow predefined folders. Using secure path handling functions to prevent path traversal.
    * Preconditions: The application must be running and accessible to external attackers. The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints must be exposed publicly.
    * Source code analysis:
        ```python
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str):
            if not folder:
                raise HTTPException(status_code=400, detail="Folder path is required")

            folder_path = Path(folder) # Line 1
            if not folder_path.exists(): # Line 2
                raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

            try:
                evals: list[Eval] = []
                # Get all HTML files from folder
                files = {
                    f: os.path.join(folder, f) # Line 3 - Path traversal here
                    for f in os.listdir(folder) # Line 4 - Path traversal here
                    if f.endswith(".html")
                }
                # ... rest of the code ...
        ```
        In line 1, the user-provided `folder` string is converted to a `Path` object. Line 2 checks if the folder exists. However, neither of these lines prevent path traversal. Lines 3 and 4 use `os.path.join(folder, f)` and `os.listdir(folder)` directly with the user-provided `folder` path. If an attacker provides `folder = "../../"` the `os.listdir("../../")` will list files in the directory two levels above the current working directory of the backend. `os.path.join("../../", "file.html")` will also resolve to a path outside the intended directory.

    * Security test case:
        1. Identify the URL for the `/evals` endpoint of the publicly accessible application. Let's assume it is `https://example.com/api/evals`.
        2. Craft a malicious request to the `/evals` endpoint by providing a path traversal payload as the `folder` parameter. For example: `https://example.com/api/evals?folder=../../`
        3. Send the crafted request to the application.
        4. Observe the response. If the application returns a list of evals, examine the content of the evals. Check if the file paths or content in the response are from directories outside the intended evaluation directories. If the response lists files or shows content from system directories or directories outside of the expected `EVALS_DIR`, it confirms the path traversal vulnerability. For example, if the application lists `.html` files from the parent directory or root directory (depending on where the backend is running and what's in the parent/root directory), it's a successful path traversal.
