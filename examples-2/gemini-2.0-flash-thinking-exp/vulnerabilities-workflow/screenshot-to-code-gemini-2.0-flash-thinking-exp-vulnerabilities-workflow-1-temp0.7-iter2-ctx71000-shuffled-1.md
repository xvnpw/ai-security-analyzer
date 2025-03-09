## Vulnerability List

- Vulnerability Name: Path Traversal in Evaluation File Access

- Description:
    An external attacker can exploit a path traversal vulnerability to access arbitrary files on the server by manipulating the `folder`, `folder1`, or `folder2` parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` API endpoints. By providing a crafted path containing directory traversal sequences like `../`, an attacker can potentially read sensitive files outside of the intended evaluation directories.

    Steps to trigger the vulnerability:
    1. Access the `/evals` endpoint (or `/pairwise-evals`, `/best-of-n-evals`) with a crafted `folder` parameter (or `folder1`, `folder2` respectively).
    2. Set the `folder` parameter to a path containing directory traversal sequences, for example: `folder=../../../../etc/passwd`.
    3. The backend application will attempt to access files within the specified path. Due to insufficient path validation, it may access files outside the intended `evals_data` directory.
    4. If successful, the attacker will receive an error message indicating a failure to process the file or folder, or in some cases, may even be able to read the content if the application attempts to process files it shouldn't. While the current code reads HTML and images, an attacker could potentially try to read other file types by manipulating the code or exploiting other endpoints if they exist or are added later.

- Impact:
    An attacker can read arbitrary files on the server, including application code, configuration files, and potentially sensitive data if they are accessible to the application's user. This can lead to information disclosure, which can be further used to compromise the application or the server.

- Vulnerability Rank: High

- Currently implemented mitigations:
    - The code checks if the provided `folder` exists using `folder_path.exists()` and `os.path.exists(folder1)`, `os.path.exists(folder2)`.
    - The code only reads `.html` and `.png` files.

- Missing mitigations:
    - Input path sanitization and validation to prevent directory traversal sequences like `../`.
    - Restricting the base directory for file access to the intended `evals_data` directory and its subdirectories.
    - Using secure path manipulation functions that prevent traversal, such as `os.path.abspath` combined with checks to ensure the resolved path is still within the allowed base directory.

- Preconditions:
    - The application must be deployed and accessible to external attackers.
    - The attacker needs to identify the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints and understand that they accept file paths as parameters.

- Source code analysis:
    - File: `backend/routes/evals.py`

    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [LINE 1] Path is created directly from user input 'folder'
        if not folder_path.exists(): # [LINE 2] Checks if folder exists, but doesn't prevent traversal
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [LINE 3] Path is joined with user input 'folder'
                for f in os.listdir(folder) # [LINE 4] List directory content based on user input 'folder'
                if f.endswith(".html")
            }
            # ... rest of the code ...
    ```
    - In `get_evals` function (and similarly in `get_pairwise_evals` and `get_best_of_n_evals`), the `folder` parameter from the query is directly used to create a `Path` object and in `os.listdir` and `os.path.join`.
    - Line 1: `folder_path = Path(folder)` -  A `Path` object is created directly from the user-provided `folder` string without any sanitization or validation against path traversal characters.
    - Line 2: `if not folder_path.exists():` - This line only checks if the folder exists at the path provided by the user. It does not validate if the path is within the intended directory or prevent path traversal.
    - Line 3: `f: os.path.join(folder, f)` - `os.path.join` is used to construct file paths by joining the user-provided `folder` with filenames found in the directory. If `folder` contains traversal sequences, `os.path.join` will not prevent the traversal.
    - Line 4: `os.listdir(folder)` - `os.listdir` lists the contents of the directory specified by the user-provided `folder`. If `folder` points to a directory outside of the intended `evals_data` directory due to path traversal, `os.listdir` will operate in that directory.

    - Visualization:
    Imagine `EVALS_DIR` is `/app/backend/evals_data`.
    If attacker provides `folder=../../../../etc`, `folder_path` becomes `Path('../../../../etc')`.
    `folder_path.exists()` will check if `/etc` exists (which it likely does).
    `os.listdir(folder)` will list files in `/etc`.
    `os.path.join(folder, f)` will create paths like `../../../../etc/passwd`.

- Security test case:
    1. Deploy the `screenshot-to-code` backend application.
    2. As an attacker, craft a GET request to the `/evals` endpoint with the following parameters: `folder=../../../../etc`. The full URL might look like: `http://<deployed-backend-url>/evals?folder=../../../../etc`.
    3. Send the request to the deployed application.
    4. Observe the response. If the application returns an HTTP 500 error with a detail message indicating "Error processing evals: [Errno 2] No such file or directory: '<path-within-/etc>'", or a 404 error indicating "Folder not found", this could still indirectly confirm the path traversal vulnerability by showing the application attempted to access files within `/etc`.
    5. To further confirm and attempt to read a known file, craft a GET request to the `/evals` endpoint with the following parameters: `folder=../../../../etc&file=passwd`. This is a modified test case, as the original endpoint doesn't directly allow specifying a file, but it highlights the potential. In the current code, this specific test might not directly read `/etc/passwd` content because it's looking for `.html` files, but it demonstrates the path traversal. A more successful test would involve creating a dummy `.html` file within `/etc` (if possible in a test environment) or observing error messages closely for path traversal effects.
    6. Examine the server logs for any file access attempts outside of the intended `evals_data` directory. If logs indicate access attempts to paths like `/etc/passwd` or other system files based on the manipulated `folder` parameter, the path traversal vulnerability is confirmed.

    **Improved Security Test Case (more directly verifiable):**
    1.  **Setup:** In a testing environment where you can control the filesystem, create a directory within the `/backend/evals_data/inputs` directory, for example, `test_dir`. Inside `test_dir`, place a dummy file named `test.html` with some content like `<h1>Test File</h1>`. Also, place a sensitive file outside of the intended directory, for example, at the root level `/sensitive.txt` with content `This is sensitive data`.
    2.  **Attack Attempt 1 (Intended Directory Access):** Send a GET request to `/evals?folder=evals_data/inputs/test_dir`. Observe that the application correctly processes `test.html` and includes its content in the response (if the test setup and expected behavior allow for content to be returned in this way - in the current implementation, it's more about listing and processing files for evaluation, so adjust test expectation accordingly).
    3.  **Attack Attempt 2 (Path Traversal):** Send a GET request to `/evals?folder=../../../../`. This attempts to traverse to the root directory. Observe the response. It's likely to be a 404 or 500 error as it might not find `.html` files directly at the root.
    4.  **Attack Attempt 3 (Reading Sensitive File - adjusted for file type and endpoint behavior):** Since the current `/evals` endpoint is designed to process `.html` files within specified folders, directly reading `/sensitive.txt` might not be possible with this endpoint as is. However, to demonstrate path traversal leading to potential sensitive file access, we can observe error messages more closely in attempts 2 and 3, or consider modifying the backend code temporarily for testing to read and return file contents directly for any file type if a valid path is provided (for testing purposes only, never in production!). For instance, if error messages reveal "Folder not found: ../../../../etc/passwd" or similar after attempting `/evals?folder=../../../../etc/passwd`, it indicates the application is indeed attempting to access the traversed path.
    5.  **Log Analysis:** Examine application logs for file access attempts. Look for any log entries indicating the application tried to access files or directories outside the intended `evals_data` path when using manipulated `folder` parameters.
