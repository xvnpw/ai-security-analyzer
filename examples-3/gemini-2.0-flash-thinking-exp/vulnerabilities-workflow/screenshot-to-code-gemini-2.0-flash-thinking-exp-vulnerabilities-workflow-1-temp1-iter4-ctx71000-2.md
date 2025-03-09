- Path Traversal Vulnerability in Evals Endpoints
    - Description:
        The application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` that allow users to specify folder paths as query parameters. These paths are used to read HTML files for evaluation purposes. However, the application does not properly sanitize or validate these folder paths. This allows an attacker to manipulate the folder paths to traverse the file system and potentially read arbitrary files on the server, if the application has sufficient file system permissions.

        To trigger this vulnerability, an attacker can send a crafted HTTP GET request to one of the vulnerable endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) and include a malicious folder path in the query parameters. For example, in the `/evals` endpoint, the attacker can set the `folder` parameter to a path containing path traversal sequences like `../` to navigate to parent directories and access files outside the intended evaluation directories.

        Steps to trigger the vulnerability in `/evals`:
        1. Identify a publicly accessible instance of the application.
        2. Craft a GET request to the `/evals` endpoint with a malicious `folder` parameter. For example: `/evals?folder=../../../../etc/passwd`.
        3. Send the crafted request to the application.
        4. If the application has sufficient permissions and path traversal is successful, the attacker may receive an error message indicating that the folder was not found, or a server error if it attempts to process non-HTML files. In a successful attack, the attacker could potentially read the content of `/etc/passwd` or other accessible files, if they were processed as if they were HTML files and returned in the `evals` response. Note that reading `/etc/passwd` directly might not be the primary goal, but rather accessing application configuration files or other sensitive data within the application's file system.

        Similar steps apply to `/pairwise-evals` and `/best-of-n-evals`, by manipulating `folder1`, `folder2`, etc. parameters.

    - Impact:
        High. Successful exploitation of this vulnerability could allow an attacker to read arbitrary files from the server's file system that the application process has access to. This could lead to:
        - **Exposure of sensitive application data:** Configuration files, database credentials, API keys, source code, and other sensitive information could be exposed.
        - **Privilege escalation (in some scenarios):** If application configuration files are readable, attackers might find credentials or configuration errors that could be used for privilege escalation in other parts of the system.
        - **Further attacks:** Information gathered through path traversal can be used to plan more sophisticated attacks.

    - Vulnerability rank: high

    - Currently implemented mitigations:
        - The code checks if the provided `folder_path` exists using `folder_path.exists()` in the `get_evals` endpoint and `os.path.exists(folder1)` and `os.path.exists(folder2)` in `get_pairwise_evals`, and similar checks in `get_best_of_n_evals`. However, this check only verifies the existence of the path after potential traversal has already occurred. It does not prevent path traversal itself.
        - The code also checks if files end with `.html` before processing them, limiting the type of files read, but not preventing access to HTML files outside intended directories.

    - Missing mitigations:
        - **Input sanitization:** The application should sanitize the input folder paths to remove or escape path traversal sequences like `../` and `./`.
        - **Path validation/Canonicalization:** Use secure path handling functions that canonicalize the paths and validate that the resolved path is within the expected base directory (e.g., within or under `EVALS_DIR`). Check if the resolved path starts with the intended base directory prefix.
        - **Principle of least privilege:** Ensure the application process runs with the minimum necessary file system permissions to reduce the impact of successful path traversal.

    - Preconditions:
        - The application must be deployed and accessible to external attackers.
        - The attacker must be able to send HTTP requests to the application's endpoints.
        - The application process needs to have file system read permissions to the files being targeted by path traversal.

    - Source code analysis:
        - **File: `..\screenshot-to-code\backend\routes\evals.py`**

        - **Function: `get_evals`**
            ```python
            @router.get("/evals", response_model=list[Eval])
            async def get_evals(folder: str):
                if not folder:
                    raise HTTPException(status_code=400, detail="Folder path is required")

                folder_path = Path(folder) # [POINT OF CONCERN] Path is created from user input without sanitization
                if not folder_path.exists(): # Check if the path exists, but after potential traversal
                    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

                try:
                    evals: list[Eval] = []
                    # Get all HTML files from folder
                    files = {
                        f: os.path.join(folder, f) # [POINT OF CONCERN] os.path.join is used with unsanitized folder input
                        for f in os.listdir(folder) # [POINT OF CONCERN] os.listdir is used with unsanitized folder input
                        if f.endswith(".html")
                    }
                    ...
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
            ```
            In `get_evals`, the `folder` parameter from the query is directly used to create a `Path` object and in `os.listdir` and `os.path.join` without any sanitization. This allows path traversal sequences in the `folder` parameter to be interpreted by the operating system, potentially leading to access to files outside the intended directory.

        - **Function: `get_pairwise_evals` and `get_best_of_n_evals`**
            These functions exhibit similar vulnerability patterns as `get_evals` in how they handle folder paths from query parameters. They directly use `folder1`, `folder2`, etc. in `os.path.join` and `os.listdir` without proper sanitization, making them vulnerable to path traversal as well.

    - Security test case:
        1. Deploy the application in a test environment where you can observe file system access.
        2. Choose a target file on the server that the application process is likely to have read access to, but is outside the intended `EVALS_DIR` directory. For example, within the application directory structure, if `EVALS_DIR` is in `/app/evals`, a target could be a file in `/app/config/app_config.html` (if it exists and is readable). Alternatively, in a Linux environment, a common target for testing path traversal might be `/etc/passwd` although reading this may be restricted by permissions and may not be as useful in this application context. Focus on accessing files relative to the application's intended data directories, e.g. configuration files or similar resources.
        3. Craft a GET request to `/evals` endpoint with the `folder` parameter set to traverse to the target file. For example, if `EVALS_DIR` is expected to be in `/app/evals`, and you want to access `/app/config/app_config.html`, the malicious folder path could be `folder=../../config`. The full URL would be something like `http://<application-url>/evals?folder=../../config`. Assuming the filenames inside `/app/config` are predictable or guessable (e.g., `app_config.html`), and they have matching PNG inputs, the application might attempt to process and return them.
        4. Send the crafted request to the application.
        5. Analyze the response. If the vulnerability is successfully exploited, you might see content from the targeted file (if it's HTML and matches naming conventions) in the `outputs` of the `evals` response. Even if direct file content is not returned due to file type or naming mismatches, observe server logs or file system access logs (if available) to confirm if the application attempted to access the files outside the intended directory.
        6. Repeat steps for `/pairwise-evals` and `/best-of-n-evals` endpoints, adjusting the query parameters accordingly (`folder1`, `folder2`, etc.) and the path traversal payload.
