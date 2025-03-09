## Vulnerability List:

### 1. Path Traversal in Evals Endpoints

- **Vulnerability Name:** Path Traversal in Evals Endpoints
- **Description:**
    The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in `evals.py` are vulnerable to path traversal. An attacker can manipulate the `folder`, `folder1`, `folder2`, etc. parameters to access files and directories outside the intended evaluation folders. By providing paths like `../sensitive_folder` or absolute paths like `/etc/`, an attacker might be able to list directories and potentially read arbitrary files from the server's filesystem, depending on file permissions.

    **Step-by-step trigger:**
    1. The attacker identifies the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoint.
    2. The attacker crafts a GET request to one of these endpoints.
    3. In the query parameters, the attacker provides a path that traverses outside the intended directory for the `folder`, `folder1`, `folder2`, etc. parameter. For example, using `?folder=../` to try to access the parent directory, or `?folder=/etc/` to attempt to access system directories.
    4. The server-side code uses `os.listdir` and `os.path.join` with the user-provided path without sufficient validation to ensure the path stays within the intended directories.
    5. The server attempts to list files and read HTML files in the traversed directory.
    6. If successful (depending on file permissions), the attacker can potentially read data from unexpected locations.

- **Impact:**
    An attacker can list directories and potentially read files from the server's filesystem outside the intended evaluation directories. This could lead to information disclosure of sensitive data, including application source code, configuration files, or other data accessible to the server process.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The code checks if the provided `folder`, `folder1`, `folder2`, etc. paths exist using `os.path.exists()`.
    - This check only verifies the existence of the directory but does not prevent path traversal as it does not validate if the path is within an allowed base directory.

- **Missing Mitigations:**
    - **Input validation and sanitization:** Implement robust validation to ensure that the provided folder paths are within the expected base directory (e.g., `EVALS_DIR`).
    - **Path normalization and restriction:** Normalize the user-provided paths and use functions to ensure that the final path after joining stays within the intended base directory. For example, using `os.path.abspath` and checking if it starts with the allowed base path.
    - **Principle of least privilege:** Ensure the application runs with minimal necessary permissions to reduce the impact if path traversal is exploited.

- **Preconditions:**
    - The application must be deployed and publicly accessible.
    - The attacker needs to identify and access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.

- **Source Code Analysis:**
    - **File:** `backend/routes/evals.py`
    - **Endpoints:** `/evals`, `/pairwise-evals`, `/best-of-n-evals`
    - **Code Snippets:**
        ```python
        # For /evals endpoint:
        folder = request.query_params.get("folder")
        folder_path = Path(folder)
        if not folder_path.exists(): # Existence check, not path traversal prevention
            raise HTTPException(...)
        files = {
            f: os.path.join(folder, f) # Vulnerable path join
            for f in os.listdir(folder) # Vulnerable listdir
            if f.endswith(".html")
        }
        ```
        ```python
        # For /pairwise-evals and /best-of-n-evals, similar pattern:
        folder1 = Query(...) # User-provided folder path
        if not os.path.exists(folder1): # Existence check, not path traversal prevention
            return {"error": ...}
        files1 = {
            f: os.path.join(folder1, f) # Vulnerable path join
            for f in os.listdir(folder1) # Vulnerable listdir
            if f.endswith(".html")
        }
        ```
    - **Vulnerability Explanation:** The vulnerability arises because the code directly uses user-provided folder paths with `os.listdir` and `os.path.join` without validating that these paths are within the intended `EVALS_DIR` or a set of allowed directories. The `os.path.exists()` check is insufficient as it only verifies if the given path exists, not if it's a safe path to access. An attacker can supply paths like `../`, `../../`, or absolute paths to traverse the filesystem and access files outside the intended scope.

- **Security Test Case:**
    1. **Target Endpoint:** `/evals`
    2. **Method:** GET
    3. **Parameters:** `folder`
    4. **Request:** Send a GET request to `/evals?folder=../`
    5. **Expected Outcome:** The server should process the request without blocking it due to path traversal. The response might be an empty list of evals if no HTML files are found in the parent directory, or an error if it encounters permission issues while listing or reading files in the parent directory. The key is that the application attempts to access and process files from outside the intended `EVALS_DIR` based on the traversed path.
    6. **Verification:**
        - Observe the server's behavior. If the server does not immediately reject the request as invalid due to path traversal, and proceeds to process the request (even if it results in an empty response or an error due to file access permissions in the traversed directory), it confirms the path traversal vulnerability.
        - Ideally, monitor server logs to see if there are attempts to list files in directories like the parent directory or system directories when providing traversal paths like `../` or `/etc/`.
