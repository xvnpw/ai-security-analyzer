## Vulnerability List

### Vulnerability Name: Path Traversal in `/evals` endpoint

* Description:
    1. An attacker sends a GET request to the `/evals` endpoint.
    2. The attacker crafts a malicious `folder` query parameter, attempting to traverse directories, for example: `../../../../etc/passwd`.
    3. The backend application receives this request and uses the provided `folder` path directly with `os.listdir()` and `os.path.join()` without proper validation or sanitization.
    4. `os.listdir()` lists files and directories within the path specified by the attacker, and `os.path.join()` constructs file paths based on the attacker-controlled `folder` parameter.
    5. If the attacker-provided path leads to a directory containing `.html` files and is readable by the application, the application proceeds to read these files.
    6. If successful, the attacker can potentially read the content of arbitrary files on the server's filesystem, depending on file permissions and the application's execution context.

* Impact:
    - **Information Disclosure**: Successful exploitation allows an attacker to read arbitrary files from the server. This could include sensitive data such as configuration files, application source code, internal application data, or even system files if permissions allow.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The code checks if the provided folder exists using `folder_path.exists()`, but this does not prevent path traversal as it doesn't validate if the path is within an allowed base directory.

* Missing Mitigations:
    - **Input Validation and Sanitization**: Implement robust validation for the `folder` parameter to ensure it is a safe path and within the expected directories. This could involve:
        - **Whitelisting**: Define a set of allowed base directories and verify that the provided path is a subdirectory of one of these allowed directories.
        - **Path Canonicalization**: Convert both the user-provided path and the allowed base directory to their canonical forms (e.g., by resolving symbolic links and removing redundant separators like `..`) and check if the user-provided path starts with the allowed base directory.
        - **Blacklisting dangerous characters**: Although less robust than whitelisting, blacklisting characters like `../` could offer a basic level of protection but is generally not recommended as it can be bypassed.
    - **Secure Path Manipulation**: Utilize secure path manipulation functions that prevent path traversal, ensuring that any file access remains within the intended boundaries.

* Preconditions:
    - The application must be deployed and publicly accessible.
    - The `/evals` endpoint must be exposed and reachable by external users.

* Source Code Analysis:
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [POINT OF VULNERABILITY 1] User-provided path is directly converted to Path object without sanitization.
        if not folder_path.exists(): # Existence check is insufficient to prevent traversal.
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [POINT OF VULNERABILITY 2] User-provided 'folder' is used in path construction without validation.
                for f in os.listdir(folder) # [POINT OF VULNERABILITY 3] User-provided 'folder' is used in os.listdir without validation.
                if f.endswith(".html")
            }
            # ... rest of the code ...
    ```
    The vulnerability lies in the direct use of the `folder` parameter from the query string in `os.listdir()` and `os.path.join()` without any validation to ensure that the path stays within the intended evaluation directories. The `folder_path.exists()` check is insufficient as it only verifies if the path exists, not if it's a safe or intended path. An attacker can manipulate the `folder` parameter to traverse up the directory structure and access files outside the intended scope.

* Security Test Case:
    1. Deploy the application to a test environment or a publicly accessible instance.
    2. Identify the base directory where evaluation folders are expected to be located on the server.
    3. Craft a GET request to the `/evals` endpoint. In the `folder` query parameter, insert a path traversal string to target a sensitive file on the server, such as `/etc/passwd` on Linux-based systems or `C:\Windows\win.ini` on Windows-based systems. For example:
        ```
        GET /evals?folder=../../../../etc/passwd
        ```
        or
        ```
        GET /evals?folder=../../../../C:\Windows\win.ini
        ```
    4. Send the crafted GET request to the application.
    5. Analyze the HTTP response from the server.
        - **Successful Exploitation**: If the vulnerability is successfully exploited, the server's response might contain the content of the targeted sensitive file (e.g., `/etc/passwd` or `win.ini`) within the `outputs` field of the JSON response, especially if there happens to be an HTML file in the traversed directory (which is unlikely for `/etc/passwd` but possible for other paths). Even if no HTML file is found in the traversed directory, an error message different from "Folder not found" or "Error processing evals" could indicate successful traversal and an attempt to access the directory.
        - **Error Response**: If the application returns an error such as "Folder not found" (HTTP 404) or "Error processing evals" (HTTP 500) and the error message or logs indicate a file system error related to accessing the traversed path, this could also indicate successful path traversal attempt, even if the file content is not directly returned in the response.
    6. Examine the server-side logs for any file access errors or unusual activity related to the path traversal attempt.
    7. If the response or server logs indicate successful access to the sensitive file or directory outside the intended scope, the path traversal vulnerability is confirmed.
