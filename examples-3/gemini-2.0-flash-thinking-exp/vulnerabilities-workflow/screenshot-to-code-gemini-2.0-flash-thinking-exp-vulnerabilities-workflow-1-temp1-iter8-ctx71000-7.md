## Vulnerability List

### Path Traversal in Evals Endpoints

- Vulnerability Name: Path Traversal in Evals Endpoints
- Description:
    - An attacker can exploit the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints by manipulating the `folder`, `folder1`, `folder2`, etc. parameters.
    - By including directory traversal sequences like `../` or `..\\` in these parameters, the attacker can navigate the file system beyond the intended evaluation directories.
    - This allows them to potentially access and read sensitive files and directories on the server.
- Impact:
    - **High**: Unauthorized file system access.
    - Potential disclosure of sensitive information, including application configuration, source code, or other data stored on the server.
    - In a worst-case scenario, if the attacker can access writable directories or upload files, it could lead to further compromise, including code execution (though less likely in this specific context of reading HTML files).
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None.
    - While the code checks if the provided `folder` exists using `os.path.exists()`, it lacks proper input validation and sanitization to prevent path traversal attacks.
    - The use of `Path` objects does not inherently prevent path traversal when constructed from unsanitized string inputs.
- Missing mitigations:
    - **Input validation and sanitization**: Implement robust validation and sanitization of the `folder`, `folder1`, `folder2`, etc. parameters.
    - **Path normalization**: Normalize the input paths to remove traversal sequences before using them in file system operations.
    - **Restrict access to allowed directories**: Ideally, the application should be configured to only allow access to a specific, restricted directory for evaluations, and reject any paths outside of this base directory.
- Preconditions:
    - The backend application is deployed and accessible to external attackers over the network.
    - The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints are exposed and reachable by attackers.
- Source code analysis:
    - **File:** `backend/routes/evals.py`
    - **Vulnerable code:**
        - **`get_evals` function:**
            ```python
            @router.get("/evals", response_model=list[Eval])
            async def get_evals(folder: str):
                if not folder:
                    raise HTTPException(status_code=400, detail="Folder path is required")

                folder_path = Path(folder) # Path object creation from user input - vulnerable
                if not folder_path.exists():
                    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

                try:
                    evals: list[Eval] = []
                    # Get all HTML files from folder
                    files = {
                        f: os.path.join(folder, f) # os.path.join resolves traversal but starts from input 'folder'
                        for f in os.listdir(folder) # os.listdir operates on input 'folder'
                        if f.endswith(".html")
                    }
            ```
        - **`get_pairwise_evals` and `get_best_of-n-evals` functions:** These functions exhibit similar patterns, taking folder paths from query parameters and using `os.listdir` and `os.path.join` without proper sanitization.

    - **Vulnerability Explanation:**
        1. The endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` accept folder paths directly from user input (query parameters).
        2. The code uses `os.listdir(folder)` and `os.path.join(folder, f)` to list and access files within the provided folder.
        3. If an attacker provides a `folder` parameter like `../../sensitive_dir`, `os.listdir` and `os.path.join` will operate on the directory path resolved by traversing up from the current directory, effectively allowing access outside the intended directories.
        4. The `Path(folder)` creation does not prevent traversal because it simply creates a path object from the string, it doesn't sanitize or restrict it.
    - **Visualization:**

    ```
    User Input (folder parameter):  "../../sensitive_dir"
        |
        v
    Path(folder) in code:         Path("../../sensitive_dir")
        |
        v
    os.listdir(folder):          Operates on the directory resolved by Path("../../sensitive_dir")
    os.path.join(folder, f):     Joins paths based on the potentially traversed 'folder'
    ```
- Security test case:
    1. **Environment Setup:** Deploy the application to a test environment where you can send HTTP requests. Ensure there are some files outside the intended evaluation directory that you can try to access (for example, a test file named `test_sensitive.txt` in the parent directory of the application's root directory, if feasible in your test setup).
    2. **Send Path Traversal Request to `/evals` endpoint:**
        - Construct a GET request to the `/evals` endpoint.
        - In the query parameters, set the `folder` parameter to a path traversal string like `../`. If you want to try to access a specific file, for example, `test_sensitive.txt` in the parent directory, you might need to adjust the traversal string accordingly, such as `../../`. For example: `GET /evals?folder=../` or `GET /evals?folder=../../`.
        - Send the crafted GET request to the application.
    3. **Analyze the Response:**
        - Observe the HTTP response from the server.
        - **If Vulnerable:** If the application is vulnerable, you might see one of the following:
            - An error message indicating that the server tried to access a directory outside the intended scope, but the error itself confirms the traversal attempt was made.
            - If there are `.html` files in the traversed directory (e.g., parent directory), the response might contain data from these files, confirming successful traversal.
            - In some cases, you might get a generic error (HTTP 500) if the server encounters permissions issues or other errors when trying to access files outside its intended scope, but even this can indicate a path traversal attempt.
        - **Specifically test for sensitive file access:** If you placed a `test_sensitive.txt` file in a predictable location relative to the application, try to access it using a more targeted path traversal in the `folder` parameter, like `folder=../../../test_sensitive.txt` (adjust the number of `../` based on the file's location). If you receive the content of `test_sensitive.txt` or an error message clearly indicating access to this file was attempted, it confirms the vulnerability.
    4. **Repeat for `/pairwise-evals` and `/best-of-n-evals`:** Perform steps 2 and 3 for the `/pairwise-evals` and `/best-of-n-evals` endpoints, using `folder1`, `folder2`, and `folder{i}` parameters respectively, to verify the vulnerability across all affected endpoints. For `/pairwise-evals` use `folder1=../&folder2=./`, and for `/best-of-n-evals` use `folder1=../&folder2=./&folder3=./` etc.
    5. **Document Findings:** Record your observations. If you successfully triggered directory traversal and accessed files outside the intended evaluation directories, document this as a confirmed Path Traversal vulnerability.
