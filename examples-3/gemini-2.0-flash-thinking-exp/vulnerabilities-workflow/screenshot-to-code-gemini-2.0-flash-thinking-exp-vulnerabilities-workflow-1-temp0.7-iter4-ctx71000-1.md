## Vulnerability List

- Vulnerability Name: Path Traversal in Evaluation Folder Access
  - Description:
    1. An attacker sends a GET request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoint.
    2. In the query parameter `folder`, `folder1`, `folder2`, etc., the attacker provides a path that traverses outside the intended `EVALS_DIR` directory, for example, using paths like `/../../`.
    3. The backend code uses `os.listdir` and `os.path.join` with the attacker-controlled folder path to access files.
    4. If the path traversal is successful and points to a readable directory containing `.html` files, the server will read and return the content of those files in the response, potentially exposing sensitive information.
  - Impact:
    High: An attacker can read arbitrary files from the server's filesystem that the backend process has read permissions to. This could include configuration files, source code, or other sensitive data.
  - Vulnerability Rank: high
  - Currently implemented mitigations:
    - The code checks if the provided `folder_path` exists using `os.path.exists()`. This check is insufficient to prevent path traversal vulnerabilities as it only validates the existence of the path but not its legitimacy within the intended directory structure.
  - Missing mitigations:
    - Input validation and sanitization of the folder parameters to prevent path traversal.
    - Implement path canonicalization and validation to ensure that the resolved path stays within the intended base directory (e.g., `EVALS_DIR`).
    - Consider using a whitelist of allowed directories or strictly defining the acceptable input format for folder paths.
  - Preconditions:
    - The application must be running and accessible to the attacker.
    - The backend process must have read permissions to the files being targeted by the path traversal.
  - Source code analysis:
    - File: `backend/routes/evals.py`
    - Function: `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
    - Code Snippet (from `get_evals`):
      ```python
      @router.get("/evals", response_model=list[Eval])
      async def get_evals(folder: str):
          if not folder:
              raise HTTPException(status_code=400, detail="Folder path is required")

          folder_path = Path(folder) # folder is directly from user input
          if not folder_path.exists(): # Existence check, insufficient for path traversal prevention
              raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

          try:
              evals: list[Eval] = []
              # Get all HTML files from folder
              files = {
                  f: os.path.join(folder, f) # folder is directly from user input
                  for f in os.listdir(folder) # folder is directly from user input
                  if f.endswith(".html")
              }
              # ... rest of the code ...
      ```
    - The vulnerability is present because the `folder` parameter, which is directly controlled by the user, is used in `os.listdir(folder)` and `os.path.join(folder, f)` without proper validation or sanitization to prevent path traversal. Similar code patterns exist in `get_pairwise_evals` and `get_best_of_n_evals`.
  - Security test case:
    1. Deploy the application to a test environment.
    2. Create a test file named `test.html` with content `<h1>Test File</h1>` in the `/tmp` directory of the server (assuming a Linux-like environment and the backend process has read access to `/tmp`).
    3. Construct a GET request to the `/evals` endpoint with the `folder` parameter set to traverse to the `/tmp` directory. For example: `GET /evals?folder=../../tmp`
    4. Send the request to the application.
    5. Analyze the JSON response. If the vulnerability is present, the response will include an `evals` array containing an object with `outputs` that includes the content of `/tmp/test.html` (i.e., `<h1>Test File</h1>`), encoded within a data URL. This confirms that the attacker was able to list and read files from the `/tmp` directory via path traversal.
