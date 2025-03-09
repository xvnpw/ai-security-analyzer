- Vulnerability Name: Path Traversal in Evaluation File Access

- Description:
  1. The application exposes endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) in `backend\routes\evals.py` that allow users to retrieve evaluation data.
  2. These endpoints take folder paths as input parameters (`folder`, `folder1`, `folder2`, etc.).
  3. The application uses `os.listdir()` and `os.path.join()` functions to list files and construct file paths within the user-provided folders.
  4. There is insufficient validation or sanitization of the input folder paths.
  5. An attacker can provide a malicious folder path containing path traversal sequences (e.g., `../`, `..\\`) to access files and directories outside the intended evaluation folders.
  6. For example, an attacker could use a path like `../../../../etc/passwd` or `../../../../sensitive_eval_data` to access sensitive system files or evaluation data stored in other directories.
  7. This vulnerability allows an attacker to read arbitrary files on the server if the application process has sufficient file system permissions.

- Impact:
  - An attacker can read arbitrary files from the server's file system.
  - This can lead to the disclosure of sensitive information, including:
    - Application source code.
    - Configuration files, potentially containing API keys or database credentials.
    - Internal evaluation data or results.
    - System files, depending on the server's file system permissions.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - The code checks if the provided folder exists using `os.path.exists()`. However, this check does not prevent path traversal as it only validates the final resolved path, not the path traversal sequences within the input.
  - The application only reads `.html` and `.png` files. This partially limits the impact but does not prevent reading any `.html` or `.png` file accessible by the application process if path traversal is successful.

- Missing Mitigations:
  - Input validation and sanitization: Implement robust input validation and sanitization for the folder path parameters.
    - Whitelist approach: Define a restricted set of allowed base directories for evaluations and validate that the user-provided path is within these allowed directories.
    - Path sanitization: Sanitize the input path to remove or neutralize path traversal sequences (e.g., `../`, `..\\`). Use secure path manipulation functions that resolve paths safely and prevent traversal outside allowed directories.
  - Principle of least privilege: Ensure that the application process runs with the minimum necessary file system permissions to limit the scope of readable files in case of successful path traversal.

- Preconditions:
  - The application must be deployed and accessible to external attackers.
  - An attacker needs to identify and access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
  - The attacker needs to be able to manipulate the `folder`, `folder1`, `folder2`, etc. query parameters in the HTTP requests to these endpoints.

- Source Code Analysis:
  ```python
  File: ..\screenshot-to-code\backend\routes\evals.py

  @router.get("/evals", response_model=list[Eval])
  async def get_evals(folder: str): # [USER INPUT] 'folder' parameter from request
      if not folder:
          raise HTTPException(status_code=400, detail="Folder path is required")

      folder_path = Path(folder) # [PATH CONSTRUCTION] Path object created from user input
      if not folder_path.exists(): # [EXISTENCE CHECK] Checks if the resolved path exists, but allows traversal
          raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

      try:
          evals: list[Eval] = []
          # Get all HTML files from folder
          files = {
              f: os.path.join(folder, f) # [PATH JOIN] Path is joined using user input
              for f in os.listdir(folder) # [LIST DIRECTORY] Lists files in user provided folder
              if f.endswith(".html")
          }
          # ... (rest of the code) ...

  @router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
  async def get_pairwise_evals(
      folder1: str = Query( # [USER INPUT] 'folder1' parameter from request
          "...",
          description="Absolute path to first folder",
      ),
      folder2: str = Query( # [USER INPUT] 'folder2' parameter from request
          "..",
          description="Absolute path to second folder",
      ),
  ):
      if not os.path.exists(folder1) or not os.path.exists(folder2): # [EXISTENCE CHECK] Checks if the resolved paths exist, but allows traversal
          return {"error": "One or both folders do not exist"}

      # Get all HTML files from first folder
      files1 = {
          f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html") # [PATH JOIN & LIST DIRECTORY] Path is joined and directory listed using user input
      }
      files2 = {
          f: os.path.join(folder2, f) for f in os.listdir(folder2) if f.endswith(".html") # [PATH JOIN & LIST DIRECTORY] Path is joined and directory listed using user input
      }
      # ... (rest of the code) ...

  @router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
  async def get_best_of_n-evals(request: Request):
      # Get all query parameters
      query_params = dict(request.query_params)

      # Extract all folder paths (folder1, folder2, folder3, etc.)
      folders = []
      i = 1
      while f"folder{i}" in query_params: # [USER INPUT] 'folder1', 'folder2', etc. parameters from request
          folders.append(query_params[f"folder{i}"])
          i += 1

      # Validate folders exist
      for folder in folders:
          if not os.path.exists(folder): # [EXISTENCE CHECK] Checks if the resolved paths exist, but allows traversal
              return {"error": f"Folder does not exist: {folder}"}

      # Get HTML files from all folders
      files_by_folder = []
      for folder in folders:
          files = {
              f: os.path.join(folder, f) # [PATH JOIN] Path is joined using user input
              for f in os.listdir(folder) # [LIST DIRECTORY] Lists files in user provided folder
              if f.endswith(".html")
          }
          files_by_folder.append(files)
      # ... (rest of the code) ...
  ```
  The code directly uses the user-provided `folder` parameters in `os.listdir()` and `os.path.join()` without sufficient validation. The `os.path.exists()` check only verifies if the final path exists, not if the path is within the intended directory, making it vulnerable to path traversal attacks.

- Security Test Case:
  1. Deploy a publicly accessible instance of the `screenshot-to-code` application.
  2. As an attacker, access the `/evals` endpoint by sending a GET request with a malicious `folder` parameter designed to traverse directories. For example:
     ```
     GET /evals?folder=../../../../etc/
     ```
  3. Observe the response from the server. If the server returns a list of files from the `/etc/` directory (or attempts to, potentially encountering permission errors depending on the server setup), it indicates a successful path traversal vulnerability. Check the server logs for file access attempts.
  4. To further confirm the vulnerability and attempt to read a specific sensitive file, try accessing `/evals` with a path like:
     ```
     GET /evals?folder=../../../../etc/passwd
     ```
     or for pairwise-evals:
     ```
     GET /pairwise-evals?folder1=../../../../etc/passwd&folder2=../../../../etc/passwd
     ```
     or for best-of-n-evals:
     ```
     GET /best-of-n-evals?folder1=../../../../etc/passwd
     ```
  5. Analyze the response. If the server returns content that resembles the `/etc/passwd` file (or an error indicating file access was attempted), it confirms the path traversal vulnerability. Note that you might not be able to retrieve the full content due to file format expectations in the application logic, but observing any response or server behavior change indicating file access outside expected directories validates the vulnerability. You can test with known `.html` files outside the intended directory as well if simply listing `/etc/` is not conclusive enough due to application logic expecting specific file types. For instance, if there is an `.html` file in the root directory, try `GET /evals?folder=../../../../`.
