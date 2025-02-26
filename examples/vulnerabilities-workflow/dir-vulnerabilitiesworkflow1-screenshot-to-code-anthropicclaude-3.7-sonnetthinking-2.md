# Vulnerabilities

After analyzing the screenshot-to-code codebase, I've identified two high-severity security vulnerabilities:

## 1. Path Traversal Vulnerability

- **Vulnerability Name**: Path Traversal in Evaluation Routes
- **Description**: In `routes/evals.py`, the application directly accepts folder paths from user input without proper validation or path sanitization. This allows an attacker to access arbitrary files on the filesystem by using path traversal sequences (e.g., `../../../etc/passwd`). The vulnerability exists because the application only checks if the requested path exists rather than validating that it's within an authorized directory.
- **Impact**: An attacker could read sensitive files from anywhere on the server's filesystem where the application has permissions, potentially exposing configuration files, credentials, or other sensitive information.
- **Vulnerability Rank**: High
- **Currently Implemented Mitigations**: None. The code only checks if the paths exist but doesn't restrict them to a safe directory.
- **Missing Mitigations**: The application should validate that all user-supplied paths are within an allowed directory using path canonicalization and strict comparison against allowlisted directories.
- **Preconditions**: The attacker needs access to the application's API endpoints and needs to provide a valid path to an existing file on the server.
- **Source Code Analysis**:

  In `routes/evals.py`, there are multiple instances where user-provided folder paths are used directly:

  ```python
  @router.get("/evals", response_model=list[Eval])
  async def get_evals(folder: str):
      if not folder:
          raise HTTPException(status_code=400, detail="Folder path is required")

      folder_path = Path(folder)
      if not folder_path.exists():
          raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
  ```

  Similar code patterns appear in the `get_pairwise_evals` and `get_best_of_n_evals` functions, where user-provided folder paths are directly used to access files:

  ```python
  if not os.path.exists(folder1) or not os.path.exists(folder2):
      return {"error": "One or both folders do not exist"}
  ```

  Once a folder path is "validated" (only checking existence), the application opens and reads files from that location:

  ```python
  with open(files1[f1], "r") as f:
      output1 = f.read()
  ```

  This allows an attacker to navigate to any directory on the filesystem and read files, as long as the application has permission to access them.

- **Security Test Case**:
  1. Identify any endpoint that accepts a folder parameter, such as `/evals?folder=PATH`
  2. Send a request with a path traversal sequence to access sensitive files:
     ```
     GET /evals?folder=../../../etc/passwd
     ```
  3. Attempt to access other sensitive files in the system using similar techniques:
     ```
     GET /evals?folder=../../../.env
     GET /evals?folder=../../../config/secrets.json
     ```
  4. If the server returns the content of these files, the vulnerability is confirmed.

## 2. Server-Side Request Forgery (SSRF) Vulnerability

- **Vulnerability Name**: SSRF in Screenshot API
- **Description**: The screenshot functionality in `routes/screenshot.py` allows an attacker to specify any URL to be captured by the external screenshot service. This creates a Server-Side Request Forgery vulnerability where the application can be used to access internal network resources or services that might not be publicly accessible.
- **Impact**: An attacker could use this vulnerability to:
  - Scan internal networks using the screenshot service as a proxy
  - Access internal services that are otherwise restricted from public access
  - Potentially extract information from responses via screenshots
  - Possibly exploit vulnerabilities in internal services
- **Vulnerability Rank**: High
- **Currently Implemented Mitigations**: None. The application passes the user-provided URL directly to the external screenshot service without validation.
- **Missing Mitigations**: The application should implement URL validation to ensure only legitimate, public websites can be screenshotted. This should include:
  - Validating URL schemes (only allowing http/https)
  - Blocking requests to private IP ranges and localhost
  - Using an allowlist approach for permitted domains if possible
- **Preconditions**: The attacker needs access to the `/api/screenshot` endpoint and a valid API key for the screenshot service.
- **Source Code Analysis**:

  In `routes/screenshot.py`, the `capture_screenshot` function accepts a `target_url` parameter directly from user input:

  ```python
  async def capture_screenshot(
      target_url: str, api_key: str, device: str = "desktop"
  ) -> bytes:
      api_base_url = "https://api.screenshotone.com/take"

      params = {
          "access_key": api_key,
          "url": target_url,
          "full_page": "true",
          # ... other parameters ...
      }
  ```

  This URL is then sent to the screenshotone.com API without any validation. The API endpoint receives this URL from the client via the `ScreenshotRequest` model:

  ```python
  @router.post("/api/screenshot")
  async def app_screenshot(request: ScreenshotRequest):
      # Extract the URL from the request body
      url = request.url
      api_key = request.apiKey

      # TODO: Add error handling
      image_bytes = await capture_screenshot(url, api_key=api_key)
  ```

  Without proper validation, an attacker could provide URLs like:
  - `http://localhost:8080` (internal service)
  - `http://10.0.0.1/admin` (internal network address)
  - `http://169.254.169.254/latest/meta-data/` (AWS metadata service)

- **Security Test Case**:
  1. Send a POST request to `/api/screenshot` with a payload targeting internal services:
     ```json
     {
       "url": "http://localhost:8080",
       "apiKey": "valid-api-key"
     }
     ```
  2. Try various internal IP addresses and services:
     ```json
     {
       "url": "http://127.0.0.1:22",
       "apiKey": "valid-api-key"
     }
     ```
  3. Attempt to access cloud metadata services:
     ```json
     {
       "url": "http://169.254.169.254/latest/meta-data/",
       "apiKey": "valid-api-key"
     }
     ```
  4. If any of these requests return screenshots of internal services or metadata, the vulnerability is confirmed.
