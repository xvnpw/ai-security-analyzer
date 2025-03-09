## Combined Vulnerability List

This document consolidates identified vulnerabilities from multiple lists into a unified view, removing duplicates and providing comprehensive details for each.

### 1. Path Traversal in Evaluation Endpoints

- **Vulnerability Name:** Path Traversal in Evaluation Endpoints
  - **Description:**
    The application's `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints are susceptible to path traversal vulnerabilities. These endpoints allow users to specify folder paths through query parameters (`folder`, `folder1`, `folder2`, etc.) to retrieve evaluation files. However, the application fails to adequately validate and sanitize these user-supplied folder paths. Consequently, an attacker can craft malicious paths containing traversal sequences like `../` to access files and directories outside the intended evaluation directories on the server's file system.

    **Step-by-step trigger:**
    1. An attacker targets the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
    2. The attacker constructs a malicious URL request to one of these endpoints, embedding path traversal sequences in the folder parameter. For example, a request to `/evals` might look like `/evals?folder=../../../../etc/passwd`.
    3. The backend application receives this request and, without proper validation, uses the provided `folder` parameter directly in functions like `os.listdir` and `os.path.join`.
    4. Due to the path traversal sequences, the application attempts to list and read files from locations outside the intended directory, such as `/etc/passwd` or other system files.
    5. If successful, the application may expose the content of these accessed files in the response, or leak information about the file system structure through error messages or altered behavior.

  - **Impact:**
    High: Successful exploitation allows an attacker to read arbitrary files from the server's filesystem. This information disclosure can expose sensitive data, including:
    - Application source code
    - Configuration files containing API keys, database credentials, or other secrets
    - System files, revealing operating system and software details
    - User data or other confidential information

    This vulnerability is ranked high due to the severity of information disclosure and its potential to serve as a stepping stone for further attacks.

  - **Vulnerability Rank:** high
  - **Currently implemented mitigations:**
    - The application includes a check to verify if the provided `folder_path` exists using `os.path.exists()`. However, this mitigation is insufficient as it only confirms the path's existence without validating its legitimacy within the intended directory structure, failing to prevent path traversal.
  - **Missing mitigations:**
    - **Input validation and sanitization:** Implement robust validation for the `folder`, `folder1`, `folder2`, etc., parameters in the affected endpoints.
        - Validate that provided paths are within designated evaluation directories.
        - Sanitize input paths to remove or neutralize path traversal sequences like `../`.
        - Consider using absolute paths and verifying that the resolved path remains within the allowed base directory.
    - **Path Canonicalization and Validation:** Implement path canonicalization to resolve symbolic links and relative paths, then validate the canonical path to ensure it stays within the designated base directory (e.g., `EVALS_DIR`).
    - **Whitelist of Allowed Directories:** Consider using a whitelist of pre-approved directories or strictly defining the acceptable input format for folder paths to limit access to only authorized locations.
    - **Principle of least privilege:** Operate the application with minimal necessary file system permissions to limit the scope of a path traversal attack even if input validation is bypassed.
  - **Preconditions:**
    - The application is deployed and publicly accessible.
    - The `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints are exposed without sufficient access control, or are accessible to the attacker.
  - **Source code analysis:**
    - File: `backend/routes/evals.py`
    - Functions: `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`
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
                  f: os.path.join(folder, f) # Vulnerable: using user-provided 'folder' directly in path join
                  for f in os.listdir(folder) # Vulnerable: using user-provided 'folder' directly in listdir
                  if f.endswith(".html")
              }
              # ... rest of the code ...
      ```
    - **Explanation:** The vulnerability arises because the `folder` parameter, directly controlled by the user, is used without proper validation in `os.listdir(folder)` and `os.path.join(folder, f)`. The `folder_path.exists()` check is inadequate for preventing path traversal. Similar vulnerable code patterns are present in `get_pairwise_evals` and `get_best_of_n_evals`.
  - **Security test case:**
    1. Deploy the application to a test environment accessible to the attacker.
    2. Create a test file, e.g., `test.html` with content `<h1>Test File</h1>`, in the `/tmp` directory of the server (assuming a Linux-like environment and backend process read access to `/tmp`).
    3. Construct a GET request to the `/evals` endpoint with a path traversal payload in the `folder` parameter to target the `/tmp` directory: `GET /evals?folder=../../tmp`.
    4. Send the request to the application and analyze the JSON response.
    5. **Expected Outcome:** If vulnerable, the response will include an `evals` array containing an object with `outputs` that includes the content of `/tmp/test.html` (i.e., `<h1>Test File</h1>`), likely encoded within a data URL. This confirms successful listing and reading of files from `/tmp` via path traversal.

### 2. Server-Side Request Forgery (SSRF) via `OPENAI_BASE_URL`

- **Vulnerability Name:** Server-Side Request Forgery (SSRF) via `OPENAI_BASE_URL`
  - **Description:**
    The application permits users to configure a custom base URL for OpenAI API requests through the `OPENAI_BASE_URL` environment variable. This URL is subsequently used by the backend to make requests to the OpenAI API. Insufficient validation and sanitization of this user-provided URL enables an attacker to manipulate it to point to an internal or external malicious server. This leads to Server-Side Request Forgery (SSRF), where the application backend initiates requests to unintended destinations on behalf of the attacker.

    **Steps to trigger vulnerability:**
    1. An attacker sets up a malicious server to log requests or perform other malicious actions.
    2. The attacker identifies a publicly accessible instance of the application running in a **non-production environment**.
    3. The attacker attempts to configure the application to use their malicious server by manipulating the `OPENAI_BASE_URL`. This may be possible through environment variable manipulation in vulnerable environments or via a misconfigured configuration interface.
    4. The attacker triggers a function in the application that makes an OpenAI API request (e.g., code generation from a screenshot).
    5. Due to the manipulated `OPENAI_BASE_URL`, the backend sends the request to the attacker's malicious server instead of the legitimate OpenAI API endpoint.
    6. The attacker's server logs the request, potentially capturing sensitive information intended for OpenAI, or performs other actions based on the manipulated request.

  - **Impact:**
    High: Successful SSRF exploitation can lead to:
    - **Information Disclosure:** Access to internal resources or services not meant for public access by redirecting requests to internal IPs or hostnames.
    - **Data Exfiltration:** Potential capture of sensitive data sent in OpenAI API requests by redirecting requests to an attacker's server.
    - **Internal Port Scanning:** Using the application as a proxy to scan internal networks for open ports and services.
    - **Indirect Denial of Service:** Potentially causing denial of service for external services or the application itself by making numerous requests to arbitrary external servers.

  - **Vulnerability Rank:** High
  - **Currently implemented mitigations:**
    - In `backend\generate_code.py`, the application disables user-specified `OPENAI_BASE_URL` in production environments by checking the `IS_PROD` flag. This prevents SSRF in production deployments where `IS_PROD` is `True`.
  - **Missing mitigations:**
    - **Input Validation and Sanitization:** Even in non-production, validate `OPENAI_BASE_URL` to ensure it's a valid URL and points to a trusted OpenAI API endpoint. Implement a whitelist of allowed domains (e.g., `api.openai.com`) or strict URL parsing and validation.
    - **Principle of Least Privilege:** Run the application with minimal necessary privileges to limit SSRF impact.
    - **Network Segmentation:** Deploy the backend server in a segmented network, even in non-production, to limit SSRF impact on internal resources.
    - **Regular Security Audits:** Conduct regular audits and penetration testing to identify and address SSRF and other security vulnerabilities, especially in non-production configurations.
  - **Preconditions:**
    - Application deployed in a **non-production environment** where `IS_PROD` is `False` and `OPENAI_BASE_URL` is manipulable.
    - Publicly accessible instance of the application.
    - Application configured to use OpenAI API, and user can trigger code generation.
  - **Source code analysis:**
    - File: `backend\config.py`
      ```python
      OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", None)
      ```
      - `OPENAI_BASE_URL` is read directly from the environment without validation.
    - File: `backend\llm.py`
      ```python
      async def stream_openai_response(
          messages: List[ChatCompletionMessageParam],
          api_key: str,
          base_url: str | None, # base_url is passed here
          callback: Callable[[str], Awaitable[None]],
          model: Llm,
      ) -> Completion:
          start_time = time.time()
          client = AsyncOpenAI(api_key=api_key, base_url=base_url) # base_url is used to initialize AsyncOpenAI client
      ```
      - `base_url` is used to initialize `AsyncOpenAI` client without validation.
    - File: `backend\generate_code.py`
      ```python
      openai_base_url: str | None = None
      # Disable user-specified OpenAI Base URL in prod
      if not IS_PROD:
          openai_base_url = get_from_settings_dialog_or_env(
              params, "openAiBaseURL", OPENAI_BASE_URL
          )
      if not openai_base_url:
          print("Using official OpenAI URL")
      ```
      - In non-production (`IS_PROD` is false), `openai_base_url` can be user-specified and used for OpenAI client initialization. Production defaults to the official OpenAI URL, mitigating SSRF in production.

    ```mermaid
    graph LR
        A[config.py: Read OPENAI_BASE_URL from env] --> B{IS_PROD?};
        B -- Yes (Prod) --> C[generate_code.py: Use official OpenAI URL];
        B -- No (Non-Prod) --> D[generate_code.py: Allow user-specified OPENAI_BASE_URL];
        D --> E(llm.py: stream_openai_response);
        E --> F[AsyncOpenAI Client Initialization with base_url];
        F --> G[External Request to base_url];
        G --> H{Attacker Malicious Server?};
        H -- Yes --> I[SSRF Vulnerability (Non-Prod)];
        H -- No --> J[Legitimate OpenAI API];
        C --> J;
    ```

  - **Security test case:**
    1. **Prerequisites:**
        - Set up a malicious HTTP server (e.g., using `netcat` or Python's `http.server`) on a public IP and port (e.g., `http://[your_public_ip]:8080`).
        - Obtain the public IP of your malicious server.
        - Access a publicly accessible instance of the application in a **non-production environment** (`IS_PROD` is `False`).
    2. **Steps:**
        - Access the application in a browser and open developer tools.
        - Navigate to settings and find the "OpenAI Base URL" configuration (if UI configurable). If not, set `OPENAI_BASE_URL=http://[your_public_ip]:8080` in the backend's `.env` file and ensure `IS_PROD=False`.
        - Start listening for HTTP requests on your malicious server (e.g., `nc -lvp 8080`).
        - In the application, upload a screenshot and initiate code generation.
        - Observe HTTP requests received by your malicious server.
    3. **Expected result:**
        - Your malicious server will receive an HTTP request from the application backend, confirming SSRF in non-production. Logs will show the connection from the application backend to your server.
    4. **Cleanup:**
        - Reset `OPENAI_BASE_URL` to its original or safe value.
        - Stop the malicious HTTP server.
        - Ensure `IS_PROD=True` in `.env` for production deployments.

### 3. API Key Exposure via Misconfigured Debug Mode

- **Vulnerability Name:** API Key Exposure via Misconfigured Debug Mode
  - **Description:**
    If `IS_DEBUG_ENABLED` is set to `True` in production, the application writes debug artifacts, including prompts sent to LLMs, to a publicly accessible directory if `DEBUG_DIR` is misconfigured or unsecured. These prompts could contain sensitive information, potentially including API keys if inadvertently included in prompt construction or debug logging. Although current code doesn't explicitly log API keys in prompts, future changes could lead to accidental inclusion.

  - **Impact:**
    High: Exposure of API keys can lead to unauthorized use of LLM services, incurring financial costs and potential misuse by malicious actors. Attackers could perform actions beyond intended application use, such as training models or accessing other API account data.

  - **Vulnerability Rank:** High
  - **Currently implemented mitigations:**
    - API keys are read from environment variables, avoiding hardcoding secrets.
    - `IS_DEBUG_ENABLED` is intended for development environments only.
  - **Missing mitigations:**
    - **Secure Default for `DEBUG_DIR`:** Default `DEBUG_DIR` is an empty string, potentially resolving to a publicly accessible location in the application's working directory. Enforce a more secure default outside the web server's document root.
    - **Strict Configuration Validation:** Validate that `IS_DEBUG_ENABLED` is `False` in production and log a warning or prevent startup if `True` in production.
    - **API Key Sanitization in Debug Logs:** Implement redaction or sanitization of API keys and sensitive information from debug logs before writing to files.
    - **Access Control for Debug Directory:** Secure `DEBUG_DIR` with access controls to prevent unauthorized access, even if not intended to be public.
  - **Preconditions:**
    - `IS_DEBUG_ENABLED` is `True` in a production deployment.
    - `DEBUG_DIR` is misconfigured, publicly accessible, or defaults to a location within the web server's document root.
    - Web server serves static files from `DEBUG_DIR`.
    - Prompts or debug logging inadvertently include API keys or secrets.
  - **Source code analysis:**
    - **`backend\config.py`:**
      - `IS_DEBUG_ENABLED` from `MOCK` env var (converted to boolean).
      - `DEBUG_DIR` from `DEBUG_DIR` env var.
    - **`backend\debug\DebugFileWriter.py`:**
      - `DebugFileWriter` initialized only if `IS_DEBUG_ENABLED` is `True`.
      - `self.debug_artifacts_path` uses `DEBUG_DIR` and UUID. Empty `DEBUG_DIR` defaults to backend's working directory.
      - `write_to_file` writes to files in `self.debug_artifacts_path`.
    - **`backend\llm.py` & other modules:**
      - `DebugFileWriter` used to log debug info (prompts, generated code) to `DEBUG_DIR` if `IS_DEBUG_ENABLED` is `True`.
    - **`docker-compose.yml` & Dockerfiles:**
      - Docker setup doesn't prevent `MOCK=true` or `IS_DEBUG_ENABLED=true` in production. `.env` with `MOCK=true` in production enables debugging.
  - **Security test case:**
    1. **Setup:** Deploy application with Docker Compose in a publicly accessible environment.
    2. **Modify `.env` in backend:** Set `MOCK=true` in backend's `.env` (sets `IS_DEBUG_ENABLED=True`). Ensure `DEBUG_DIR` is publicly accessible or defaults to working directory.
    3. **Trigger Code Generation:** Use frontend to upload a screenshot and trigger code generation. Debug artifacts will be written to `DEBUG_DIR`.
    4. **Access Debug Directory:** Attempt to access `DEBUG_DIR` via browser. If web server misconfigured, you should be able to list and download debug artifacts.
    5. **Inspect Debug Artifacts:** Download and check debug artifact files (e.g., `full_stream.txt`, `pass_1.html`) for sensitive information like API keys or sensitive prompt data.
    6. **Expected Result:** If vulnerable, debug artifacts are accessible, and potentially contain sensitive information. If secure, debug directory should not be accessible, or sensitive data should not be publicly exposed even with debug mode enabled.

This vulnerability highlights the risk of enabling debug mode in production and misconfiguring the debug output directory, potentially leading to information disclosure. While current code may not directly expose API keys, it creates a pathway for future exposure and information leakage through debug logs.
