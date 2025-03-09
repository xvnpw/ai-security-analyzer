### Vulnerability List

- Vulnerability Name: API Key Exposure via Insecure Configuration
- Description: The application uses environment variables to store sensitive API keys for OpenAI, Anthropic, and Gemini. If the application is deployed without proper environment variable configuration and the `.env` file is inadvertently exposed (e.g., through misconfigured Docker setup or accessible web server configuration), or if logs are not secured and environment variables are logged, these API keys could be compromised. An attacker could then use these keys to access the paid AI services, potentially incurring costs and accessing the AI models using the application's credentials.
- Impact:
    - Unauthorized access to AI services (OpenAI, Anthropic, Gemini) using the application's API keys.
    - Financial cost incurred by the application owner due to unauthorized usage of AI services.
    - Potential data leakage if the attacker can use the compromised keys to access more sensitive data or functionalities within the AI service provider's platform (depending on the API key's permissions).
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The application is designed to load API keys from environment variables, which is a standard practice for separating configuration from code.
    - The README.md provides instructions on how to set up API keys using `.env` files for local development, and mentions that keys are stored in the browser settings dialog locally (client-side).
- Missing Mitigations:
    - **Secure Deployment Documentation:** Lack of explicit documentation for secure deployment, especially regarding the handling of environment variables in production environments (e.g., using platform-specific secrets management, not including `.env` in Docker images, secure logging practices).
    - **Secret Scanning:** No automated secret scanning in the codebase or CI/CD pipeline to prevent accidental commits of API keys or configuration files containing keys.
    - **Logging Security:** No explicit mention of secure logging practices to prevent accidental logging of environment variables containing API keys.
- Preconditions:
    - The application is deployed in a publicly accessible environment.
    - The environment variables containing API keys are not securely configured. This could happen if:
        - The `.env` file (containing API keys) is mistakenly included in the deployed application (e.g., in a Docker image or accessible directory).
        - The environment variables are logged by the application in an insecure manner (e.g., in publicly accessible logs).
        - The hosting environment itself is misconfigured, allowing access to environment variables from outside the intended scope.
- Source Code Analysis:
    - **`backend/config.py`**:
        ```python
        import os

        OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)
        ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", None)
        GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", None)
        ```
        This code snippet shows that the application retrieves API keys directly from environment variables using `os.environ.get()`. If these environment variables are exposed, the keys are compromised.
    - **`README.md`**:
        ```bash
        echo "OPENAI_API_KEY=sk-your-key" > .env
        echo "ANTHROPIC_API_KEY=your-key" > .env
        ```
        This instruction in the README encourages developers to use `.env` files for storing API keys during development, which can be insecure if these files are inadvertently deployed to production or shared.
    - **`docker-compose.yml`**:
        ```yaml
        env_file:
          - .env
        ```
        The `docker-compose.yml` configuration uses `.env` file, which might lead to including `.env` file in docker image if not handled carefully during build process for production.

- Security Test Case:
    1. **Setup Insecure Deployment (Simulated):**
        - For testing purposes, simulate an insecure deployment where the `.env` file is accessible from the web server's document root or is inadvertently included in the Docker image.
        - Alternatively, configure the application to log all environment variables to a publicly accessible log file.
    2. **Access Configuration File or Logs:**
        - As an external attacker, attempt to access the `.env` file directly via a web browser if deployed insecurely (e.g., `http://<application-url>/.env`).
        - If logs are insecurely exposed, access the log files (e.g., `http://<application-url>/logs/app.log` if such a path exists and is incorrectly exposed).
    3. **Extract API Keys:**
        - If the `.env` file or logs are accessible, examine the content and extract the values of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `GEMINI_API_KEY`.
    4. **Verify API Key Validity (Optional):**
        - Use the extracted API keys to make a test API call to OpenAI, Anthropic, or Gemini services (e.g., using `curl` or a simple Python script) to verify their validity and access. For example, using OpenAI API:
          ```bash
          curl https://api.openai.com/v1/chat/completions \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer YOUR_EXTRACTED_OPENAI_API_KEY" \
          -d '{
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "Say this is a test!"}],
            "temperature": 0.7
          }'
          ```
    5. **Expected Result:**
        - If the test is successful, the attacker should be able to retrieve valid API keys, demonstrating the API Key Exposure vulnerability. A successful API call using the extracted key would further confirm the impact.

- Missing Mitigations:
    - Add documentation on secure deployment practices, emphasizing:
        - **Never include `.env` files in Docker images or deployed application artifacts.**
        - **Use platform-specific secrets management solutions** (e.g., AWS Secrets Manager, Google Secret Manager, Azure Key Vault, Kubernetes Secrets) to securely inject environment variables in production.
        - **Implement secure logging practices** that prevent logging of sensitive environment variables.
        - **Regularly rotate API keys** to limit the window of opportunity if keys are compromised.
    - Implement automated secret scanning in the CI/CD pipeline to detect accidental inclusion of secrets in the codebase.
    - Add security headers to prevent directory listing if the web server is misconfigured and accidentally exposes the `.env` file directory.

- Vulnerability Name: Path Traversal in Evals Endpoints
- Description: The application's `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints allow users to specify folder paths to read evaluation files. The application uses these paths directly with `os.listdir` and `os.path.join` without proper validation to ensure that the paths are within the intended evaluation directories. An attacker could potentially provide a manipulated folder path (e.g., using `../` sequences) to traverse the file system and access files and directories outside the intended scope.
- Impact:
    - **Information Disclosure**: An attacker could read arbitrary files on the server if the application's process has sufficient file system permissions. This could include configuration files, application code, or other sensitive data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Checks if the folder exists using `os.path.exists`.
- Missing Mitigations:
    - **Path Validation and Sanitization**: Implement validation to ensure that the provided folder path is within an allowed base directory (e.g., under `EVALS_DIR`). Use functions like `os.path.abspath` and `os.path.commonprefix` to normalize and check if the resolved path is still within the allowed base path.
    - **Input Sanitization**: Sanitize the input folder path to remove or neutralize any path traversal sequences like `../` or `./`.
- Preconditions:
    - The application is deployed and publicly accessible.
    - The attacker can access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
- Source Code Analysis:
    - **`backend/routes/evals.py`**:
        - **`get_evals(folder: str)`**: The `folder` parameter is directly used in `os.listdir(folder)` and `os.path.join(folder, f)`.
        ```python
        @router.get("/evals", response_model=list[Eval])
        async def get_evals(folder: str):
            # ...
            files = {
                f: os.path.join(folder, f)
                for f in os.listdir(folder)
                if f.endswith(".html")
            }
            # ...
        ```
        - **`get_pairwise_evals(folder1: str, folder2: str)`**: `folder1` and `folder2` are directly used in `os.listdir` and `os.path.join`.
        ```python
        @router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
        async def get_pairwise_evals(folder1: str, folder2: str):
            # ...
            files1 = {
                f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html")
            }
            files2 = {
                f: os.path.join(folder2, f) for f in os.listdir(folder2) if f.endswith(".html")
            }
            # ...
        ```
        - **`get_best_of_n_evals(request: Request)`**: Folder paths are extracted from query parameters (`folder1`, `folder2`, etc.) and directly used.
        ```python
        @router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
        async def get_best_of_n_evals(request: Request):
            # ...
            while f"folder{i}" in query_params:
                folders.append(query_params[f"folder{i}"])
                i += 1
            # ...
            files_by_folder = []
            for folder in folders:
                files = {
                    f: os.path.join(folder, f)
                    for f in os.listdir(folder)
                    if f.endswith(".html")
                }
                files_by_folder.append(files)
            # ...
        ```

- Security Test Case:
    1. **Identify Evals Endpoint:** Determine the URL for the `/evals` endpoint (or `/pairwise-evals`, `/best-of-n-evals`). Let's assume it's `/api/evals`.
    2. **Craft Malicious Payload:** Prepare a malicious folder path to attempt path traversal. For example, use `../` to go up one directory level from the expected base directory. Assume the application is running in a directory like `/app/backend` and the intended eval folders are under `/app/evals`. We want to access `/etc/passwd`. So, the payload could be `../../../../etc`.
    3. **Send Malicious Request:** Send a GET request to the `/evals` endpoint with the malicious folder path as a query parameter. For example:
       `GET /api/evals?folder=../../../../etc`
    4. **Analyze Response:** Examine the response from the server. Observe if the server attempts to access or list files from the provided path, potentially indicating successful path traversal even if direct file content is not immediately revealed due to file type filtering.
    5. **Expected Result:**
        - The server attempts to access the provided path, leading to an error or unexpected behavior, confirming path traversal vulnerability. Error messages indicating "Folder not found: /etc" or similar still confirm the vulnerability as the application tried to access the manipulated path.

- Missing Mitigations:
    - Implement path validation and sanitization in the `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` functions in `evals.py`. Ensure that the input `folder`, `folder1`, `folder2` and dynamically created folder paths are validated to be within the expected directories under `EVALS_DIR`.

- Vulnerability Name: Server-Side Request Forgery (SSRF) in Screenshot Endpoint
- Description: The `/api/screenshot` endpoint in `screenshot.py` allows users to provide a URL as input to capture a screenshot using the `screenshotone.com` service. The application directly uses the user-provided URL in a server-side HTTP request to `api.screenshotone.com/take` without sufficient validation or sanitization. An attacker could exploit this to perform Server-Side Request Forgery (SSRF) attacks. By providing a malicious URL, the attacker could potentially make the server:
    - Access internal network resources (e.g., internal servers, services).
    - Access localhost resources (e.g., application metadata endpoints, other services running on the same server).
    - Probe for open ports and services on internal networks.
    - In some cases, potentially read local files or interact with cloud metadata services, depending on the permissions of the server and the capabilities of the `screenshotone.com` service.
- Impact:
    - **Information Disclosure**: Access to internal resources, configuration files, or service metadata.
    - **Internal Network Scanning**: Ability to probe and map internal network infrastructure.
    - **Potential for further exploitation**: Depending on the internal services exposed, SSRF can be a stepping stone to other vulnerabilities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None
- Missing Mitigations:
    - **URL Validation and Sanitization**: Implement strict validation of the input URL in `screenshot.py` to ensure it only allows safe protocols (e.g., `http`, `https`) and potentially whitelisted domains. Blacklisting is generally less effective against SSRF.
    - **Prevent Access to Internal Networks**: Configure network firewalls or application-level restrictions to prevent the application from accessing internal network ranges (e.g., private IP ranges).
    - **Disable or Restrict URL Schemes**: Limit the allowed URL schemes to `http` and `https` and explicitly deny schemes like `file://`, `gopher://`, `ftp://`, etc., which are often used in SSRF attacks.
- Preconditions:
    - The application is deployed and publicly accessible.
    - The attacker can access the `/api/screenshot` endpoint.
- Source Code Analysis:
    - **`backend/routes/screenshot.py`**:
        - **`capture_screenshot(target_url: str, api_key: str, device: str = "desktop")`**: The `target_url` parameter, directly derived from user input `request.url`, is used to construct the URL for the request to `screenshotone.com`.
        ```python
        @router.post("/api/screenshot")
        async def app_screenshot(request: ScreenshotRequest):
            url = request.url # User-controlled URL
            api_key = request.apiKey
            image_bytes = await capture_screenshot(url, api_key=api_key) # vulnerable function call
            # ...
        ```
        ```python
        async def capture_screenshot(
            target_url: str, api_key: str, device: str = "desktop"
        ) -> bytes:
            api_base_url = "https://api.screenshotone.com/take"
            params = {
                "access_key": api_key,
                "url": target_url, # User-controlled URL is used here
                # ...
            }
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(api_base_url, params=params) # HTTP request with user-controlled URL
                # ...
        ```

- Security Test Case:
    1. **Identify Screenshot Endpoint:** Determine the URL for the `/api/screenshot` endpoint.
    2. **Craft SSRF Payload:** Prepare a malicious URL to target localhost, e.g., `http://127.0.0.1`.
    3. **Send SSRF Request:** Send a POST request to the `/api/screenshot` endpoint with the malicious URL in the request body. For example, using `curl`:
       ```bash
       curl -X POST -H "Content-Type: application/json" -d '{"url": "http://127.0.0.1", "apiKey": "YOUR_SCREENSHOTONE_API_KEY"}' http://<application-url>/api/screenshot
       ```
       Replace `YOUR_SCREENSHOTONE_API_KEY` with a valid API key for screenshotone.com. Replace `http://<application-url>` with the actual URL of the deployed application.
    4. **Analyze Response and Side Effects:** Examine the response from the server. Check if the request to `http://127.0.0.1` is successfully processed by `screenshotone.com`.
    5. **Expected Result:**
        - The server initiates a request to `http://127.0.0.1` via `screenshotone.com`, demonstrating the SSRF vulnerability. The exact response depends on `screenshotone.com`'s handling of localhost targets, but any indication that the request was processed for `127.0.0.1` confirms the vulnerability.

- Missing Mitigations:
    - Implement URL validation and sanitization in the `app_screenshot` function in `screenshot.py` to prevent SSRF attacks. Validate the `request.url` to ensure it's a safe URL before passing it to `capture_screenshot`.
