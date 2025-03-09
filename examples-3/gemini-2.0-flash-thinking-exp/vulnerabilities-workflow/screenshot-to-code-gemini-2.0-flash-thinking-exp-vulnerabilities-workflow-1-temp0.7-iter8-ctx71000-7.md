### Vulnerability List:

- Vulnerability Name: Permissive Cross-Origin Resource Sharing (CORS) Policy

- Description:
    1. The backend application is configured with a permissive CORS policy that allows requests from any origin (`allow_origins=["*"]`).
    2. This configuration is located in `backend\main.py` within the `CORSMiddleware` setup.
    3. An attacker can host a malicious website on any domain.
    4. This malicious website can then make requests to the backend API of the `screenshot-to-code` application.
    5. Due to the permissive CORS policy, the browser will allow these cross-origin requests to proceed without the usual same-origin policy restrictions.
    6. If the backend API relies on client-side origin checks for security or assumes requests are only coming from the frontend application's domain, these assumptions can be bypassed.
    7. This could lead to various attacks depending on the backend API's functionality, such as unauthorized access to features or data manipulation if proper backend security measures are not in place or are insufficient.

- Impact:
    - High. A permissive CORS policy weakens the application's security posture by allowing unauthorized cross-origin requests. The impact depends on the specific backend API endpoints and the security measures implemented there. It could potentially lead to:
        - **Data breaches:** If the API exposes sensitive data without proper authentication or authorization checks that rely on origin.
        - **Unauthorized actions:** If the API allows actions to be performed without proper authorization checks that rely on origin, attackers could potentially perform actions on behalf of legitimate users.
        - **CSRF-like attacks:** Although not strictly CSRF, a permissive CORS policy can make it easier for attackers to craft malicious requests from different origins that might bypass some client-side security assumptions.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The project explicitly sets `allow_origins=["*"]` in `backend\main.py`.
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```

- Missing mitigations:
    - **Restrict `allow_origins` to specific, trusted origins:** Instead of `"*"` (wildcard), the `allow_origins` should be set to a list of specific origins that are authorized to access the backend API. This typically includes the domain(s) where the frontend application is hosted. For development purposes, it might include `http://localhost:5173` or similar if the frontend is served locally.
    - **Implement robust backend authentication and authorization:** While restricting CORS is crucial, the backend API should not solely rely on CORS for security. It must implement its own authentication and authorization mechanisms to verify the identity and permissions of the requester, regardless of the origin of the request. This is essential to prevent unauthorized access even if CORS is misconfigured or bypassed.

- Preconditions:
    - The `screenshot-to-code` application backend is deployed in a publicly accessible environment.
    - The backend API relies on origin-based security assumptions or lacks sufficient backend authentication and authorization mechanisms.

- Source code analysis:
    1. File: `backend\main.py`
    2. The `FastAPI` application is initialized.
    3. `CORSMiddleware` is added to the application's middleware stack:
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    4. `allow_origins=["*"]` configuration explicitly allows all origins.
    5. This configuration makes the backend API accessible from any website, bypassing the same-origin policy for cross-origin requests.

- Security test case:
    1. Deploy the `screenshot-to-code` application backend to a publicly accessible instance.
    2. Create a simple HTML file with JavaScript code hosted on a different domain than the `screenshot-to-code` backend. For example, host it on `attacker.com`.
    3. In the HTML file, use JavaScript to make an AJAX request (e.g., using `fetch` or `XMLHttpRequest`) to a backend API endpoint of the `screenshot-to-code` application (e.g., `/generate`).
    4. Include sensitive operations in the API request if possible, or attempt to access data that should be protected.
    5. Observe that the request is successfully sent and processed by the backend, and the response is received by the malicious website, even though the origin (`attacker.com`) is different from the backend's origin.
    6. If backend API perform sensitive actions or leak data in response without proper authentication and authorization, this confirms the vulnerability.

- Vulnerability Name: Path Traversal in Evals API

- Description:
    1. The backend application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` in `backend\routes\evals.py` that take user-controlled folder paths as input via query parameters (`folder`, `folder1`, `folder2`, etc.).
    2. These folder paths are used directly with functions like `os.listdir`, `os.path.join`, and `os.path.exists` to access files on the server's file system.
    3. An attacker can craft malicious requests to these endpoints by providing manipulated folder paths containing path traversal sequences like `../` or `..\\`.
    4. By exploiting path traversal, the attacker can potentially access files and directories outside the intended evaluation folders.
    5. This could allow the attacker to read sensitive files, application source code, configuration files, or other system files, depending on the server's file system permissions and the application's execution context.

- Impact:
    - High. Successful path traversal can lead to:
        - **Confidentiality breach:** Attackers could read sensitive files on the server, such as configuration files, source code, or data files.
        - **Integrity breach:** In some scenarios, if combined with other vulnerabilities or misconfigurations, attackers might be able to write or modify files, although less likely in this read-focused file access pattern.
        - **Information Disclosure:** Exposure of internal file structure and potentially sensitive data contained within accessible files.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The code directly uses user-provided folder paths without any sanitization or validation against path traversal attacks in `backend\routes\evals.py`.
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder)
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f)
                for f in os.listdir(folder)
                if f.endswith(".html")
            }
            ...
    ```

- Missing mitigations:
    - **Input validation and sanitization:** Validate the folder paths provided by users. Implement checks to ensure that the paths are within the expected base directory for evaluations and do not contain path traversal sequences (`../`, `..\\`).
    - **Path canonicalization:** Convert user-provided paths to their canonical form and verify that they still fall within the allowed base directory. This can help prevent bypasses using symbolic links or other path manipulation techniques.
    - **Principle of least privilege:** Ensure that the application runs with minimal file system permissions necessary. Avoid running the backend process with root or administrator privileges, which would limit the impact of a path traversal vulnerability.

- Preconditions:
    - The `screenshot-to-code` application backend is deployed in a publicly accessible environment.
    - The evaluation files are stored in a directory accessible to the backend application.
    - The attacker can access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.

- Source code analysis:
    1. File: `backend\routes\evals.py`
    2. Routes `/evals`, `/pairwise-evals`, and `/best-of-n-evals` are defined.
    3. In the `get_evals` function, the `folder` query parameter is directly used to construct file paths:
    ```python
    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    files = {
        f: os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".html")
    }
    ```
    4. The code uses `os.listdir(folder)`, `os.path.join(folder, f)`, and `os.path.exists(folder_path)` directly with the user-provided `folder` parameter without any validation or sanitization to prevent path traversal.
    5. Similar pattern is observed in `get_pairwise_evals` and `get_best_of_n-evals` functions for `folder1`, `folder2`, etc. parameters.

- Security test case:
    1. Deploy the `screenshot-to-code` application backend to a publicly accessible instance.
    2. Identify the base directory where evaluation files are expected to be stored on the server (e.g., assume it's `/app/evals`).
    3. Attempt to access a file outside of this base directory using path traversal in the `folder` parameter of the `/evals` endpoint. For example, try to access `/etc/passwd` by crafting a URL like: `https://<your-backend-url>/evals?folder=../../../../../etc/passwd`.
    4. Observe the server's response. If the server returns the content of `/etc/passwd` or an error indicating that the file was accessed (e.g., file not found error within `/etc/passwd` directory), it confirms the path traversal vulnerability. If the server returns an error like "Folder not found" for `/etc/passwd`, it might still be vulnerable if it's checking for directory existence but not sanitizing paths within existing directories. Further testing might be needed to confirm.
    5. To further validate, try to access other sensitive files or directories that the backend user might have access to, adjusting the path traversal payload accordingly.

- Vulnerability Name: Server-Side Request Forgery (SSRF) in Screenshot API

- Description:
    1. The backend application exposes the `/api/screenshot` endpoint in `backend\routes\screenshot.py` that takes a user-controlled URL (`url` parameter in `ScreenshotRequest`) as input.
    2. This URL is passed to the `capture_screenshot` function, which uses the `httpx` library to make an HTTP GET request to an external service (`api.screenshotone.com/take`) to capture a screenshot of the provided URL.
    3. If the `url` parameter is not properly validated or sanitized, an attacker can supply malicious URLs, including internal network addresses or URLs to sensitive services not intended for public access.
    4. The backend server will then make a request to the attacker-specified URL on behalf of the attacker, potentially exposing internal resources or leaking sensitive information.
    5. This can lead to various SSRF attack scenarios, such as port scanning of internal networks, accessing internal services, or reading sensitive data from internal endpoints if they are not properly protected.

- Impact:
    - High. Successful SSRF can lead to:
        - **Access to internal resources:** Attackers can access internal services and resources that are not publicly accessible, such as internal APIs, databases, or administration panels.
        - **Port scanning:** Attackers can use the vulnerable endpoint to scan internal networks and identify open ports and running services.
        - **Information disclosure:** Attackers might be able to retrieve sensitive data from internal endpoints if they are not properly secured.
        - **Denial of Service (DoS):** In some cases, attackers might be able to cause a DoS by making a large number of requests to internal or external services, although this is explicitly excluded from this list per instructions.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The code directly uses the user-provided URL in the `httpx` request without any validation or sanitization in `backend\routes\screenshot.py`.
    ```python
    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"
        ...
        params = {
            "access_key": api_key,
            "url": target_url,
            ...
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(api_base_url, params=params)
            ...
    ```

- Missing mitigations:
    - **Input validation and sanitization:** Validate the `url` parameter to ensure it is a safe and expected URL. Implement checks to:
        - **URL scheme validation:** Allow only `http` and `https` schemes.
        - **Hostname validation:** Use a whitelist of allowed hostnames or a blacklist of disallowed hostnames (e.g., private IP ranges, localhost, meta-data IPs). If possible, resolve the hostname to an IP address and check if it's within an allowed range.
        - **URL format validation:** Check for unexpected characters or formats that might indicate malicious intent.
    - **Output validation:** Validate the response from the external service (`screenshotone.com`) to ensure it is expected and does not contain any unexpected redirects or content that could be part of an SSRF exploit.
    - **Principle of least privilege:** Ensure that the backend application has minimal network permissions necessary to perform its functions. Restrict outbound network access to only the necessary external services.

- Preconditions:
    - The `screenshot-to-code` application backend is deployed in a publicly accessible environment.
    - The attacker can access the `/api/screenshot` endpoint.

- Source code analysis:
    1. File: `backend\routes\screenshot.py`
    2. Route `/api/screenshot` is defined.
    3. The `app_screenshot` function extracts the `url` from the `ScreenshotRequest`.
    4. The `capture_screenshot` function is called with the user-provided `target_url`:
    ```python
    async def app_screenshot(request: ScreenshotRequest):
        # Extract the URL from the request body
        url = request.url
        api_key = request.apiKey

        # TODO: Add error handling
        image_bytes = await capture_screenshot(url, api_key=api_key)
        ...
    ```
    5. Inside `capture_screenshot`, `httpx.AsyncClient().get()` is used to make a request to `api.screenshotone.com/take` with the user-provided `target_url` in the `url` parameter, without any validation or sanitization.

- Security test case:
    1. Deploy the `screenshot-to-code` application backend to a publicly accessible instance.
    2. Obtain a valid API key for `screenshotone.com` or use a test API key if available for testing purposes.
    3. Craft a malicious request to the `/api/screenshot` endpoint, replacing the `url` parameter with an internal URL or a URL to a sensitive service. For example, if the backend is running on `localhost:8000`, try to access the home page itself by setting `url` to `http://localhost:8000`.
    4. Send the POST request to `/api/screenshot` with the malicious URL and a valid API key in the request body:
    ```json
    {
        "url": "http://localhost:8000",
        "apiKey": "<your-screenshotone-api-key>"
    }
    ```
    5. Observe the server's response or network traffic. If the server successfully makes a request to `http://localhost:8000` and attempts to take a screenshot of it (which might fail or return an error from screenshotone.com, but the internal request is made), it confirms the SSRF vulnerability.
    6. To further validate, try to access other internal services or resources that might be running in the same network as the backend server, adjusting the `url` parameter accordingly. For example, try to access common ports like `http://localhost:22` (SSH) or `http://localhost:6379` (Redis) to see if you can get a response or connection timeout, indicating that the backend is attempting to connect to these internal ports.
