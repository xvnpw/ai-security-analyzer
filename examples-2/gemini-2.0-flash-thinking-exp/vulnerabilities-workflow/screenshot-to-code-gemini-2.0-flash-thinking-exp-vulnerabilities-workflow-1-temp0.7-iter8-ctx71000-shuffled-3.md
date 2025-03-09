- Vulnerability name: Server-Side Request Forgery (SSRF) in Screenshot Capture
- Description:
    1. An attacker sends a request to the `/api/screenshot` endpoint with a crafted URL in the `url` parameter.
    2. The backend application, in `backend\routes\screenshot.py`, uses the `capture_screenshot` function.
    3. The `capture_screenshot` function directly uses the attacker-provided URL to make an HTTP GET request to the `screenshotone.com` API.
    4. By providing a malicious URL (e.g., pointing to internal network resources or localhost), the attacker can induce the server to make requests to unintended destinations.
    5. This can lead to information disclosure if internal resources are accessed or allow the attacker to use the server as a proxy to interact with other systems.
- Impact:
    - Information Disclosure: An attacker could potentially access sensitive information from internal network resources or the application server itself.
    - Internal Network Scanning: The server can be used to scan internal ports and services, potentially revealing network topology and vulnerable services.
    - Further Exploitation: SSRF can be a stepping stone for more complex attacks if internal services are exposed.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code directly uses the user-provided URL without any validation or sanitization.
- Missing mitigations:
    - Input validation: Implement strict validation of the `target_url` to ensure it points to external, safe web resources and not to internal or restricted addresses.
    - URL Allowlisting: Define an allowlist of permitted domains or URL patterns that the screenshot service is allowed to access. Reject requests targeting URLs outside this allowlist.
    - Network Segmentation: Isolate the screenshot service and backend components from internal networks to limit the potential impact of SSRF.
- Preconditions:
    - The application must be deployed and accessible to external attackers.
    - The `/api/screenshot` endpoint must be exposed without authentication or with easily bypassable authentication.
    - An attacker needs to know or guess the existence of the `/api/screenshot` endpoint and its parameters.
- Source code analysis:
    ```python
    # File: ..\screenshot-to-code\backend\routes\screenshot.py
    import httpx

    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"

        params = {
            "access_key": api_key,
            "url": target_url, # User-controlled input is directly passed as 'url' parameter.
            "full_page": "true",
            "device_scale_factor": "1",
            "format": "png",
            "block_ads": "true",
            "block_cookie_banners": "true",
            "block_trackers": "true",
            "cache": "false",
            "viewport_width": "342",
            "viewport_height": "684",
        }

        if device == "desktop":
            params["viewport_width"] = "1280"
            params["viewport_height"] = "832"

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(api_base_url, params=params) # httpx.get makes a request to screenshotone.com, but the 'url' is from user input.
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")

    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        url = request.url # User-provided URL from request body
        api_key = request.apiKey

        image_bytes = await capture_screenshot(url, api_key=api_key) # capture_screenshot is called with user-provided URL.
        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    - The `app_screenshot` function in `backend\routes\screenshot.py` takes a `ScreenshotRequest` which includes a `url` parameter.
    - This `url` is directly passed to the `capture_screenshot` function without any validation.
    - The `capture_screenshot` function uses this `target_url` in a `httpx.get` request to the `screenshotone.com` API.
    - This flow allows an attacker to control the `target_url` and potentially perform SSRF attacks.

- Security test case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible server.
    2. Open a web browser and access the frontend of the deployed application.
    3. Open the browser's developer console (e.g., by pressing F12). Navigate to the "Network" tab.
    4. In the application's settings (gear icon), enter a dummy value for the "Screenshot API Key" (e.g., "test_api_key").
    5. Initiate a screenshot request within the application (e.g., by providing a URL and triggering the screenshot functionality).
    6. In the browser's developer console "Network" tab, locate the POST request to `/api/screenshot`.
    7. Right-click on the request and select "Edit and Resend".
    8. In the "Request Payload" or "Request Body" section, modify the `url` parameter to point to an internal resource of the server, such as `http://localhost:7001/api/home` or `http://127.0.0.1:7001/api/home`.
    9. Send the modified request.
    10. Examine the response in the "Response" tab of the developer console.
    11. If the response contains the HTML content of the backend's home route (e.g., "Your backend is running correctly..."), this confirms the SSRF vulnerability, as the server has fetched content from its internal endpoint as instructed by the attacker.

- Vulnerability name: Path Traversal in Evaluation File Access
- Description:
    1. An attacker crafts a malicious folder path containing path traversal sequences (e.g., `../`, `..\\`).
    2. The attacker sends a GET request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints, providing the crafted folder path as a parameter (`folder`, `folder1`, `folder2`, etc.).
    3. The backend application, in `backend\routes\evals.py`, uses the provided folder path to access files within the file system.
    4. Due to insufficient validation of the folder path, the attacker can bypass intended directory restrictions and access files outside of the designated evaluation directories.
    5. This can lead to the attacker reading sensitive files on the server, including application code, configuration files, or other data.
- Impact:
    - Information Disclosure: An attacker could read arbitrary files from the server's file system, potentially exposing sensitive data, credentials, or source code.
    - Server Compromise: In severe cases, if sensitive configuration files or executable scripts are exposed, this vulnerability could be a stepping stone to further compromise the server.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code directly uses the user-provided folder path without any sanitization or validation to prevent path traversal.
- Missing mitigations:
    - Input validation: Implement strict validation of the `folder` parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints. Sanitize the input paths to remove path traversal sequences and ensure that the paths are within the expected evaluation directories.
    - Path normalization: Normalize the input paths to resolve symbolic links and canonicalize the path, making it harder for attackers to use path traversal techniques.
    - Filesystem access control: Implement proper filesystem access controls to limit the application's ability to access sensitive files, even if a path traversal vulnerability exists.
- Preconditions:
    - The application must be deployed and accessible to external attackers.
    - The `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints must be exposed without authentication or with easily bypassable authentication.
    - An attacker needs to know or guess the existence of these endpoints and their parameters.
    - The server's file system must contain sensitive files that are accessible to the user running the backend application.
- Source code analysis:
    ```python
    # File: ..\screenshot-to-code\backend\routes\evals.py

    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str): # folder parameter from request
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # Path object is created directly from user input 'folder'
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # os.path.join is used with unsanitized 'folder'
                for f in os.listdir(folder) # os.listdir is used with unsanitized 'folder'
                if f.endswith(".html")
            }
            # ... rest of the code ...

    @router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
    async def get_pairwise_evals(
        folder1: str = Query( # folder1 parameter from request
            "...",
            description="Absolute path to first folder",
        ),
        folder2: str = Query( # folder2 parameter from request
            "..",
            description="Absolute path to second folder",
        ),
    ):
        if not os.path.exists(folder1) or not os.path.exists(folder2): # os.path.exists is used with unsanitized 'folder1' and 'folder2'
            return {"error": "One or both folders do not exist"}

        evals: list[Eval] = []

        # Get all HTML files from first folder
        files1 = {
            f: os.path.join(folder1, f) # os.path.join is used with unsanitized 'folder1'
            for f in os.listdir(folder1) # os.listdir is used with unsanitized 'folder1'
            if f.endswith(".html")
        }
        files2 = {
            f: os.path.join(folder2, f) # os.path.join is used with unsanitized 'folder2'
            for f in os.listdir(folder2) # os.listdir is used with unsanitized 'folder2'
            if f.endswith(".html")
        }
        # ... rest of the code ...

    @router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
    async def get_best_of_n_evals(request: Request):
        # Get all query parameters
        query_params = dict(request.query_params)

        # Extract all folder paths (folder1, folder2, folder3, etc.)
        folders = []
        i = 1
        while f"folder{i}" in query_params:
            folders.append(query_params[f"folder{i}"]) # folder parameters from request
            i += 1

        if not folders:
            return {"error": "No folders provided"}

        # Validate folders exist
        for folder in folders: # Looping through unsanitized 'folder' parameters
            if not os.path.exists(folder): # os.path.exists is used with unsanitized 'folder'
                return {"error": f"Folder does not exist: {folder}"}

        evals: list[Eval] = []
        folder_names = [os.path.basename(folder) for folder in folders]

        # Get HTML files from all folders
        files_by_folder = []
        for folder in folders: # Looping through unsanitized 'folder' parameters
            files = {
                f: os.path.join(folder, f) # os.path.join is used with unsanitized 'folder'
                for f in os.listdir(folder) # os.listdir is used with unsanitized 'folder'
                if f.endswith(".html")
            }
            files_by_folder.append(files)
        # ... rest of the code ...
    ```
    - The `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` functions in `backend\routes\evals.py` take folder paths as input parameters (`folder`, `folder1`, `folder2`, etc.) via query parameters.
    - These folder paths are used directly with `os.path.join` and `os.listdir` without any sanitization or validation to prevent path traversal.
    - An attacker can manipulate these folder parameters to include path traversal sequences like `../` to access directories outside the intended evaluation folders.

- Security test case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible server.
    2. Open a web browser or use a tool like `curl`.
    3. Send a GET request to the `/evals` endpoint with a crafted `folder` parameter designed to traverse directories, for example: `/evals?folder=../../../`.
    4. Observe the server's response. If the application attempts to list or access files outside the intended `evals` directory based on the traversed path, it indicates a path traversal vulnerability.
    5. To confirm the vulnerability and attempt to read a sensitive file, modify the `folder` parameter to point to a known file path outside the intended directory, such as `/evals?folder=../../../../etc/passwd` (on Linux-based systems) or `/evals?folder=../../../../windows/win.ini` (on Windows-based systems), assuming these files exist and the application has sufficient permissions to attempt to access them. Note that direct file content might not be returned in the response depending on how the application handles file access and errors, but any indication of attempted access or errors related to the traversed path confirms the vulnerability.
    6. Examine the server logs for any errors or file access attempts that confirm the path traversal. A successful exploitation might not always directly return file contents in the HTTP response but can be verified through server-side behavior and logs.
