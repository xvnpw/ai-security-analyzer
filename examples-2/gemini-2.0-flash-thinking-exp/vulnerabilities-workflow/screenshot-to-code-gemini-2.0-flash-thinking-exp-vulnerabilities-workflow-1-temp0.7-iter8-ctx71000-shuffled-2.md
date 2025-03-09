### Vulnerability List

#### 1. Server-Side Request Forgery (SSRF) in Screenshot Capture Feature

- Description:
    1. An attacker can send a crafted URL to the `/api/screenshot` endpoint.
    2. The backend application, without proper validation, uses this attacker-supplied URL as the `url` parameter in a request to the `screenshotone.com` service.
    3. The `capture_screenshot` function in `backend/routes/screenshot.py` then makes an HTTP request to the attacker-controlled URL via `screenshotone.com`.
    4. This can lead to Server-Side Request Forgery (SSRF), where the backend server can be tricked into making requests to unintended locations, potentially internal resources or external services.

- Impact:
    - **High**: An attacker could potentially use the server as a proxy to:
        - Scan internal network ports and services that are not publicly accessible.
        - Access internal services or resources that are protected by firewalls or access control lists, potentially leading to information disclosure or unauthorized actions if internal services are vulnerable.
        - In some scenarios, depending on the `screenshotone.com` service capabilities and internal network configuration, it might be possible to interact with internal APIs or services, potentially leading to further exploitation.
        - Expose internal server information through error messages or response content from internal resources.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The application directly passes the user-provided URL to the external screenshot service without any validation or sanitization.

- Missing mitigations:
    - **Input validation and sanitization**: Implement robust validation on the `url` parameter in the `/api/screenshot` endpoint to ensure it only accepts safe and expected URL formats. A whitelist of allowed protocols (e.g., `http`, `https`) and domain patterns could be used.
    - **URL scheme and destination restrictions**: Restrict the URL schemes allowed to `http` and `https` and consider using a blocklist or denylist to prevent access to internal network ranges (e.g., private IP ranges, localhost).
    - **Error handling**: Implement proper error handling to prevent leakage of sensitive information in error responses if the screenshot service encounters issues when accessing internal resources.

- Preconditions:
    - The application must be running and publicly accessible.
    - The attacker needs to have network access to the application.
    - The ScreenshotOne API key must be configured and functional in the backend.

- Source code analysis:
    - File: `backend/routes/screenshot.py`
    ```python
    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        # Extract the URL from the request body
        url = request.url # [POINT OF VULNERABILITY: User-controlled URL is directly used]
        api_key = request.apiKey

        # TODO: Add error handling
        image_bytes = await capture_screenshot(url, api_key=api_key) # [POINT OF VULNERABILITY: User-controlled URL is passed to capture_screenshot]

        # Convert the image bytes to a data url
        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    - File: `backend/routes/screenshot.py`
    ```python
    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"

        params = {
            "access_key": api_key,
            "url": target_url, # [POINT OF VULNERABILITY: target_url is used in external API call]
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
            response = await client.get(api_base_url, params=params) # [External API call to screenshotone.com with user-controlled URL]
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")
    ```
    - The code directly takes the `url` from the `ScreenshotRequest` and passes it as `target_url` to the `capture_screenshot` function.
    - The `capture_screenshot` function then uses this `target_url` in the `params` dictionary when making a GET request to `screenshotone.com`.
    - There is no input validation or sanitization on the `target_url` before making the external API call.

- Security test case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible instance.
    2. Prepare a malicious URL, for example, `http://localhost:7001/api/home` if you want to test internal access, or a URL to a public IP you control to observe the request. For this example, we will assume testing internal access.
    3. Open a tool like `curl` or Postman.
    4. Send a POST request to the `/api/screenshot` endpoint of the deployed application with the following JSON body:
        ```json
        {
          "url": "http://localhost:7001/api/home",
          "apiKey": "YOUR_SCREENSHOTONE_API_KEY"
        }
        ```
        Replace `YOUR_SCREENSHOTONE_API_KEY` with a valid ScreenshotOne API key if needed for the test environment, or if the application is configured to work without API key for testing purposes, you might omit it if the application allows.
    5. Observe the response from the `/api/screenshot` endpoint. If the application is vulnerable to SSRF, the response might contain:
        - An error message from `screenshotone.com` indicating it tried to access `http://localhost:7001/api/home` and failed (e.g., timeout, connection refused), which confirms SSRF as the request was made.
        - If `http://localhost:7001/api/home` returns any content, and if `screenshotone.com` includes this content in its response (unlikely but possible depending on service behavior), you might see parts of the application's home page in the response.
    6. To further confirm, you can try to access other internal resources or external services you control and monitor the network traffic to see if the requests originate from the application server via `screenshotone.com`.
    7. Examine the application logs (if available) for any errors or logs related to the request to `http://localhost:7001/api/home` made by `screenshotone.com`.

This test case demonstrates how an external attacker can trigger SSRF by providing a malicious URL to the `/api/screenshot` endpoint.

#### 2. Local File Inclusion (LFI) in Evals Endpoints

- Description:
    1. An attacker can send a crafted request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints, manipulating the `folder`, `folder1`, `folder2`, etc. parameters.
    2. The backend application, without proper validation, uses these attacker-supplied folder paths to list files and read file contents.
    3. Functions `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` in `backend/routes/evals.py` use `os.listdir` and `open` with the user-controlled folder paths.
    4. This can lead to Local File Inclusion (LFI), where the attacker can read arbitrary files from the server's filesystem by using path traversal techniques (e.g., `../`, `..\\`).

- Impact:
    - **High**: An attacker could potentially read sensitive files on the server, including:
        - Source code of the application, revealing business logic and potentially other vulnerabilities.
        - Configuration files, which might contain database credentials, API keys, or other sensitive information.
        - Data files or logs that are accessible within the application's filesystem.
        - In some cases, if the attacker can read executable files, it might be a stepping stone to further exploitation.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The application directly uses user-provided folder paths without any validation or sanitization.

- Missing mitigations:
    - **Input validation and sanitization**: Implement robust validation on the `folder`, `folder1`, `folder2`, etc. parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints.
        - **Whitelist approach**: Define a whitelist of allowed base directories for evaluations and ensure that the provided folder paths are within these allowed directories.
        - **Path sanitization**: Sanitize the input paths to remove path traversal sequences like `../` and `..\\`. Use functions like `os.path.abspath` and `os.path.normpath` to resolve paths and check if they are still within the allowed base directories.
    - **Restrict file access**: Ensure that the application user has minimal necessary file system permissions, limiting the impact of potential LFI vulnerabilities.

- Preconditions:
    - The application must be running and publicly accessible.
    - The attacker needs to have network access to the application.
    - The attacker needs to know or guess the endpoint paths (`/evals`, `/pairwise-evals`, `/best-of-n-evals`).

- Source code analysis:
    - File: `backend/routes/evals.py`
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [POINT OF VULNERABILITY: User-controlled folder path is used directly]
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [POINT OF VULNERABILITY: User-controlled folder path is used in os.path.join]
                for f in os.listdir(folder) # [POINT OF VULNERABILITY: User-controlled folder path is used in os.listdir]
                if f.endswith(".html")
            }
            # ... rest of the code ...
            for base_name in base_names:
                # ...
                output_file = None
                for filename, filepath in files.items():
                    if filename.startswith(base_name):
                        output_file = filepath
                        break

                if output_file:
                    # ...
                    with open(output_file, "r", encoding="utf-8") as f: # [POINT OF VULNERABILITY: User-controlled file path is used in open]
                        output_html = f.read()
                    evals.append(Eval(input=input_data, outputs=[output_html]))
            return evals

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
    ```
    - The `get_evals` function takes the `folder` parameter directly from the query string.
    - It uses `Path(folder)` and `os.path.exists()` to check if the folder exists, but this does not prevent path traversal.
    - `os.listdir(folder)` lists files within the directory specified by the user-controlled `folder` path.
    - `os.path.join(folder, f)` constructs file paths by joining the user-provided `folder` with filenames.
    - `open(output_file, "r", encoding="utf-8")` opens and reads the file content based on the constructed path, allowing an attacker to read files if they can manipulate the `folder` parameter to traverse directories.
    - Similar vulnerabilities exist in `get_pairwise_evals` and `get_best_of_n_evals` functions, which also use user-provided folder paths without proper validation.

- Security test case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible instance.
    2. Open a tool like `curl` or a web browser.
    3. Send a GET request to the `/evals` endpoint with a crafted `folder` parameter to attempt path traversal. For example, to read the `/etc/passwd` file (assuming a Linux-based server and that the application has read permissions, which is unlikely but serves as a PoC):
        ```
        curl "http://<your-app-url>/evals?folder=../../../../../../../../etc/"
        ```
        Or to test reading application files, assuming the application is deployed in `/app`:
        ```
        curl "http://<your-app-url>/evals?folder=../../../../../../app/backend/routes/"
        ```
    4. Observe the response from the `/evals` endpoint.
        - If vulnerable, and if there are `.html` files in the traversed directory (in the `/evals` case, it is very unlikely for `/etc/passwd` or `/app/backend/routes/` to contain `.html` files, so this test case might not directly return file content but could expose error messages or different behavior confirming LFI), you might see an error message like "Error processing evals" if no `.html` files are found, or if the application attempts to process non-HTML files and fails.
        - To make the test more effective, you can create a directory with `.html` files within the application's expected `EVALS_DIR` (or a similar accessible directory if you know the application structure) and then try to traverse out of that directory to read other files. For example, if `EVALS_DIR` is `/app/evals` and you have files in `/app/evals/test_folder/`, you could try `folder=../` to try and list files in `/app/evals`. Or `folder=../../` to try and list files in `/app/`.

    5. Examine the application logs for any file access attempts or errors that indicate path traversal.

This test case demonstrates how an external attacker can attempt to exploit LFI by manipulating the `folder` parameter in the `/evals` endpoint. Similar tests can be performed for `/pairwise-evals` and `/best-of-n-evals` endpoints.
