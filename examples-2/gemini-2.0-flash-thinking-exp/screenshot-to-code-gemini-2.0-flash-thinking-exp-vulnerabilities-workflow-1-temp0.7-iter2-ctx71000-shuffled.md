## Combined Vulnerability List

This document outlines the identified vulnerabilities from the provided lists, consolidated into a single report.

### Vulnerability 1: Path Traversal in Evaluation File Access

- **Description:**
    An external attacker can exploit a path traversal vulnerability to access arbitrary files on the server by manipulating the `folder`, `folder1`, or `folder2` parameters in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` API endpoints. By providing a crafted path containing directory traversal sequences like `../`, an attacker can potentially read sensitive files outside of the intended evaluation directories.

    Steps to trigger the vulnerability:
    1. Access the `/evals` endpoint (or `/pairwise-evals`, `/best-of-n-evals`) with a crafted `folder` parameter (or `folder1`, `folder2` respectively).
    2. Set the `folder` parameter to a path containing directory traversal sequences, for example: `folder=../../../../etc/passwd`.
    3. The backend application will attempt to access files within the specified path. Due to insufficient path validation, it may access files outside the intended `evals_data` directory.
    4. If successful, the attacker will receive an error message indicating a failure to process the file or folder, or in some cases, may even be able to read the content if the application attempts to process files it shouldn't. While the current code reads HTML and images, an attacker could potentially try to read other file types by manipulating the code or exploiting other endpoints if they exist or are added later.

- **Impact:**
    An attacker can read arbitrary files on the server, including application code, configuration files, and potentially sensitive data if they are accessible to the application's user. This can lead to information disclosure, which can be further used to compromise the application or the server.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - The code checks if the provided `folder` exists using `folder_path.exists()` and `os.path.exists(folder1)`, `os.path.exists(folder2)`.
    - The code only reads `.html` and `.png` files.

- **Missing mitigations:**
    - Input path sanitization and validation to prevent directory traversal sequences like `../`.
    - Restricting the base directory for file access to the intended `evals_data` directory and its subdirectories.
    - Using secure path manipulation functions that prevent traversal, such as `os.path.abspath` combined with checks to ensure the resolved path is still within the allowed base directory.

- **Preconditions:**
    - The application must be deployed and accessible to external attackers.
    - The attacker needs to identify the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints and understand that they accept file paths as parameters.

- **Source code analysis:**
    - File: `backend/routes/evals.py`

    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [LINE 1] Path is created directly from user input 'folder'
        if not folder_path.exists(): # [LINE 2] Checks if folder exists, but doesn't prevent traversal
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [LINE 3] Path is joined with user input 'folder'
                for f in os.listdir(folder) # [LINE 4] List directory content based on user input 'folder'
                if f.endswith(".html")
            }
            # ... rest of the code ...
    ```
    - In `get_evals` function (and similarly in `get_pairwise_evals` and `get_best_of_n_evals`), the `folder` parameter from the query is directly used to create a `Path` object and in `os.listdir` and `os.path.join`.
    - Line 1: `folder_path = Path(folder)` -  A `Path` object is created directly from the user-provided `folder` string without any sanitization or validation against path traversal characters.
    - Line 2: `if not folder_path.exists():` - This line only checks if the folder exists at the path provided by the user. It does not validate if the path is within the intended directory or prevent path traversal.
    - Line 3: `f: os.path.join(folder, f)` - `os.path.join` is used to construct file paths by joining the user-provided `folder` with filenames found in the directory. If `folder` contains traversal sequences, `os.path.join` will not prevent the traversal.
    - Line 4: `os.listdir(folder)` - `os.listdir` lists the contents of the directory specified by the user-provided `folder`. If `folder` points to a directory outside of the intended `evals_data` directory due to path traversal, `os.listdir` will operate in that directory.

    - Visualization:
    Imagine `EVALS_DIR` is `/app/backend/evals_data`.
    If attacker provides `folder=../../../../etc`, `folder_path` becomes `Path('../../../../etc')`.
    `folder_path.exists()` will check if `/etc` exists (which it likely does).
    `os.listdir(folder)` will list files in `/etc`.
    `os.path.join(folder, f)` will create paths like `../../../../etc/passwd`.

- **Security test case:**
    1. Deploy the `screenshot-to-code` backend application.
    2. As an attacker, craft a GET request to the `/evals` endpoint with the following parameters: `folder=../../../../etc`. The full URL might look like: `http://<deployed-backend-url>/evals?folder=../../../../etc`.
    3. Send the request to the deployed application.
    4. Observe the response. If the application returns an HTTP 500 error with a detail message indicating "Error processing evals: [Errno 2] No such file or directory: '<path-within-/etc>'", or a 404 error indicating "Folder not found", this could still indirectly confirm the path traversal vulnerability by showing the application attempted to access files within `/etc`.
    5. To further confirm and attempt to read a known file, craft a GET request to the `/evals` endpoint with the following parameters: `folder=../../../../etc&file=passwd`. This is a modified test case, as the original endpoint doesn't directly allow specifying a file, but it highlights the potential. In the current code, this specific test might not directly read `/etc/passwd` content because it's looking for `.html` files, but it demonstrates the path traversal. A more successful test would involve creating a dummy `.html` file within `/etc` (if possible in a test environment) or observing error messages closely for path traversal effects.
    6. Examine the server logs for any file access attempts outside of the intended `evals_data` directory. If logs indicate access attempts to paths like `/etc/passwd` or other system files based on the manipulated `folder` parameter, the path traversal vulnerability is confirmed.


### Vulnerability 2: Server-Side Request Forgery (SSRF) in Screenshot Capture Endpoint

- **Description:**
    1. An attacker sends a POST request to the `/api/screenshot` endpoint with a crafted JSON payload.
    2. The payload includes a `url` parameter set to an internal resource (e.g., `http://localhost:7001`, `http://127.0.0.1:5173`, `http://<internal_service_ip>:<port>`) and a valid `apiKey` for the screenshot service.
    3. The backend application, specifically the `app_screenshot` function in `backend/routes/screenshot.py`, receives this request.
    4. The `capture_screenshot` function is called with the attacker-controlled `target_url`.
    5. The `capture_screenshot` function uses the `screenshotone.com` API to capture a screenshot of the provided `target_url` without proper validation.
    6. The `screenshotone.com` service attempts to access and take a screenshot of the internal resource specified in `target_url`.
    7. If `screenshotone.com` can access the internal resource, it will return a screenshot back to the backend.
    8. The backend then returns this screenshot (as a data URL) to the attacker.
    9. Even if `screenshotone.com` cannot directly access or screenshot the internal resource, the response time or error message might reveal information about the internal network and services.

- **Impact:**
    - **Information Disclosure:** An attacker can probe internal network infrastructure, identify running services, and potentially gather information about their configurations and versions by observing response times or error messages when attempting to screenshot internal resources.
    - **Service Disruption (Indirect):** While not a direct denial of service, if the screenshot service `screenshotone.com` is heavily abused by SSRF requests, it could lead to performance degradation or temporary unavailability of the screenshot service for legitimate users. This is an indirect impact on the application's functionality.
    - **Potential for further exploitation:** In more complex scenarios, if internal services are not properly secured, SSRF can be a stepping stone to further attacks, such as accessing sensitive data or triggering actions on internal systems.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - None. The code directly passes the user-provided URL to the external screenshot service without any validation or sanitization.

- **Missing mitigations:**
    - **Input Validation and Sanitization:** Implement robust validation on the `url` parameter in the `/api/screenshot` endpoint. This should include:
        - **URL Scheme Whitelisting:** Only allow `http` and `https` schemes.
        - **Hostname/IP Address Blacklisting/Whitelisting:** Prevent access to private IP ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7`) and potentially localhost. If possible, maintain a whitelist of allowed external domains if the application's use case is limited to specific websites.
        - **URL Format Validation:** Ensure the URL is well-formed and does not contain malicious characters or encoding.
    - **Using a dedicated URL validation library:** Employ a well-vetted library for URL parsing and validation to avoid common pitfalls and ensure comprehensive checks.
    - **Error Handling and Response Sanitization:** Avoid leaking sensitive information in error messages. If the screenshot service encounters an error due to an invalid or blocked URL, return a generic error message to the user without disclosing details about the internal network or the reason for failure.

- **Preconditions:**
    - The application must be deployed and publicly accessible.
    - The `/api/screenshot` endpoint must be exposed without authentication or with easily obtainable API keys (in this case, the `apiKey` is passed from the frontend, suggesting it might be intended for client-side use and not strictly secret).
    - The attacker needs to know or guess the existence and functionality of the `/api/screenshot` endpoint.

- **Source code analysis:**
    ```python
    # File: ..\screenshot-to-code\backend\routes\screenshot.py
    import base64
    from fastapi import APIRouter
    from pydantic import BaseModel
    import httpx

    router = APIRouter()

    # ... (bytes_to_data_url function)

    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"

        params = {
            "access_key": api_key,
            "url": target_url, # [VULNERABILITY]: target_url is directly from user input without validation
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
            response = await client.get(api_base_url, params=params) # Request to external service with user-controlled URL
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")

    class ScreenshotRequest(BaseModel):
        url: str # User-controlled URL input
        apiKey: str


    class ScreenshotResponse(BaseModel):
        url: str


    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        # Extract the URL from the request body
        url = request.url # URL is extracted from request body
        api_key = request.apiKey

        # TODO: Add error handling
        image_bytes = await capture_screenshot(url, api_key=api_key) # capture_screenshot called with user-controlled URL

        # Convert the image bytes to a data url
        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    The code snippet shows that the `app_screenshot` function directly takes the `url` from the `ScreenshotRequest` and passes it to `capture_screenshot` function. The `capture_screenshot` function then makes an HTTP GET request to `screenshotone.com` with this user-controlled `url` as a parameter, without any validation. This allows an attacker to control the `target_url` and potentially perform SSRF attacks.

- **Security test case:**
    1. **Setup:** Ensure the backend application is running and accessible publicly or within a test environment where you can act as an external attacker. You will need to know the base URL of the backend (e.g., `http://localhost:7001` if running locally or a public domain if deployed).
    2. **Craft SSRF Payload:** Create a JSON payload for a POST request to `/api/screenshot`. Set the `url` parameter to target an internal resource, for example, the backend itself: `http://localhost:7001`. Use a valid API key for the `apiKey` parameter (you can find or generate a placeholder API key if needed for testing, or use a valid one if you have access).

        ```json
        {
            "url": "http://localhost:7001",
            "apiKey": "YOUR_API_KEY"
        }
        ```

    3. **Send the Request:** Use a tool like `curl`, `Postman`, or a web browser's developer console to send a POST request to the `/api/screenshot` endpoint with the crafted JSON payload. For example, using `curl`:

        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"url": "http://localhost:7001", "apiKey": "YOUR_API_KEY"}' http://<your_backend_url>/api/screenshot
        ```
        Replace `<your_backend_url>` with the actual URL of your backend application and `YOUR_API_KEY` with your API key.

    4. **Analyze the Response:** Examine the response from the server.
        - **Successful Screenshot:** If the request is successful (HTTP status 200), the response body will contain a JSON object with a `url` field. This `url` will be a data URL representing a screenshot. If the screenshot is of the backend's default page or status endpoint (as defined in `backend/routes/home.py`), it confirms that the attacker was able to access the internal resource `http://localhost:7001` via the SSRF vulnerability.
        - **Error Response/Time Difference:** If the screenshot service or the backend returns an error, analyze the error message. Even if a direct screenshot is not returned, the response time might be different compared to a request with a valid external URL. This difference in response time or specific error messages can still indicate that the backend attempted to access the internal resource, confirming the SSRF vulnerability to some extent. For example, if you target a non-existent internal port, the error might be different than when targeting a valid, but blocked, external website.

    5. **Repeat with other internal URLs:** Try targeting other internal resources like `http://127.0.0.1:5173` (frontend port), or internal IP addresses and ports if you know of any other services running in the same network as the backend. Observe the responses for each attempt to map out potential internal services.


### Vulnerability 3: API Key Exposure via Client-Side Settings Dialog

- **Description:**
    1. The application allows users to provide API keys (OpenAI, Anthropic) through a "settings dialog" in the client-side application.
    2. These API keys are then sent to the backend via websocket messages as part of the request payload for code generation (`/generate-code` endpoint in `generate_code.py`).
    3. The `get_from_settings_dialog_or_env` function in `generate_code.py` prioritizes API keys provided in the request parameters (from the settings dialog) over environment variables.
    4. If an attacker can intercept or manipulate the frontend code or the websocket communication, they could potentially retrieve the API keys being sent from the client to the backend, especially if the client-side settings dialog stores or exposes these keys in local storage or browser memory.
    5. While the intended use case is for the user to provide their *own* API keys, if the application were to be misconfigured or if a developer accidentally included a default or shared API key in the client-side code or configuration, this mechanism could lead to unintentional exposure of these API keys to malicious actors.

- **Impact:**
    - **Unauthorized API Access:** Exposed API keys for OpenAI, Anthropic, or other LLM services could be used by attackers to make unauthorized requests to these services. This could lead to:
        - **Financial Costs:** Usage of the API keys by attackers can incur significant costs for the API key owner, depending on the pricing model of the LLM service.
        - **Service Disruption:** Abuse of the API keys could lead to rate limiting or suspension of the API key, disrupting the intended functionality of the application for legitimate users.
        - **Data Breach (Indirect):** In some scenarios, if the LLM service is used to process sensitive data, unauthorized access via exposed API keys could potentially lead to indirect data breaches depending on the attacker's activities.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - None. The application directly accepts API keys from client-side settings dialog and environment variables without any specific security measures to protect them in transit or in the client-side context.

- **Missing mitigations:**
    - **Secure API Key Handling on Client-Side:**
        - **Avoid storing API keys in client-side code or easily accessible storage (like local storage).** If API keys must be used client-side, consider more secure storage mechanisms or avoid storing them persistently.
        - **HTTPS for all communication:** Ensure all communication between the frontend and backend (especially websocket communication) is over HTTPS to prevent interception of API keys in transit.
    - **Backend-Only API Key Management (Recommended):**
        - **Ideally, the application should be designed to manage API keys only on the backend.** The frontend should not handle or transmit API keys directly.
        - **Implement authentication and authorization for the `/generate-code` websocket endpoint.** This would ensure that only authenticated users can initiate code generation requests and potentially use the API keys managed by the backend.
        - **Use secure environment variables for API keys on the backend.** Ensure proper permissions and access controls are in place to protect the backend environment where API keys are stored.
    - **Rate Limiting and Monitoring:** Implement rate limiting on the `/generate-code` endpoint to mitigate potential abuse if API keys are compromised. Monitor API key usage for any unusual activity.

- **Preconditions:**
    - The application must be deployed and publicly accessible.
    - The `/generate-code` websocket endpoint must be exposed.
    - An attacker needs to be able to intercept websocket communication or access/manipulate client-side code to retrieve API keys being sent to the backend.
    - The application is configured to accept API keys from client-side settings dialog.

- **Source code analysis:**
    ```python
    # File: ..\screenshot-to-code\backend\routes\generate_code.py

    def get_from_settings_dialog_or_env(
        params: dict[str, str], key: str, env_var: str | None
    ) -> str | None:
        value = params.get(key) # [POTENTIAL VULNERABILITY]: API key from client-side params
        if value:
            print(f"Using {key} from client-side settings dialog")
            return value

        if env_var:
            print(f"Using {key} from environment variable")
            return env_var

        return None

    async def extract_params(
        params: Dict[str, str], throw_error: Callable[[str], Coroutine[Any, Any, None]]
    ) -> ExtractedParams:
        # ...

        openai_api_key = get_from_settings_dialog_or_env(
            params, "openAiApiKey", OPENAI_API_KEY # API key is extracted from client params or env
        )

        # ...

    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        await websocket.accept()
        print("Incoming websocket connection...")

        # ...

        params: dict[str, str] = await websocket.receive_json() # [INPUT]: Params received from websocket, potentially including API keys
        print("Received params")

        extracted_params = await extract_params(params, throw_error)
        openai_api_key = extracted_params.openai_api_key # API key is used for code generation

        # ...
    ```
    The `get_from_settings_dialog_or_env` function clearly prioritizes retrieving API keys from the `params` dictionary, which is populated from the JSON payload received via the websocket connection (`/generate-code` endpoint). This means that if the client-side application sends API keys as part of the websocket message, the backend will use those keys. If an attacker can intercept this websocket communication or compromise the frontend, they could potentially extract the API keys.

- **Security test case:**
    1. **Setup:** Ensure the backend and frontend applications are running and publicly accessible or within a test environment. Use a network interception proxy (like Burp Suite or Wireshark) to monitor websocket communication between the frontend and backend.
    2. **Configure API Key via Settings Dialog:** In the frontend application, open the settings dialog (if available) and enter a valid OpenAI API key (or any API key the application uses). Initiate a code generation request via the frontend UI.
    3. **Intercept Websocket Communication:** Using the network interception proxy, capture the websocket messages sent from the frontend to the backend when the code generation request is initiated.
    4. **Analyze Websocket Payload:** Examine the intercepted websocket message payload (it should be in JSON format). Check if the API key you entered in the settings dialog is present in the payload as a parameter (e.g., `openAiApiKey`).
    5. **Verify API Key Exposure:** If the API key is found in the websocket payload, this confirms that the API key is being transmitted from the client to the backend and is potentially exposed during transit. Further, if the frontend code stores this API key in browser storage (e.g., localStorage), inspect the browser's developer tools to see if the API key is accessible from the client-side as well.
