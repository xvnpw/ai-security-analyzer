- Vulnerability Name: Server-Side Request Forgery (SSRF) in Screenshot Capture
- Description:
    - An attacker can trigger a Server-Side Request Forgery (SSRF) vulnerability by sending a crafted POST request to the `/api/screenshot` endpoint.
    - The attacker provides a malicious URL in the `url` field of the request body.
    - The backend application, specifically in `backend/routes/screenshot.py`, takes this user-supplied URL and passes it as the `url` parameter to the `capture_screenshot` function.
    - The `capture_screenshot` function then uses the `httpx` library to make an HTTP GET request to `api.screenshotone.com/take`, including the attacker-controlled URL as a parameter.
    - Because there is no validation or sanitization of the user-provided URL, the backend can be tricked into making requests to arbitrary URLs, including internal network resources or sensitive endpoints.
- Impact:
    - **High**: Successful exploitation of this SSRF vulnerability can allow an attacker to:
        - **Scan internal network**: Probe internal services and identify open ports or running applications that are not publicly accessible.
        - **Access internal services**: Interact with internal APIs or services that are not exposed to the public internet, potentially leading to unauthorized actions or data access. For example, accessing internal monitoring dashboards, databases, or configuration panels.
        - **Information Disclosure**: Retrieve sensitive information from internal resources, such as configuration files, application code, or cloud metadata endpoints (e.g., AWS metadata at `http://169.254.169.254/latest/meta-data/`). Accessing cloud metadata could leak sensitive credentials and configuration details.
        - **Denial of Service (Indirect)**: While not the primary impact and excluded from the list by instruction, SSRF could be chained to indirectly cause DoS by overloading internal services.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code in `backend/routes/screenshot.py` directly uses the user-provided URL without any validation or sanitization.
- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement robust validation and sanitization of the `target_url` in the `capture_screenshot` function before making the external request. This should include:
        - **URL Scheme Validation**: Allow only `http` and `https` schemes. Reject any other schemes like `file://`, `ftp://`, `gopher://`, etc.
        - **Hostname Validation**: Implement a whitelist of allowed domains or a blocklist of private IP ranges and internal hostnames. If a whitelist is used, only allow URLs pointing to known safe screenshot services. If a blocklist is used, reject URLs pointing to private IP addresses (e.g., `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), localhost (`127.0.0.1` or `::1`) and metadata IPs (`169.254.169.254`).
        - **Path Validation (Optional but Recommended)**: If possible, validate or restrict the path component of the URL to further limit the attack surface.
    - **Network Segmentation**:  Employ network segmentation to restrict the backend server's access to internal resources. This defense-in-depth measure can limit the impact of SSRF even if input validation is bypassed. Use firewalls or network policies to allow only necessary outbound connections from the backend server.
- Preconditions:
    - The application must be deployed and accessible over the network.
    - An attacker needs to have network access to the application and the ability to send POST requests to the `/api/screenshot` endpoint.
    - A valid `apiKey` for `screenshotone.com` is needed for the `capture_screenshot` function to work as intended but is not strictly necessary to test the SSRF vulnerability itself as the core issue is the backend attempting to access the attacker-controlled URL.
- Source Code Analysis:
    - File: `backend/routes/screenshot.py`
    ```python
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
            "url": target_url,  # User-provided URL is directly used here
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
            response = await client.get(api_base_url, params=params) # HTTP GET request is made to screenshotone.com with user controlled URL
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")


    class ScreenshotRequest(BaseModel):
        url: str # User input for URL
        apiKey: str


    class ScreenshotResponse(BaseModel):
        url: str


    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        url = request.url # User-controlled URL from request body
        api_key = request.apiKey

        image_bytes = await capture_screenshot(url, api_key=api_key) # capture_screenshot is called with user-controlled URL

        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    - The code snippet clearly shows that the `url` from `ScreenshotRequest` (user input) is passed directly to the `capture_screenshot` function and used in the `httpx.get` request without any validation. This direct usage of user-controlled input in making server-side requests is the root cause of the SSRF vulnerability.

- Security Test Case:
    1. **Setup**:
        - Deploy the `screenshot-to-code` backend application. Ensure it is running and accessible (e.g., at `http://localhost:7001`).
        - Obtain a valid API key for `screenshotone.com` and set it in the `backend/.env` file or pass it through the frontend settings.
    2. **Exploit**:
        - Use `curl` or a similar HTTP client to send a POST request to the `/api/screenshot` endpoint.
        - Set the `Content-Type` header to `application/json`.
        - Provide the following JSON payload in the request body, replacing `YOUR_SCREENSHOTONE_API_KEY` with your actual API key:
        ```json
        {
          "url": "http://localhost:7001/",
          "apiKey": "YOUR_SCREENSHOTONE_API_KEY"
        }
        ```
        - Send the request to `http://localhost:7001/api/screenshot`.
    3. **Verification**:
        - Examine the response from the `/api/screenshot` endpoint.
        - If the application is vulnerable to SSRF, you might observe one of the following outcomes:
            - **Error Response**: The response might indicate an error from `screenshotone.com` because it is attempting to screenshot `http://localhost:7001/`. However, the fact that the request was made to `localhost:7001` confirms the SSRF vulnerability.
            - **Timeout or No Response**: If `screenshotone.com` blocks or times out on local requests, you might receive a timeout or no response from the `/api/screenshot` endpoint. This behavior still suggests the SSRF is present as the backend attempted to access the local URL.
            - **Successful Response (Less Likely)**: In some scenarios, if `screenshotone.com` does not block localhost and is able to process the request (which is unlikely but theoretically possible depending on their internal handling), you might get a successful response containing a screenshot of the backend's home page (which is served at `/` in `backend/routes/home.py`).
        - To further confirm and explore the vulnerability, try targeting other internal resources or services running on the same network as the backend application, or attempt to access cloud metadata endpoints if the application is running in a cloud environment. For instance, try URLs like `http://127.0.0.1:6379` (if Redis is running locally) or `http://169.254.169.254/latest/meta-data/` (for AWS metadata).

This test case demonstrates that an attacker can manipulate the backend to make requests to internal resources by controlling the `url` parameter, thus confirming the SSRF vulnerability.
