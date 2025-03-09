- Vulnerability Name: Server-Side Request Forgery (SSRF) in Screenshot Functionality
- Description:
    1. An attacker can send a crafted POST request to the `/api/screenshot` endpoint.
    2. In the request body, the attacker provides a malicious URL as the `url` parameter. This URL can be an internal resource not intended for public access (e.g., `http://localhost:internal_service_port/sensitive_data`).
    3. The backend application, without proper validation of the provided URL, uses the `capture_screenshot` function to initiate a request to `screenshotone.com` API.
    4. The `capture_screenshot` function includes the attacker-provided URL as a parameter in its request to `screenshotone.com`.
    5. `screenshotone.com` service then attempts to access and take a screenshot of the URL provided in the parameter.
    6. If the attacker provided an internal URL, `screenshotone.com` will attempt to access this internal resource.
    7. The response from `screenshotone.com` (which might contain information from the internal resource if accessible and screenshotable by `screenshotone.com`) is then returned to the user as a data URL.
- Impact:
    - **Information Disclosure**: An attacker could potentially access sensitive information from internal resources if they are accessible to the `screenshotone.com` service and the service includes this information in the screenshot or response.
    - **Indirect Security Risk**: If `screenshotone.com` service is compromised or has vulnerabilities, this SSRF could be leveraged to further attack internal networks or systems, as the request originates from `screenshotone.com` infrastructure.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses the user-provided URL without validation in the `capture_screenshot` function.
- Missing Mitigations:
    - **URL Validation and Sanitization**: Implement robust validation on the server-side to ensure that the `target_url` is a valid and safe URL, and explicitly allow only external and expected domains. Block or sanitize URLs pointing to internal networks or sensitive resources.
    - **Restrict URL Schemes**: Limit allowed URL schemes to `http` and `https` to prevent usage of other potentially dangerous schemes like `file://` or `gopher://`.
    - **Network Segmentation**: Ensure that the backend server and the `screenshotone.com` service are appropriately segmented from internal, more sensitive networks to limit the impact of potential SSRF exploits.
    - **Rate Limiting**: Implement rate limiting on the `/api/screenshot` endpoint to reduce the ability of an attacker to perform large-scale scanning of internal resources.
- Preconditions:
    - The application must be running and accessible to external attackers.
    - An attacker needs to know or guess the existence of the `/api/screenshot` endpoint.
    - The `SCREENSHOTONE_API_KEY` must be configured for the screenshot functionality to be active.
- Source Code Analysis:
    ```python
    # File: ..\screenshot-to-code\backend\routes\screenshot.py
    from fastapi import APIRouter
    from pydantic import BaseModel
    import httpx

    router = APIRouter()

    async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
        api_base_url = "https://api.screenshotone.com/take" # Line 7
        params = {
            "access_key": api_key,
            "url": target_url, # Line 11: User-provided target_url is used directly
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
            response = await client.get(api_base_url, params=params) # Line 27: Request to screenshotone.com
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")

    class ScreenshotRequest(BaseModel):
        url: str # Line 34: url parameter from request
        apiKey: str

    class ScreenshotResponse(BaseModel):
        url: str

    @router.post("/api/screenshot") # Line 41: Vulnerable endpoint
    async def app_screenshot(request: ScreenshotRequest):
        url = request.url # Line 43: User-provided URL extracted
        api_key = request.apiKey

        image_bytes = await capture_screenshot(url, api_key=api_key) # Line 46: Vulnerable function call

        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    **Visualization:**

    ```mermaid
    sequenceDiagram
        participant Attacker
        participant Backend Server
        participant ScreenshotOne API

        Attacker->>Backend Server: POST /api/screenshot {url: "http://internal-resource", apiKey: "API_KEY"}
        Backend Server->>ScreenshotOne API: GET https://api.screenshotone.com/take?access_key=API_KEY&url=http://internal-resource&...
        ScreenshotOne API->>internal-resource: GET http://internal-resource
        alt internal-resource is accessible
            internal-resource-->>ScreenshotOne API: Response from internal resource
            ScreenshotOne API->>Backend Server: Response with screenshot of internal resource
            Backend Server->>Attacker: Response {url: "data:image/png;base64,..."}
        else internal-resource is not accessible
            ScreenshotOne API-->>Backend Server: Error response
            Backend Server->>Attacker: Error response
        end
    ```
- Security Test Case:
    1. **Pre-requisite**: Ensure the application is running and accessible. You will need to obtain or guess a valid `SCREENSHOTONE_API_KEY` or if the API key is not validated, you can try without it.
    2. **Craft Malicious Request**: Prepare a POST request to the `/api/screenshot` endpoint with the following JSON body:
        ```json
        {
          "url": "http://localhost:7001/",
          "apiKey": "YOUR_SCREENSHOTONE_API_KEY"  // Replace with a valid or dummy API key
        }
        ```
        Replace `"http://localhost:7001/"` with an internal resource you want to test for access. For example, if you want to check for access to the backend itself, you can use `http://localhost:7001/`. For testing external access, use a known external service like `https://www.google.com`.
    3. **Send the Request**: Use a tool like `curl`, `Postman`, or a browser's developer console to send the crafted POST request to the `/api/screenshot` endpoint of the application.
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"url": "http://localhost:7001/", "apiKey": "YOUR_SCREENSHOTONE_API_KEY"}' http://<YOUR_APPLICATION_URL>/api/screenshot
        ```
        Replace `<YOUR_APPLICATION_URL>` with the actual URL where the application is running (e.g., `http://localhost:5173` if testing locally and accessing backend on port 7001).
    4. **Analyze the Response**: Examine the response from the server.
        - **Successful Screenshot**: If the request is successful, the response will be a JSON object containing a `data URL`. If you requested an internal resource and received a data URL, it indicates that `screenshotone.com` was able to access and screenshot the internal resource, confirming the SSRF vulnerability. The content of the data URL (if you decode the base64 part) might reveal information about the internal resource.
        - **Error Response**: If you receive an error, it could mean the resource is not accessible, or there was some other issue. Try testing with a known public website URL (like `https://www.google.com`) to ensure the screenshot functionality is working in general and to differentiate between network access issues and SSRF vulnerability.
    5. **Repeat with Different Internal URLs**: Try different internal URLs (e.g., `http://localhost:7001/evals`, `http://127.0.0.1:7001/`) to further explore accessible internal resources and confirm the scope of the SSRF vulnerability.

This test case will help verify if the application is vulnerable to SSRF through the screenshot functionality. Success is indicated if you can get a screenshot (data URL) of an internal resource.
