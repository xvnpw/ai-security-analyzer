- Vulnerability name: Server-Side Request Forgery (SSRF) in Screenshot Route
- Description:
    1. An attacker sends a POST request to the `/api/screenshot` endpoint with a crafted JSON payload.
    2. In the JSON payload, the attacker provides a malicious URL in the `url` parameter, for example, `http://localhost:7001/api/evals` or a URL pointing to an internal service.
    3. The backend application, in `backend\routes\screenshot.py`, calls the `capture_screenshot` function.
    4. The `capture_screenshot` function uses the `screenshotone.com` API to take a screenshot of the URL provided in the request.
    5. The `screenshotone.com` service, acting on behalf of the backend, makes an HTTP GET request to the attacker-specified URL (`http://localhost:7001/api/evals` in the example).
    6. If the attacker specifies an internal URL, the `screenshotone.com` service will access resources within the backend's network that are not intended to be exposed to external users.
    7. The response from the internal URL is then processed by `screenshotone.com` and returned as a screenshot to the backend, and finally back to the attacker as a data URL.
- Impact:
    - Information Disclosure: An attacker can use this vulnerability to access internal endpoints and retrieve sensitive information that would otherwise be inaccessible from the public internet. For example, they might be able to access internal API endpoints, configuration files, or monitoring dashboards if these are accessible from the backend server and do not require authentication from the `screenshotone.com` IP range.
    - Potential for further exploitation: If internal services are accessible and vulnerable, SSRF can be a stepping stone to further attacks, such as accessing databases, executing arbitrary code (in more complex scenarios, not directly evident here), or performing other actions within the internal network.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code directly passes the user-provided URL to the `capture_screenshot` function without any validation or sanitization. The provided project files do not introduce any mitigations.
- Missing mitigations:
    - URL validation: Implement strict validation of the input URL to ensure it only allows access to external, safe domains. Blacklisting or whitelisting domains, or using a URL parsing library to check the hostname.
    - Disallow access to internal networks: Configure the `screenshotone.com` API or network settings to prevent it from accessing internal network ranges (e.g., private IP ranges like `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`).
    - Principle of least privilege: Ensure that the `screenshotone.com` API key used has the minimum necessary permissions and does not allow for actions beyond taking screenshots, if possible through ScreenshotOne API configurations.
- Preconditions:
    - The application must be running and accessible over the internet.
    - The `/api/screenshot` endpoint must be exposed and functional.
    - A valid ScreenshotOne API key must be configured in the backend, as indicated by the `ScreenshotRequest` model requiring `apiKey`.
- Source code analysis:
    - File: `backend\routes\screenshot.py`
    ```python
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
            "url": target_url, # User-provided URL is directly used here
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
            response = await client.get(api_base_url, params=params)
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")

    class ScreenshotRequest(BaseModel):
        url: str # User controlled input 'url'
        apiKey: str

    class ScreenshotResponse(BaseModel):
        url: str

    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        # Extract the URL from the request body
        url = request.url # User input is assigned to 'url' variable
        api_key = request.apiKey

        # TODO: Add error handling
        image_bytes = await capture_screenshot(url, api_key=api_key) # 'url' is passed directly to capture_screenshot

        # Convert the image bytes to a data url
        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)
    ```
    - The code in `backend\routes\screenshot.py` defines a POST endpoint `/api/screenshot` that takes a JSON payload with `url` and `apiKey` parameters as input, as defined by the `ScreenshotRequest` Pydantic model.
    - The `app_screenshot` function extracts the `url` from the request and passes it directly to the `capture_screenshot` function without any validation or sanitization.
    - The `capture_screenshot` function then constructs a request to the `screenshotone.com` API, embedding the user-provided `target_url` as a parameter.
    - This direct usage of user-provided input in a server-side request to an external service without validation is the root cause of the SSRF vulnerability.
    - The file `backend\start.py` shows that the backend application is run on port 7001, which is used in the example test URL.
    - The other files in `PROJECT FILES` do not directly relate to mitigating or exacerbating this SSRF vulnerability. They are mostly related to prompt engineering, LLM interaction, image generation, and testing, and do not modify the vulnerable screenshot route.

- Security test case:
    1. Deploy the `screenshot-to-code` application to a publicly accessible server.
    2. Identify the base URL of the deployed application (e.g., `https://example.com`).
    3. Prepare a malicious URL to test for SSRF. For example, to test access to the internal eval endpoint, use `http://localhost:7001/evals?folder=backend/evals_data/outputs`. To test access to a public IP in private range, use `http://192.168.1.1`. You can replace `localhost:7001` with the actual internal address if known or test common private IPs.
    4. Send a POST request to `https://example.com/api/screenshot` with the following JSON payload using `curl`, `Postman` or similar tool:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://localhost:7001/evals?folder=backend/evals_data/outputs", "apiKey": "YOUR_SCREENSHOTONE_API_KEY"}' https://example.com/api/screenshot
    ```
    Replace `YOUR_SCREENSHOTONE_API_KEY` with a valid ScreenshotOne API key and `https://example.com` with your deployed application URL.
    5. Observe the response. If the vulnerability exists, the `ScreenshotResponse` will contain a data URL representing a screenshot of the content from `http://localhost:7001/evals?folder=backend/evals_data/outputs` (or the other URL you tested). If you try to access an internal service and it returns data, the screenshot may reveal parts of that internal service's response. The response will be a JSON object like:
    ```json
    {
      "url": "data:image/png;base64,..."
    }
    ```
    Decode the base64 data URL in the `url` field to view the screenshot. You should see content from the internal URL if the SSRF is successful.
    6. To further confirm SSRF and rule out external accessibility of the target URL, try accessing a non-existent internal resource (e.g., `http://localhost:7001/nonexistent`) or a resource that returns specific identifiable content only accessible from the internal network, and check if the screenshot reflects this. For example, create a simple endpoint on the backend (e.g., `/api/internal-test`) that returns a unique string and try to screenshot that using `http://localhost:7001/api/internal-test` as the `url` parameter in the POST request.
