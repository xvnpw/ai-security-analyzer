- Vulnerability name: Server-Side Request Forgery (SSRF) in Screenshot Capture
- Description:
    1. An attacker sends a POST request to the `/api/screenshot` endpoint with a crafted URL in the `url` parameter.
    2. The backend server, without proper validation, uses the provided URL to make a request to the `screenshotone.com` API via the `capture_screenshot` function.
    3. If the attacker provides a URL pointing to an internal resource (e.g., `http://localhost:7001/api/status`) or an external service, the backend server will make a request to that URL via `screenshotone.com`.
    4. The response from the target URL is then captured as a screenshot and returned to the attacker.
- Impact:
    - Information Disclosure: An attacker can potentially access internal resources that are not publicly accessible, such as internal APIs, configuration files, or services running on the backend network.
    - Port Scanning: An attacker might be able to use the service to scan internal ports and identify open services.
    - Data Exfiltration (potentially): If internal services return sensitive data, this data could be captured in the screenshot and exposed to the attacker.
    - Abuse of external services (potentially): An attacker could make requests to external services via `screenshotone.com`, potentially abusing those services or bypassing access controls.
- Vulnerability rank: high
- Currently implemented mitigations:
    - None. The code directly uses the user-provided URL without validation.
- Missing mitigations:
    - Input validation and sanitization: Implement robust validation and sanitization of the `target_url` parameter to prevent access to internal or disallowed external resources.
    - URL allowlist: Maintain an allowlist of allowed URL schemes (e.g., `http`, `https`) and domains if possible, limiting to publicly accessible websites.
    - Response validation: Validate the response from `screenshotone.com` to ensure it's a valid screenshot and not an error page or unexpected content that could indicate an SSRF attempt.
- Preconditions:
    - Publicly accessible instance of the application.
    - `screenshotone.com` API key configured correctly.
    - Vulnerable endpoint `/api/screenshot` is exposed and accessible.
- Source code analysis:
    - File: `backend/routes/screenshot.py`
    ```python
    @router.post("/api/screenshot")
    async def app_screenshot(request: ScreenshotRequest):
        # Extract the URL from the request body
        url = request.url # [POINT OF INTEREST] User-provided URL
        api_key = request.apiKey

        # TODO: Add error handling
        image_bytes = await capture_screenshot(url, api_key=api_key) # [POINT OF INTEREST] URL passed directly to capture_screenshot

        # Convert the image bytes to a data url
        data_url = bytes_to_data_url(image_bytes, "image/png")

        return ScreenshotResponse(url=data_url)

    async def capture_screenshot(
        target_url: str, api_key: str, device: str = "desktop"
    ) -> bytes:
        api_base_url = "https://api.screenshotone.com/take"

        params = {
            "access_key": api_key,
            "url": target_url, # [VULNERABILITY] target_url is directly from user input 'url'
            ...
        }

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(api_base_url, params=params)
            if response.status_code == 200 and response.content:
                return response.content
            else:
                raise Exception("Error taking screenshot")
    ```
    - The `app_screenshot` function takes the `url` directly from the `ScreenshotRequest` body without validation.
    - This `url` is passed to `capture_screenshot` and used in the `screenshotone.com` API request.
    - The lack of validation on `target_url` allows for SSRF.
- Security test case:
    1. Deploy the `screenshot-to-code` application publicly.
    2. Prepare a malicious URL, e.g., `http://localhost:7001/api/status` to target the application's status endpoint.
    3. Send a POST request to `/api/screenshot` with the following JSON payload, replacing `YOUR_SCREENSHOTONE_API_KEY` with a valid key:
       ```json
       {
           "url": "http://localhost:7001/api/status",
           "apiKey": "YOUR_SCREENSHOTONE_API_KEY"
       }
       ```
    4. Observe the response. If vulnerable, the response will contain a screenshot of the backend's status page, confirming SSRF.
    5. Further testing can involve using an attacker-controlled external URL (e.g., `http://attacker-controlled-domain.com/ssrf-probe`) and checking server logs for requests originating from the application.
