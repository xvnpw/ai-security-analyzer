# VULNERABILITIES

## Server-Side Request Forgery (SSRF) via Screenshot API

### Vulnerability name
Server-Side Request Forgery (SSRF) via Screenshot API

### Description
The application has an API endpoint `/api/screenshot` that allows users to specify a URL which will be sent to an external service (screenshotone.com) to capture a screenshot. This URL is not validated or restricted in any way, creating a Server-Side Request Forgery vulnerability. An attacker can exploit this by providing a URL that points to internal services, metadata services, or other restricted resources that may be accessible to the screenshotone.com service.

Step by step to trigger vulnerability:
1. An attacker identifies the `/api/screenshot` endpoint in the backend.
2. The attacker crafts a POST request to this endpoint with a malicious URL pointing to an internal service, such as `http://169.254.169.254/latest/meta-data/` (AWS metadata service) or internal network resources.
3. The application forwards this URL to the screenshotone.com API, which attempts to access the specified URL.
4. If successful, the screenshotone.com service accesses the internal resource and returns the rendered content as a screenshot to the application.
5. The application then returns this data to the attacker, potentially leaking sensitive information.

### Impact
The impact of this vulnerability is high. It could allow attackers to:
- Access and exfiltrate data from internal services on the network where screenshotone.com's servers operate
- Potentially access cloud metadata services, which could lead to credential exposure
- Perform port scanning or service discovery on internal networks
- Access restricted URLs that have IP-based restrictions but trust the IP of screenshotone.com's servers

### Vulnerability rank
High

### Currently implemented mitigations
There are no mitigations currently implemented in the codebase for this vulnerability. The code directly takes the user-provided URL and passes it to the screenshot service without any validation or restrictions.

### Missing mitigations
The following mitigations should be implemented:
1. URL validation to only allow specific domains or URL patterns
2. Blocklist for private IP ranges and localhost
3. Disable access to internal services/metadata endpoints
4. Implementation of a URL allowlist mechanism to only permit taking screenshots of trusted domains
5. Rate limiting to prevent abuse of the service

### Preconditions
- The attacker must have access to the public API endpoint
- The application must be configured with a valid screenshotone.com API key

### Source code analysis
In `backend/routes/screenshot.py`:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)

    # Convert the image bytes to a data url
    data_url = bytes_to_data_url(image_bytes, "image/png")

    return ScreenshotResponse(url=data_url)
```

This endpoint receives a ScreenshotRequest object containing a URL. The URL is then passed to the capture_screenshot function:

```python
async def capture_screenshot(
    target_url: str, api_key: str, device: str = "desktop"
) -> bytes:
    api_base_url = "https://api.screenshotone.com/take"

    params = {
        "access_key": api_key,
        "url": target_url,
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
```

The function takes the user-provided URL (`target_url`) and includes it in a request to the screenshotone.com API. There is no validation or sanitization of the URL. The screenshotone.com service will attempt to access whatever URL is provided, potentially including private or internal services.

This creates a classic SSRF vulnerability where the attacker can use the screenshot service as a proxy to access resources that would normally be inaccessible.

### Security test case
1. Setup:
   - Deploy the application and ensure it's accessible
   - Set up a test server with a private endpoint that should not be publicly accessible

2. Test procedure:
   - Create an HTTP POST request to the `/api/screenshot` endpoint:
   ```http
   POST /api/screenshot HTTP/1.1
   Host: application-url.com
   Content-Type: application/json

   {
     "url": "http://your-private-test-server/sensitive-data",
     "apiKey": "valid-api-key-for-screenshotone"
   }
   ```

3. Expected result:
   - The application should forward the request to screenshotone.com
   - Screenshotone.com would attempt to access the private server
   - If successful, a screenshot of the private resource would be returned to the attacker

4. Verification:
   - Check if the response contains data or imagery from the private endpoint
   - Confirm that data that should be restricted has been exposed through the SSRF attack

5. Alternative test using common metadata endpoints:
   - Use a cloud metadata URL in your test, such as:
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/",
     "apiKey": "valid-api-key-for-screenshotone"
   }
   ```
   - Check if cloud instance metadata is returned in the screenshot

This test demonstrates that an attacker can use the screenshot API to access internal or restricted resources, confirming the SSRF vulnerability.
