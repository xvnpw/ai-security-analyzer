# Vulnerabilities in screenshot-to-code

## Server-Side Request Forgery (SSRF) in Screenshot API

### Description
The application's screenshot API endpoint allows users to provide arbitrary URLs for capturing screenshots, which are then processed by the application. The endpoint makes HTTP requests to these user-provided URLs without proper validation or restrictions, creating a Server-Side Request Forgery vulnerability. An attacker can exploit this by providing URLs that target internal network resources or services that should not be accessible from the public internet.

### Impact
This vulnerability could allow attackers to:
- Scan and probe internal network services
- Access metadata services in cloud environments (like AWS metadata service)
- Bypass network security controls
- Potentially gain access to sensitive internal systems or information
- Perform attacks on third-party services that trust the server's IP address

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The code in `routes/screenshot.py` forwards the user-provided URL to the external screenshot service without any validation or restrictions.

### Missing Mitigations
- URL validation to restrict requests to only public internet addresses
- Blocking of private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, etc.)
- Blocking of localhost references and internal domain names
- Request timeouts to prevent long-running SSRF attacks
- Whitelisting of allowed domains or URL patterns

### Preconditions
- Attacker must have access to the public instance of the application
- The `/api/screenshot` endpoint must be accessible

### Source Code Analysis
In `routes/screenshot.py`, the API endpoint accepts a URL from the user and forwards it to an external screenshot service:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    url = request.url  # User-provided URL
    api_key = request.apiKey

    # No validation performed on the URL
    image_bytes = await capture_screenshot(url, api_key=api_key)
    data_url = bytes_to_data_url(image_bytes, "image/png")
    return ScreenshotResponse(url=data_url)
```

The `capture_screenshot` function simply forwards this URL to the external screenshot service:

```python
async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
    api_base_url = "https://api.screenshotone.com/take"
    params = {
        "access_key": api_key,
        "url": target_url,  # Unvalidated URL is used here
        # Other parameters...
    }
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
        # ...
```

The lack of validation allows an attacker to specify URLs pointing to internal services, like:
- `http://localhost:8080`
- `http://10.0.0.1:22`
- `http://169.254.169.254/` (AWS metadata service)

### Security Test Case
1. Setup a local HTTP server to capture incoming requests
2. Deploy the application in a test environment
3. Send a POST request to `/api/screenshot` with the following payload:
   ```json
   {
     "url": "http://your-test-server-address:port/ssrf-test",
     "apiKey": "valid-api-key"
   }
   ```
4. Verify that your test server receives a request, confirming the SSRF vulnerability
5. Try with various internal addresses to demonstrate the scope of the vulnerability:
   ```json
   {
     "url": "http://localhost:8080",
     "apiKey": "valid-api-key"
   }
   ```
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/",
     "apiKey": "valid-api-key"
   }
   ```

## Unauthorized Access to WebSocket API

### Description
The application exposes a WebSocket endpoint at `/generate-code` that allows arbitrary connections without proper authentication or authorization. Combined with the permissive CORS policy (`allow_origins=["*"]`), this allows an attacker to make unauthorized requests to the AI code generation service from any domain. The attacker can fully utilize the AI capabilities of the application, potentially gaining access to sensitive information or consuming resources at the expense of the service operator.

### Impact
This vulnerability could allow attackers to:
-
