# VULNERABILITIES

## Server-Side Request Forgery (SSRF) via Screenshot API

### Vulnerability Name
Server-Side Request Forgery (SSRF) in Screenshot Capture Endpoint

### Description
The application contains a critical SSRF vulnerability in the screenshot capture functionality. An attacker can provide any arbitrary URL to the `/api/screenshot` endpoint, which the server will fetch without proper validation. The server uses the `httpx.AsyncClient` to make HTTP requests to the provided URL, which could allow an attacker to:

1. Scan and probe internal network services not meant to be accessible from the internet
2. Access cloud provider metadata services (like AWS IMDSv1)
3. Interact with localhost or internal network services
4. Potentially read local files using the file:// protocol

The step-by-step process to exploit this vulnerability:
1. The attacker sends a POST request to the `/api/screenshot` endpoint
2. The attacker includes a malicious URL pointing to internal resources (e.g., `http://169.254.169.254/latest/meta-data/` in AWS)
3. The server makes a request to this URL using httpx
4. The server returns the response content to the attacker

### Impact
This vulnerability could allow an attacker to:
- Map internal network topology
- Access sensitive cloud metadata including credentials
- Bypass firewall restrictions to access internal services
- Extract sensitive information from internal services
- Potentially achieve remote code execution if vulnerable internal services are exploited

The impact is critical as it could lead to infrastructure compromise, data breach, and potentially full system takeover.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The code has a commented TODO for adding error handling but currently implements no validation:
```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)
    # ...
```

### Missing Mitigations
1. URL validation to restrict requests to only public, external websites
2. Blocklist for private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
3. Blocklist for cloud metadata URLs (169.254.169.254, etc.)
4. Protocol restriction (only allow http:// and https:// schemes)
5. Rate limiting to prevent network scanning
6. Use of a proxy service for screenshots instead of direct requests

### Preconditions
- The application must be deployed and accessible
- The attacker needs to be able to make POST requests to the `/api/screenshot` endpoint
- No special authentication is required as the endpoint appears to be publicly accessible

### Source Code Analysis
In `backend/routes/screenshot.py`, we see the vulnerable endpoint:

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

This calls the `capture_screenshot` function:

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

The function takes the user-provided URL (`target_url`) and passes it directly to an external API (screenshotone.com) without any validation. This allows the attacker to specify any URL that the screenshot service can access, which could include internal services if the service is misconfigured or vulnerable.

### Security Test Case
1. Set up a server to monitor incoming requests (like a Burp Collaborator or simple webhook service)
2. Send a POST request to the application's `/api/screenshot` endpoint with a payload like:
   ```json
   {
     "url": "http://your-monitoring-server.com/ssrf-test",
     "apiKey": "your-screenshot-api-key"
   }
   ```
3. Verify that your monitoring server receives a request, confirming the SSRF vulnerability
4. Test with internal addresses to check if private network access is possible:
   ```json
   {
     "url": "http://localhost:8080",
     "apiKey": "your-screenshot-api-key"
   }
   ```
   ```json
   {
     "url": "http://169.254.169.254/latest/meta-data/",
     "apiKey": "your-screenshot-api-key"
   }
   ```
5. Test with file protocol to check if local file access is possible:
   ```json
   {
     "url": "file:///etc/passwd",
     "apiKey": "your-screenshot-api-key"
   }
   ```
6. Check the responses to determine the extent of the vulnerability

## Cross-Site WebSocket Hijacking (CSWSH)

### Vulnerability Name
Cross-Site WebSocket Hijacking (CSWSH) due to Missing Origin Validation

### Description
The application implements WebSocket communication for code generation without proper origin validation. This, combined with a permissive CORS policy that allows requests from any origin, creates a Cross-Site WebSocket Hijacking vulnerability. An attacker can create a malicious website that establishes a WebSocket connection to the application server, initiates code generation processes, and potentially accesses sensitive information or performs unauthorized actions.

Step by step exploitation:
1. An attacker creates a malicious website with JavaScript that opens a WebSocket connection to the victim application
2. The victim visits the malicious website
3. The attacker's JavaScript initiates a WebSocket connection to `ws://your-application-domain/generate-code`
4. Since the application has no origin validation, the connection is accepted
5. The attacker can now send commands and receive responses through this WebSocket

### Impact
This vulnerability could allow an attacker to:
- Perform unauthorized code generation using the victim's session
- Steal sensitive data that might be transmitted over the WebSocket
- Consume server resources by initiating multiple code generation requests
- Access the victim's API keys if they are stored in the browser and sent through the WebSocket

This is particularly severe because WebSocket connections are not subject to the same-origin policy, and without proper origin validation, any website can establish a connection if CORS is configured permissively.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The WebSocket endpoint has no origin validation:

```python
@router.websocket("/generate-code")
async def stream_code(websocket: WebSocket):
    await websocket.accept()
    print("Incoming websocket connection...")
    # ...
```

And the CORS policy is completely permissive:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Missing Mitigations
1. WebSocket origin validation to ensure connections are only accepted from trusted domains
2. CSRF token validation for WebSocket connections
3. Restrictive CORS policy to only allow specific origins
4. Implementing session-based authentication for WebSocket connections
5. Rate limiting to prevent abuse

### Preconditions
- The application must be deployed and accessible
- The websocket endpoint `/generate-code` must be enabled
- A victim must visit the attacker's malicious website while having an active session with the application

### Source Code Analysis
In `backend/main.py`, the application configures CORS to allow all origins:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

In `backend/routes/generate_code.py`, the WebSocket endpoint accepts connections without any origin validation:

```python
@router.websocket("/generate-code")
async def stream_code(websocket: WebSocket):
    await websocket.accept()
    print("Incoming websocket connection...")

    ## Communication protocol setup
    async def throw_error(
        message: str,
    ):
        print(message)
        await websocket.send_json({"type": "error", "value": message})
        await websocket.close(APP_ERROR_WEB_SOCKET_CODE)

    # ...

    ## Parameter extract and validation
    params: dict[str, str] = await websocket.receive_json()
    print("Received params")
```

The WebSocket connection is accepted immediately without checking the origin or implementing any token-based validation. The application then proceeds to extract parameters from the WebSocket message and process them, which could allow an attacker to trigger the code generation functionality.

### Security Test Case
1. Create a simple HTML file with JavaScript that connects to the target WebSocket endpoint:

```html
<!DOCTYPE html>
<html>
<head>
  <title>WebSocket Hijacking Test</title>
</head>
<body>
  <h1>CSWSH Test</h1>
  <div id="output"></div>

  <script>
    const ws = new WebSocket('ws://target-application-domain/generate-code');

    ws.onopen = function() {
      console.log('Connection established');
      document.getElementById('output').innerHTML += '<p>Connection established</p>';

      // Send a test message
      const payload = {
        "generatedCodeConfig": "html_tailwind",
        "inputMode": "image",
        "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        "generationType": "create"
      };

      ws.send(JSON.stringify(payload));
    };

    ws.onmessage = function(event) {
      console.log('Message from server:', event.data);
      document.getElementById('output').innerHTML += '<p>Received: ' + event.data + '</p>';
    };

    ws.onerror = function(error) {
      console.error('WebSocket error:', error);
      document.getElementById('output').innerHTML += '<p>Error: ' + JSON.stringify(error) + '</p>';
    };

    ws.onclose = function() {
      console.log('Connection closed');
      document.getElementById('output').innerHTML += '<p>Connection closed</p>';
    };
  </script>
</body>
</html>
```

2. Host this HTML file on a different domain than the target application
3. Open the HTML file in a browser while having an active session with the target application
4. Verify that the WebSocket connection is established and that the application responds to the message
5. Check if the application performs any validation of the WebSocket connection or if it processes the request without restriction

This test confirms the vulnerability if:
- The WebSocket connection is established successfully
- The application starts processing the code generation request
- The client receives messages back from the server

## Client-Side API Key Extraction

### Vulnerability Name
Client-Side API Key Extraction through WebSocket Communication

### Description
The application allows API keys (OpenAI, Anthropic, etc.) to be passed from the client-side settings dialog to the backend through WebSocket communication. This design creates a vulnerability where a malicious actor could extract these API keys if they gain access to the WebSocket traffic or can execute JavaScript in the context of the application.

Step by step exploitation:
1. The attacker intercepts WebSocket traffic (either through a compromised network, a malicious browser extension, or by exploiting a cross-site scripting vulnerability)
2. The attacker observes the WebSocket communication that contains the user's API keys
3. The attacker extracts these keys and can use them to access third-party APIs at the victim's expense

### Impact
This vulnerability could result in:
- Theft of API keys that provide access to paid services (OpenAI, Anthropic, etc.)
- Unauthorized usage of these services at the victim's expense
- Potential access to any content generated by the victim using these services
- Financial losses due to API usage charges

This is particularly severe because API keys typically don't have request-by-request authorization and can be used without additional verification once obtained.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The application explicitly supports getting API keys from the client-side settings dialog:

```python
def get_from_settings_dialog_or_env(
    params: dict[str, str], key: str, env_var: str | None
) -> str | None:
    value = params.get(key)
    if value:
        print(f"Using {key} from client-side settings dialog")
        return value

    if env_var:
        print(f"Using {key} from environment variable")
        return env_var

    return None
```

### Missing Mitigations
1. Server-side API key management only - don't accept API keys from clients
2. Implementation of a proxy service that makes API calls on behalf of users without exposing keys
3. Token-based authentication system where the server validates each request without passing API keys
4. Encryption of WebSocket traffic with client-specific keys
5. Session-based rate limiting to prevent excessive API usage

### Preconditions
- User must input their API keys in the client-side settings dialog
- Attacker must be able to intercept WebSocket traffic or execute JavaScript in the application context

### Source Code Analysis
In `backend/routes/generate_code.py`, the code extracts API keys from client parameters:

```python
def extract_params(
    params: Dict[str, str], throw_error: Callable[[str], Coroutine[Any, Any, None]]
) -> ExtractedParams:
    # ...
    openai_api_key = get_from_settings_dialog_or_env(
        params, "openAiApiKey", OPENAI_API_KEY
    )

    # If neither is provided, we throw an error later only if Claude is used.
    anthropic_api_key = get_from_settings_dialog_or_env(
        params, "anthropicApiKey", ANTHROPIC_API_KEY
    )
    # ...
```

This function calls `get_from_settings_dialog_or_env`, which prioritizes keys from the client:

```python
def get_from_settings_dialog_or_env(
    params: dict[str, str], key: str, env_var: str | None
) -> str | None:
    value = params.get(key)
    if value:
        print(f"Using {key} from client-side settings dialog")
        return value

    if env_var:
        print(f"Using {key} from environment variable")
        return env_var

    return None
```

The WebSocket endpoint receives these parameters containing API keys:

```python
@router.websocket("/generate-code")
async def stream_code(websocket: WebSocket):
    await websocket.accept()
    print("Incoming websocket connection...")

    # ...

    params: dict[str, str] = await websocket.receive_json()
    print("Received params")

    extracted_params = await extract_params(params, throw_error)
    stack = extracted_params.stack
    input_mode = extracted_params.input_mode
    openai_api_key = extracted_params.openai_api_key
    openai_base_url = extracted_params.openai_base_url
    anthropic_api_key = extracted_params.anthropic_api_key
    # ...
```

These API keys are then used directly to make API calls to the respective services.

### Security Test Case
1. Configure a proxy to intercept WebSocket traffic (like Burp Suite or mitmproxy)
2. Start the application and navigate to the settings dialog
3. Enter test API keys in the settings dialog
4. Trigger a code generation operation
5. Observe the WebSocket traffic using the proxy tool
6. Verify that the API keys are transmitted in plain text over the WebSocket connection:

Expected WebSocket message containing API keys:
```json
{
  "generatedCodeConfig": "html_tailwind",
  "inputMode": "image",
  "image": "data:image/png;base64,...",
  "generationType": "create",
  "openAiApiKey": "sk-test1234567890abcdefghijklmnopqrstuvwxyz",
  "anthropicApiKey": "sk-ant-test123456-abcdefghijklmnopqrstuvwxyz"
}
```

This test confirms the vulnerability if:
- The API keys are visible in the WebSocket traffic
- The keys are sent without encryption or obfuscation
- The same keys can be extracted and used to make API calls to the respective services
