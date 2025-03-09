# Security Vulnerabilities in Screenshot-to-Code

## 1. Path Traversal Vulnerability in Evals Routes

### Description
The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in the backend API accept folder paths as parameters without proper path validation or sanitization. An attacker can exploit this to traverse the directory structure and access sensitive files outside the intended directories.

### Impact
**Critical**. This vulnerability allows attackers to read arbitrary files on the server's filesystem to which the application has access. This could lead to exposure of sensitive configuration files (including API keys), system files, and potentially other confidential data.

### Currently implemented mitigations
The code includes basic validation to check if the folder exists but does not prevent path traversal attacks.

### Missing mitigations
- Path normalization and validation
- Restriction to specific allowed directories
- Sanitization of user-supplied path parameters

### Preconditions
- Attacker needs access to the backend API endpoints
- No authentication is required to access these endpoints

### Source code analysis
In `routes/evals.py`, several endpoints accept folder paths directly from user input:

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

The vulnerability is also present in the `get_pairwise_evals` endpoint:

```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(..., description="Absolute path to first folder"),
    folder2: str = Query(..., description="Absolute path to second folder"),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
```

The application directly uses these folder paths with `os.path.join()` and `os.listdir()` without restricting the paths to a specific directory. This allows an attacker to provide paths like `../../../etc` to access files in unauthorized locations.

### Security test case
1. Identify the `/evals` endpoint in the backend
2. Create a GET request to `/evals?folder=../../../etc`
3. Observe if the server returns file listings from the `/etc` directory
4. If successful, create a similar request to access sensitive files like `/etc/passwd` or configuration files containing API keys

## 2. Server-Side Request Forgery (SSRF) in Screenshot Endpoint

### Description
The `/api/screenshot` endpoint takes a user-supplied URL and forwards it to an external screenshot service without adequate validation. This allows an attacker to make the server initiate requests to arbitrary hosts, including internal network resources.

### Impact
**High**. This vulnerability allows attackers to:
- Scan internal networks
- Access services on the internal network that aren't accessible from the internet
- Potentially bypass firewall restrictions

### Currently implemented mitigations
None. The endpoint simply forwards the user-supplied URL to the screenshot service without validation.

### Missing mitigations
- URL validation to allow only public web addresses
- Deny requests to private IP ranges, localhost, and internal hostnames
- Rate limiting to prevent abuse

### Preconditions
- Access to the `/api/screenshot` API endpoint
- A valid API key for the screenshot service (required parameter)

### Source code analysis
In `routes/screenshot.py`, the application takes a URL from the request body and passes it directly to a screenshot service:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)
```

The `capture_screenshot` function then uses this URL without validation:

```python
async def capture_screenshot(
    target_url: str, api_key: str, device: str = "desktop"
) -> bytes:
    api_base_url = "https://api.screenshotone.com/take"

    params = {
        "access_key": api_key,
        "url": target_url,
        # ...
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
```

An attacker could supply internal network addresses like `http://192.168.1.1`, `http://localhost:8080`, or internal hostnames to probe the network.

### Security test case
1. Identify the `/api/screenshot` endpoint in the backend
2. Create a POST request with:
   ```json
   {"url": "http://localhost:7001", "apiKey": "valid-api-key"}
   ```
3. Observe if the server returns a screenshot of the backend service itself
4. Test with various internal IP addresses and ports to map the internal network

## 3. Permissive CORS Configuration

### Description
The application's CORS configuration allows requests from any origin (`"*"`) and includes credentials. This overly permissive configuration could allow malicious websites to make cross-origin requests to the API with the user's authentication credentials.

### Impact
**High**. This vulnerability could enable cross-site request forgery (CSRF) attacks, allowing malicious websites to make authenticated requests to the API on behalf of users who visit the attacker's site.

### Currently implemented mitigations
None. The CORS configuration is completely permissive.

### Missing mitigations
- Restriction of allowed origins to trusted domains
- Removal of `allow_credentials=True` if wildcard origins are necessary
- Implementation of CSRF tokens for sensitive operations

### Preconditions
- The backend service must be publicly accessible
- User must visit a malicious website while logged into the application

### Source code analysis
In `main.py`, the CORS middleware is configured with the following settings:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This configuration allows any website to make cross-origin requests to the API, including credentials (cookies, HTTP authentication). According to CORS security best practices, using `allow_origins=["*"]` with `allow_credentials=True` is especially dangerous.

### Security test case
1. Create a malicious HTML page with JavaScript that makes a fetch request to the backend API
2. Include credentials in the request: `fetch('http://backend-server:7001/generate-code', {credentials: 'include'})`
3. Host this page on a different domain
4. When a user who is authenticated to the backend visits this page, the malicious script can make authenticated requests to the API
5. Verify that the request succeeds despite coming from a different origin

## 4. Exposure of API Keys via WebSocket Communication

### Description
The application handles API keys (OpenAI, Anthropic, etc.) via WebSocket communication, potentially exposing these keys to man-in-the-middle attacks or browser extensions.

### Impact
**High**. Exposure of API keys could lead to unauthorized usage of paid API services, potentially resulting in significant financial loss.

### Currently implemented mitigations
The application attempts to use environment variables first before falling back to user-provided keys.

### Missing mitigations
- Server-side encryption of API keys
- Token-based proxy system to avoid sending raw API keys to the frontend
- Secure session handling for API keys

### Preconditions
- User must provide API keys through the settings dialog
- Attacker must be able to intercept WebSocket communication or access browser storage

### Source code analysis
In `routes/generate_code.py`, the application accepts API keys from the WebSocket connection:

```python
openai_api_key = get_from_settings_dialog_or_env(
    params, "openAiApiKey", OPENAI_API_KEY
)

anthropic_api_key = get_from_settings_dialog_or_env(
    params, "anthropicApiKey", ANTHROPIC_API_KEY
)
```

These keys are then used directly for API calls:

```python
tasks.append(
    stream_openai_response(
        prompt_messages,
        api_key=openai_api_key,
        base_url=openai_base_url,
        callback=lambda x, i=index: process_chunk(x, i),
        model=model,
    )
)
```

This approach exposes the raw API keys to potential interception in transit or by malicious browser extensions.

### Security test case
1. Open the application in a browser
2. Add API keys via the settings dialog
3. Use browser developer tools to monitor WebSocket communication
4. Verify that API keys are visible in plaintext in the WebSocket messages
5. Check if these keys are also stored in browser localStorage or sessionStorage
