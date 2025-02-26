# VULNERABILITIES

## 1. Server-Side Request Forgery (SSRF) via Custom OpenAI Base URL

**Description:**
The application allows users to set a custom base URL for OpenAI API calls, which could be exploited to perform SSRF attacks. An attacker could potentially configure a malicious base URL that targets internal network services or unauthorized external services.

Step by step to trigger vulnerability:
1. Access the public instance of screenshot-to-code
2. Open the settings dialog via the gear icon in the UI
3. Set the OPENAI_BASE_URL to a malicious endpoint (e.g., http://internal-service.local/v1 or http://169.254.169.254/latest/meta-data/ to access AWS metadata)
4. Trigger any function that makes an OpenAI API call

**Impact:**
An attacker could cause the server to make requests to:
- Internal network resources not intended to be accessible
- AWS/GCP/Azure metadata services to extract cloud credentials
- Other sensitive endpoints that should not be accessible from the internet
This could lead to information disclosure, access to internal services, or even full server compromise in worst-case scenarios.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The README suggests that URLs should contain "v1" in the path, but there's no evidence in the current code that this is enforced. In routes/generate_code.py, there's a check for whether the application is running in production with `if not IS_PROD:` before retrieving the user-provided openAiBaseURL, which partially mitigates this in production.

**Missing Mitigations:**
1. Implement strict URL validation including whitelisting allowed domains
2. Implement proper URL sanitization
3. Add network-level controls to restrict outbound connections
4. Add pattern matching to ensure base URLs conform to expected patterns

**Preconditions:**
- Access to the settings dialog in the application
- The ability to submit a custom OpenAI base URL
- The application must be configured to accept custom base URLs
- In production, this vulnerability may be limited by the IS_PROD check

**Source Code Analysis:**
In `generate_code.py`, the application reads the OpenAI base URL from user input:
```python
# Base URL for OpenAI API
openai_base_url: str | None = None
# Disable user-specified OpenAI Base URL in prod
if not IS_PROD:
    openai_base_url = get_from_settings_dialog_or_env(
        params, "openAiBaseURL", OPENAI_BASE_URL
    )
```

Then this parameter is passed to the OpenAI client:
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

The base URL is also used in image generation:
```python
return await perform_image_generation(
    completion,
    should_generate_images,
    openai_api_key,
    openai_base_url,
    image_cache,
)
```

Without proper validation in non-production environments, an attacker could set this to any URL, including internal network resources.

**Security Test Case:**
1. Start a local HTTP server on port 8000 to capture requests
2. Access the screenshot-to-code application in non-production mode
3. In the settings dialog, set OPENAI_BASE_URL to `http://attacker-controlled-server.com:8000/v1`
4. Upload an image and request code generation
5. Verify that the backend application makes a request to the attacker-controlled server
6. Observe if any sensitive information (API keys, server information) is included in the request

## 2. Permissive CORS Policy Enabling Cross-Site Attacks

**Description:**
The application uses a wildcard CORS policy that allows requests from any origin, while also setting `allow_credentials=True`. This dangerous combination could enable cross-site request forgery (CSRF) attacks, as authenticated requests would be allowed from any domain.

Step by step to trigger vulnerability:
1. Find an endpoint in the application that performs a sensitive action
2. Create a malicious website that makes cross-origin requests to that endpoint
3. Trick a user who is authenticated to the application to visit the malicious website
4. The browser will include cookies/authentication information in the request due to `allow_credentials=True`

**Impact:**
This could allow attackers to perform actions on behalf of authenticated users, potentially accessing or modifying their data. An attacker could create a malicious website that, when visited by a user who is logged into the application, could make authenticated API calls to the application.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The current configuration is explicitly permissive.

**Missing Mitigations:**
1. Restrict CORS to specific trusted origins instead of using the wildcard "*"
2. If `allow_credentials=True` is necessary, then origins must be explicitly specified and cannot use wildcards
3. Implement CSRF tokens for sensitive operations
4. Add SameSite cookie attributes to limit cross-site request capabilities

**Preconditions:**
- The application uses cookie-based or session-based authentication
- Sensitive operations are exposed via API endpoints that accept cookies/sessions

**Source Code Analysis:**
In `main.py`, the CORS middleware is configured with the following dangerous combination:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This configuration allows requests from any origin (`allow_origins=["*"]`) and includes credentials (`allow_credentials=True`). According to CORS security guidelines, these settings should never be used together because they allow any website to make authenticated requests to the API.

**Security Test Case:**
1. Create a test HTML page on a different domain with the following JavaScript:
```javascript
fetch('https://screenshot-to-code-instance.com/api/endpoint', {
  method: 'POST',
  credentials: 'include', // This includes cookies
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ data: 'test' })
})
.then(response => response.json())
.then(data => console.log(data));
```
2. Host this page on a different domain
3. Log into the screenshot-to-code application
4. Visit the test page from step 1
5. Observe if the request succeeds and credentials are sent
6. Check the network tab to confirm that the request was not blocked by CORS

## 3. Unvalidated File Paths in Debug File Writer

**Description:**
The `DebugFileWriter` class writes debug information to paths specified by an environment variable without proper validation or sanitization. If an attacker can control or influence this environment variable, they could potentially perform path traversal attacks.

Step by step to trigger vulnerability:
1. An attacker would need to find a way to modify the `DEBUG_DIR` environment variable
2. Set it to a path containing path traversal sequences (e.g., `../../../some/sensitive/directory`)
3. Trigger debug logging functionality in the application

**Impact:**
If exploitable, this could lead to:
- Writing files to unauthorized locations on the filesystem
- Potential information disclosure
- Overwriting system files or application files if the process has sufficient permissions

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
Debug mode must be explicitly enabled via the `IS_DEBUG_ENABLED` environment variable, reducing the likelihood of exploitation in production.

**Missing Mitigations:**
1. Path sanitization to remove path traversal sequences
2. Strict validation of the `DEBUG_DIR` to ensure it's a safe directory
3. Use of absolute paths to prevent relative path traversal
4. Filesystem permission restrictions on write operations

**Preconditions:**
- Debug mode must be enabled (`IS_DEBUG_ENABLED=True`)
- Attacker must be able to influence the `DEBUG_DIR` environment variable
- The application process must have write permissions to the target directories

**Source Code Analysis:**
In `debug/DebugFileWriter.py`, the class initializes with a path from the environment:
```python
self.debug_artifacts_path = os.path.expanduser(
    f"{DEBUG_DIR}/{str(uuid.uuid4())}"
)
os.makedirs(self.debug_artifacts_path, exist_ok=True)
```

Later, it writes files to this path without validation:
```python
def write_to_file(self, filename: str, content: str) -> None:
    try:
        with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
            file.write(content)
    except Exception as e:
        logging.error(f"Failed to write to file: {e}")
```

If an attacker could control `DEBUG_DIR`, they could set it to a value like `../../../etc` to potentially write files to sensitive system directories.

**Security Test Case:**
1. Set the environment variable to a path containing path traversal sequences:
   ```
   DEBUG_DIR="../../../tmp" IS_DEBUG_ENABLED=True python3 backend/start.py
   ```
2. Trigger debug logging functionality (upload an image and generate code)
3. Verify if files are created in the `/tmp` directory instead of the intended debug directory
4. Try different traversal sequences to attempt writing to various system directories
5. Check if the application restricts writing to unauthorized locations

## 4. Unfiltered Image Generation Prompts

**Description:**
The application allows users to provide prompts for image generation through DALL-E 3 or Flux Schnell without any content filtering or validation. An attacker could submit prompts designed to generate inappropriate, offensive, or potentially harmful images.

Step by step to trigger vulnerability:
1. Access the public instance of screenshot-to-code
2. Use the image generation feature
3. Submit a prompt designed to bypass content filters of the underlying AI models
4. The application passes the prompt directly to the external API without modification or filtering

**Impact:**
This could lead to:
- Generation of inappropriate or offensive images
- Potential legal issues for the application provider
- Reputational damage
- In extreme cases, generated images could contain deceptive content that leads to further attacks

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None visible in the code. The prompts are passed directly to the external APIs without any filtering or validation.

**Missing Mitigations:**
1. Implement content filtering for user-provided prompts
2. Add prompt validation against a blocklist of problematic terms
3. Implement rate limiting to prevent abuse
4. Add human review for certain prompts flagged as potentially problematic

**Preconditions:**
- Access to the image generation feature in the application
- Valid API keys for the image generation services

**Source Code Analysis:**
In `image_generation/core.py`, prompts are passed directly to the external APIs without any filtering:

```python
async def generate_image_dalle(
    prompt: str, api_key: str, base_url: str | None
) -> Union[str, None]:
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    res = await client.images.generate(
        model="dall-e-3",
        quality="standard",
        style="natural",
        n=1,
        size="1024x1024",
        prompt=prompt,  # No validation or filtering
    )
    await client.close()
    return res.data[0].url

async def generate_image_replicate(prompt: str, api_key: str) -> str:
    # We use Flux Schnell
    return await call_replicate(
        {
            "prompt": prompt,  # No validation or filtering
            "num_outputs": 1,
            "aspect_ratio": "1:1",
            "output_format": "png",
            "output_quality": 100,
        },
        api_key,
    )
```

There is no content filtering, prompt validation, or any other form of checking before sending the prompts to the external APIs.

**Security Test Case:**
1. Access the screenshot-to-code application
2. Navigate to the image generation feature
3. Submit a prompt designed to test content filtering boundaries (e.g., "Generate an image of instructions for creating a harmful substance")
4. Observe if the prompt is sent unmodified to the external API
5. Check if any content filtering or validation mechanisms are triggered
6. Verify if the application implements any rate limiting to prevent abuse

## 5. SSRF via Screenshot Service

**Description:**
The application includes a screenshot service that accepts a user-provided URL and forwards it to an external screenshot service (screenshotone.com) without proper validation or sanitization. This could enable an attacker to perform SSRF attacks by providing URLs that point to internal network resources or malicious endpoints.

Step by step to trigger vulnerability:
1. Access the screenshot-to-code application
2. Call the `/api/screenshot` endpoint with a malicious URL pointing to an internal service (e.g., `http://10.0.0.1:8080/admin`)
3. The application forwards this URL to the screenshot service
4. The service attempts to access the internal resource, potentially revealing information about it

**Impact:**
This vulnerability could allow attackers to:
- Scan internal networks to discover services
- Access internal services not meant to be public
- Retrieve sensitive information from internal endpoints
- Potentially exploit vulnerabilities in internal services
- Perform port scanning or service fingerprinting through the screenshot service

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The URL is passed directly to the screenshot service without validation.

**Missing Mitigations:**
1. Implement URL validation to ensure only public, expected domains are allowed
2. Use a URL allowlist for permitted domains
3. Block requests to private IP ranges, localhost, and internal domains
4. Add rate limiting to prevent abuse

**Preconditions:**
- Access to the screenshot API endpoint
- A valid API key for the screenshot service

**Source Code Analysis:**
In `routes/screenshot.py`, the application receives a URL from the user and passes it directly to the screenshot service:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)
```

The `capture_screenshot` function takes this URL and includes it in the request to the external service:

```python
async def capture_screenshot(
    target_url: str, api_key: str, device: str = "desktop"
) -> bytes:
    api_base_url = "https://api.screenshotone.com/take"

    params = {
        "access_key": api_key,
        "url": target_url,  # No validation or sanitization
        # ...other parameters...
    }
```

There is no validation or sanitization of the URL before it's passed to the external service.

**Security Test Case:**
1. Set up a listener on a publicly accessible server to capture incoming requests
2. Make a POST request to `/api/screenshot` with the following payload:
   ```json
   {
     "url": "http://your-listener-server.com/capture",
     "apiKey": "valid-api-key"
   }
   ```
3. Verify that the screenshot service makes a request to your listener server
4. Try URLs pointing to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
5. Try accessing cloud metadata services (e.g., http://169.254.169.254/)
6. Monitor if the screenshot service can access these internal resources
7. Check if any information from internal services is included in the response
