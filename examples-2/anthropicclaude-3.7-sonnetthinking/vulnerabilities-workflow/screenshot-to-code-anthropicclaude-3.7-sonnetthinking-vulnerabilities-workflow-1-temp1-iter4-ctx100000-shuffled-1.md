# Vulnerabilities

## 1. Path Traversal in Evals API Endpoints

### Vulnerability name
Path Traversal in Evals API Endpoints

### Description
The application has several endpoints in the `/evals` API that accept arbitrary folder paths from user input without proper validation or path sanitization. An attacker can use directory traversal sequences (such as `../`) to access files and directories outside the intended directory structure.

Steps to trigger the vulnerability:
1. Identify the endpoints that accept folder parameters: `/evals`, `/pairwise-evals`, and `/best-of-n-evals`
2. Send a request with a crafted folder path that contains directory traversal sequences
3. The application will access the specified directory, which could be anywhere on the filesystem where the server has read permissions

For example, in the `/evals` endpoint:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    # Uses user-provided folder path without sanitization
    files = {
        f: os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".html")
    }
```

Similar vulnerable code exists in the `/pairwise-evals` and `/best-of-n-evals` endpoints.

### Impact
This vulnerability allows attackers to:
- Read sensitive configuration files including API keys and other credentials
- Access application code, logs, and database files
- Read system files that might contain sensitive information
- Map the server's directory structure and gather information for further attacks

### Vulnerability rank
Critical

### Currently implemented mitigations
The only mitigation is a check that the folder exists, but this does not prevent path traversal.

### Missing mitigations
- Input validation to restrict folder paths to specific allowed directories
- Path sanitization to prevent traversal sequences
- Use of secure file access libraries that prevent path traversal
- Implementation of a secure file access abstraction layer

### Preconditions
- The attacker needs access to the evals API endpoints
- The server must be running with permissions to access files beyond the intended directory

### Source code analysis
In `backend/routes/evals.py`, we see multiple endpoints that accept folder paths:

1. In the `/evals` endpoint:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

The code only checks if the folder exists, but doesn't validate if it's within an allowed directory. It then uses `os.listdir(folder)` directly on the user-provided path.

2. Similar issues exist in the `/pairwise-evals` endpoint:
```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(...),
    folder2: str = Query(...),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
```

3. And in the `/best-of-n-evals` endpoint:
```python
@router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
async def get_best_of_n_evals(request: Request):
    # Get all query parameters
    query_params = dict(request.query_params)

    # Extract all folder paths (folder1, folder2, folder3, etc.)
    folders = []
    i = 1
    while f"folder{i}" in query_params:
        folders.append(query_params[f"folder{i}"])
        i += 1
```

In all these cases, the application takes a folder path from user input and uses it directly in file system operations without sanitizing or restricting the path.

### Security test case
1. Start by setting up the application locally.
2. Send a GET request to the `/evals` endpoint with a folder path that traverses outside the application directory:
   ```
   GET /evals?folder=../../../etc
   ```
3. Observe that the application returns contents from a sensitive system directory.
4. Test path traversal on other endpoints as well:
   ```
   GET /pairwise-evals?folder1=../../../etc&folder2=../../../var
   GET /best-of-n-evals?folder1=../../../etc&folder2=../../../var
   ```
5. Verify that these requests allow access to files outside the intended directory structure.

## 2. Server-Side Request Forgery (SSRF) in Screenshot API

### Vulnerability name
Server-Side Request Forgery in Screenshot API

### Description
The `/api/screenshot` endpoint allows users to provide an arbitrary URL to be captured by a screenshot service. This functionality exposes the application to Server-Side Request Forgery (SSRF) attacks, where an attacker can make the server issue requests to arbitrary destinations, potentially including internal services not meant to be publicly accessible.

Steps to trigger vulnerability:
1. Send a POST request to the `/api/screenshot` endpoint
2. Include a malicious URL in the request body that points to internal services, sensitive endpoints, or malicious sites
3. The server will make a request to the provided URL through the screenshot service

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)
```

The URL is passed to an external screenshot service without proper validation:

```python
async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
    api_base_url = "https://api.screenshotone.com/take"
    params = {
        "access_key": api_key,
        "url": target_url,
        # other parameters...
    }
    # Make the request to the screenshot service
```

### Impact
This vulnerability could allow attackers to:
- Access internal services and resources that should not be publicly accessible
- Bypass network security controls by using the server as a proxy
- Perform reconnaissance of internal infrastructure
- Potentially exploit vulnerabilities in the screenshot service or the target URL
- In some cases, access sensitive information through error messages or timing attacks

### Vulnerability rank
High

### Currently implemented mitigations
None. The code has a TODO comment for error handling, but no URL validation is implemented.

### Missing mitigations
- URL validation to ensure only safe, external URLs are allowed
- Allowlist of permitted domains
- Blocklist of dangerous IP ranges (internal IP ranges, localhost, etc.)
- Rate limiting to prevent abuse
- Proper error handling that doesn't leak sensitive information

### Preconditions
- Access to the `/api/screenshot` API endpoint
- Valid API key for the screenshotone.com service

### Source code analysis
The vulnerability is present in `backend/routes/screenshot.py`:

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

The `capture_screenshot` function:

```python
async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
    api_base_url = "https://api.screenshotone.com/take"

    params = {
        "access_key": api_key,
        "url": target_url,
        "full_page": "true",
        "device_scale_factor": "1",
        "format": "png",
        # Other parameters...
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
        if response.status_code == 200 and response.content:
            return response.content
        else:
            raise Exception("Error taking screenshot")
```

The code accepts any URL without validation and passes it to the external screenshot service. While the request is made to an external service (screenshotone.com) rather than directly to the target URL, this still constitutes an SSRF vulnerability as the application is making server-side requests to arbitrary URLs provided by users.

### Security test case
1. Set up the application locally with a valid screenshotone.com API key.
2. Send a POST request to the `/api/screenshot` endpoint with a URL pointing to an internal resource:
   ```
   POST /api/screenshot
   {
     "url": "http://localhost:8080/admin",
     "apiKey": "your-api-key"
   }
   ```
3. Also test with URLs to other internal services that might be accessible from the server:
   ```
   POST /api/screenshot
   {
     "url": "http://10.0.0.1:8080",
     "apiKey": "your-api-key"
   }
   ```
4. Verify that the server attempts to capture screenshots of these internal resources.
5. Test with a URL to a server you control and monitor for incoming requests to confirm the SSRF vulnerability.

## 3. Insecure API Key Handling

### Vulnerability name
Insecure API Key Handling

### Description
The application allows users to provide their own OpenAI, Anthropic, and other API keys through the frontend interface. These keys are then sent to the backend and used for API calls. The keys are not properly secured during transmission or storage, potentially allowing attackers to intercept or steal these API keys.

Steps to trigger vulnerability:
1. Monitor WebSocket traffic between the frontend and backend
2. Identify requests to the `/generate-code` WebSocket endpoint
3. Extract API keys from the WebSocket messages
4. Use the stolen API keys to make unauthorized API calls, potentially incurring charges to the victim's account

For example, in the generate_code.py, API keys are extracted from user-provided parameters:
```python
openai_api_key = get_from_settings_dialog_or_env(
    params, "openAiApiKey", OPENAI_API_KEY
)

anthropic_api_key = get_from_settings_dialog_or_env(
    params, "anthropicApiKey", ANTHROPIC_API_KEY
)
```

These keys are then used for making API calls to external services.

### Impact
This vulnerability could lead to:
- Theft of users' API keys
- Unauthorized usage of victims' API accounts resulting in financial losses
- Access to any data or capabilities provided by those API services
- Potential exposure of sensitive information processed by these APIs

### Vulnerability rank
High

### Currently implemented mitigations
The application does use environment variables as a fallback for API keys, which is more secure than always requiring user input.

### Missing mitigations
- Server-side API key storage with token-based authentication for users
- Encryption of API keys in transit (beyond HTTPS)
- Secure storage of API keys if they need to be persisted
- Implementation of a proxy service to make API calls without exposing keys to clients
- Rate limiting and monitoring for suspicious activity

### Preconditions
- The attacker must be able to intercept network traffic between the user and server
- Or have access to compromised client-side storage if keys are saved there
- Users must provide their own API keys through the interface

### Source code analysis
In `backend/routes/generate_code.py`, the application extracts API keys from user-provided parameters:

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

The API keys are later used in API calls:

```python
if model == Llm.GPT_4O_2024_11_20 or model == Llm.O1_2024_12_17:
    if openai_api_key is None:
        await throw_error("OpenAI API key is missing.")
        raise Exception("OpenAI API key is missing.")

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

The WebSocket communication channel doesn't show any special handling for sensitive data like API keys, which are likely being transmitted in plaintext (though potentially over HTTPS).

### Security test case
1. Set up the application locally.
2. Using browser developer tools or a proxy like Burp Suite, monitor WebSocket traffic between the frontend and backend.
3. Add an API key in the frontend settings dialog (e.g., for OpenAI).
4. Initiate a code generation request.
5. Examine the WebSocket messages sent to the `/generate-code` endpoint.
6. Verify that you can see the API key in plaintext in the messages.
7. Extract the API key and confirm it works by making a test API call directly to OpenAI's API.

## 4. Potential Remote Code Execution via AI-Generated Code Evaluation

### Vulnerability name
Potential Remote Code Execution via AI-Generated Code Evaluation

### Description
The application generates code (HTML, CSS, JavaScript) based on user input (screenshots, descriptions, etc.) using AI models and then displays/evaluates this code. There's no validation or sandboxing of the generated code before it's executed or displayed to users. This creates a risk where an attacker could craft input that leads the AI to generate malicious JavaScript code.

Steps to trigger vulnerability:
1. Create an input (image, text prompt) carefully designed to manipulate the AI model
2. Submit this input to the code generation endpoint
3. The AI generates JavaScript code containing malicious elements (XSS payloads, event handlers, etc.)
4. When the generated code is displayed or executed, it could access cookies, steal data, or perform other malicious actions

### Impact
This vulnerability could lead to:
- Cross-site scripting (XSS) attacks when viewing generated code
- Data theft from the application or user's browser
- Session hijacking
- Remote code execution within the browser context
- Potential for escalation to server-side vulnerabilities if combined with other exploits

### Vulnerability rank
High

### Currently implemented mitigations
None. The application doesn't appear to sanitize or validate the AI-generated code before displaying or executing it.

### Missing mitigations
- Content Security Policy (CSP) implementation
- Sanitization of AI-generated code before execution
- Sandboxing of code execution environments
- Validation of generated code against known malicious patterns
- Preview mode with security warnings

### Preconditions
- Attacker must be able to craft inputs that manipulate the AI into generating malicious code
- Application must execute or render the generated code without proper sandboxing

### Source code analysis
The issue spans multiple components of the application. In `backend/routes/generate_code.py`, the application generates code and returns it to the client:

```python
# Strip the completion of everything except the HTML content
completions = [extract_html_content(completion) for completion in completions]
```

```python
for index, updated_html in enumerate(updated_completions):
    await send_message("setCode", updated_html, index)
    await send_message("status", "Code generation complete.", index)
```

The extract_html_content function in `backend/codegen/utils.py` doesn't perform any security filtering:

```python
def extract_html_content(text: str):
    # Use regex to find content within <html> tags and include the tags themselves
    match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
    if match:
        return match.group(1)
    else:
        # Otherwise, we just send the previous HTML over
        print(
            "[HTML Extraction] No <html> tags found in the generated content: " + text
        )
        return text
```

There's no evidence of sanitization or validation of the generated code. The frontend likely renders this HTML/JavaScript directly, potentially executing any scripts contained in it.

### Security test case
1. Set up the application locally.
2. Create a specially crafted prompt designed to manipulate the AI model, such as:
   ```
   Generate a simple webpage with a script that shows an alert with the document.cookie
   ```
3. Submit this prompt to the code generation endpoint.
4. Examine the generated code to confirm it contains potentially malicious JavaScript.
5. When the code is displayed/executed, verify that the JavaScript executes and can access sensitive browser data.
6. Try more complex payloads that attempt to:
   - Make network requests to external domains
   - Access localStorage or sessionStorage
   - Modify DOM elements
   - Execute eval() with dynamic content
