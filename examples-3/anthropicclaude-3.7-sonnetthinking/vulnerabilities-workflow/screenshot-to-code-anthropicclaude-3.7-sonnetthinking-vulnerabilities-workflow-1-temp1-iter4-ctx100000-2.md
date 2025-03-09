# Security Vulnerabilities

## 1. Path Traversal in Evaluation Endpoints

### Vulnerability name
Directory Traversal / Path Traversal in Evaluation API Endpoints

### Description
The evaluation endpoints in `routes/evals.py` are vulnerable to path traversal attacks. An attacker can use these endpoints to traverse the filesystem and access arbitrary files on the server. Multiple endpoints are affected including `/evals`, `/pairwise-evals`, and `/best-of-n-evals`.

Steps to trigger the vulnerability:
1. Send a request to the `/evals` endpoint with a folder parameter containing path traversal sequences
2. Example: `/evals?folder=../../../etc/passwd`
3. The application takes this user input and directly uses it with `os.listdir()` without properly sanitizing or validating the path
4. The application attempts to read from this directory and returns any HTML files it finds
5. By carefully crafting the path, an attacker can navigate to sensitive directories and access files

### Impact
An attacker can read arbitrary files on the server that the application process has permission to access. This could include:
- Configuration files containing credentials
- API keys and secrets in environment files
- Sensitive system files
- User data and other private information

This gives attackers access to confidential information and potentially enables further attacks.

### Vulnerability rank
High

### Currently implemented mitigations
The application does check if the folder exists with `folder_path.exists()` before accessing it, but this doesn't prevent path traversal.

### Missing mitigations
The application should:
1. Implement path normalization and validation
2. Restrict access to a specific allowed directory (whitelist approach)
3. Use a security library for path sanitization
4. Implement proper authorization checks to ensure the user has permission to access the specified folder

### Preconditions
- The attacker must have access to the backend API endpoints
- No authentication or authorization checks are preventing access to these endpoints

### Source code analysis
In `routes/evals.py`, multiple endpoints handle folder paths insecurely:

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
```

The vulnerability stems from directly using the user-provided `folder` parameter with `os.listdir()` without proper sanitization. While there's a check to ensure the folder exists, this doesn't prevent traversal outside of intended directories.

Similarly, in `get_pairwise_evals` and `get_best_of_n_evals`, the code uses user-provided folder paths directly with `os.listdir()` and `os.path.join()` operations.

The file operations then combine the insecure base path with filenames, allowing read access to arbitrary files that match the file extension criteria.

### Security test case
1. Start the application and ensure the backend API is running
2. Create a temporary file somewhere in the filesystem (e.g., `/tmp/test-file.html`)
3. Use a tool like curl or a browser to access the endpoint with a path traversal sequence:
   ```
   curl http://localhost:7001/evals?folder=../../../tmp
   ```
4. Observe that the endpoint returns information about the test file from outside the intended directory
5. Try to access more sensitive locations like `/etc` or `/home` to demonstrate the severity
6. Document the files that can be accessed outside the intended directories

## 2. API Key Exposure Through Client Requests

### Vulnerability name
API Key Exposure Through Client-Side Transmission

### Description
The application accepts API keys (OpenAI, Anthropic, etc.) from client-side requests rather than securely storing them on the server. When a user calls the `/generate-code` WebSocket endpoint, they can provide API keys in the request parameters, which the server then uses to make requests to third-party services.

Steps to trigger vulnerability:
1. Connect to the WebSocket endpoint `/generate-code`
2. Send a JSON payload containing API keys in the parameters (`openAiApiKey`, `anthropicApiKey`)
3. The server extracts these keys from the request using the `get_from_settings_dialog_or_env` function
4. The keys are then used for API calls to external services

### Impact
This design creates several security risks:
- API keys transmitted over the network can be intercepted by attackers monitoring network traffic
- Keys may be exposed in browser history, logs, or debugging tools
- If there's any XSS vulnerability in the application, it could be used to steal API keys
- Users may unknowingly expose their personal API keys when using the application

An attacker who obtains these API keys could:
- Use them to make unauthorized requests to OpenAI, Anthropic, or other services
- Incur usage charges on the victim's account
- Access any data the victim has stored with these services

### Vulnerability rank
High

### Currently implemented mitigations
The application allows using environment variables as an alternative to client-provided keys, which is a more secure approach.

### Missing mitigations
1. Remove the ability to accept API keys from client requests
2. Store all API keys securely on the server (environment variables, secure vaults, etc.)
3. If client-specific keys must be used, implement a secure key management system with proper encryption
4. Add a proper authentication mechanism to ensure only authorized users can use the service

### Preconditions
- The application is deployed and accessible to users
- Users are expected to provide their own API keys through the client interface

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

These keys are then used directly to make API calls to external services. This design means that API keys are being transmitted from the client to the server, creating a security risk.

### Security test case
1. Set up a network traffic monitoring tool (like Wireshark or a proxy like Burp Suite)
2. Open the application in a browser
3. Enter an API key in the settings dialog
4. Submit a request for code generation
5. Observe the WebSocket traffic between the client and server
6. Verify that the API keys are visible in the request payload
7. Document how easily an attacker monitoring network traffic could extract these keys
