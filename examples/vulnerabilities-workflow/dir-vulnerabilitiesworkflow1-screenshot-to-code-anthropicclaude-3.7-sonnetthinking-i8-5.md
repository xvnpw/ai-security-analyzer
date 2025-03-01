# VULNERABILITIES

## Server-Side Request Forgery (SSRF) via OpenAI Base URL Configuration

### Vulnerability name
Server-Side Request Forgery (SSRF) via OpenAI Base URL Configuration

### Description
The application allows users to specify a custom base URL for OpenAI API requests through either an environment variable (`OPENAI_BASE_URL`) or through the settings dialog in the UI. According to the README, this feature is intended to help users who need to use a proxy to access OpenAI's API due to regional restrictions. However, the application passes this user-provided URL directly to the OpenAI client without proper validation or sanitization. This can be exploited to make the server send requests to arbitrary internal or external servers.

Steps to trigger the vulnerability:
1. Access the screenshot-to-code application
2. Navigate to the settings dialog (click the gear icon)
3. Set a malicious URL in the OpenAI base URL field, such as `http://internal-server.local:8080/v1` or `http://attacker-controlled-server.com/v1`
4. Submit a screenshot for processing
5. The application will make API requests to the specified URL, potentially accessing internal services or sending sensitive information to the attacker's server

### Impact
This vulnerability has severe impact because:
1. It allows attackers to scan and probe internal networks from the server, potentially discovering services not intended for public access
2. It could enable access to internal services that don't require authentication when accessed from within the network
3. API keys and other sensitive information might be leaked to attacker-controlled servers
4. The server could be used as a proxy to attack other systems, masking the attacker's identity
5. Attackers could exploit DNS rebinding to bypass protections and access internal services

### Vulnerability rank
High

### Currently implemented mitigations
There are no observed mitigations in the current codebase. The URL is retrieved from environment variables or UI settings and used directly without validation. In `generate_code.py`, there is a check to disable user-specified OpenAI Base URLs in production environments:

```python
# Disable user-specified OpenAI Base URL in prod
if not IS_PROD:
    openai_base_url = get_from_settings_dialog_or_env(
        params, "openAiBaseURL", OPENAI_BASE_URL
    )
```

However, this only prevents the vulnerability in production environments, not in development.

### Missing mitigations
1. Input validation to ensure the URL:
   - Uses HTTPS protocol only
   - Contains a valid domain or IP address (with restrictions on private IP ranges)
   - Matches a specific allowed pattern for legitimate OpenAI proxies
2. Implementation of a allowlist approach that only permits specific trusted domains
3. Blocking requests to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
4. Performing DNS resolution on the specified hostname and validating the resulting IP address
5. Setting timeouts and implementing retry limits for outgoing requests to prevent DoS conditions

### Preconditions
1. The attacker needs access to the application's UI settings dialog
2. The application needs to be configured to process screenshots with the OpenAI API
3. The server running the application needs to have access to internal services the attacker wishes to target
4. The application must be running in a non-production environment (where IS_PROD is False)

### Source code analysis
In `config.py` (referenced in previous analysis), the OpenAI base URL is loaded from an environment variable without validation.

In `generate_code.py`, the base URL is retrieved from either environment variables or user settings:
```python
# Disable user-specified OpenAI Base URL in prod
if not IS_PROD:
    openai_base_url = get_from_settings_dialog_or_env(
        params, "openAiBaseURL", OPENAI_BASE_URL
    )
```

The `get_from_settings_dialog_or_env` function prioritizes values from the client-side settings dialog:
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

This value is then passed directly to the OpenAI client without validation:
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

When a user provides a base URL, the OpenAI client will direct all API requests to that URL instead of the default OpenAI endpoint. If an attacker specifies an internal IP address or hostname in this field, the server will attempt to make requests to internal services that may not be accessible externally.

### Security test case
1. Set up the screenshot-to-code application locally following the instructions in the README
2. Run a simple HTTP server on your local machine on port 8080 with a path like `/v1/chat/completions` to mimic the OpenAI API endpoint: `python -m http.server 8080`
3. Access the UI application at http://localhost:5173
4. Click the gear icon to open the settings dialog
5. Enter `http://localhost:8080/v1` in the OpenAI base URL field
6. Save the settings
7. Upload a screenshot and submit it for processing with OpenAI models
8. Monitor the HTTP server logs to confirm that the application sends requests to your local server
9. Examine the request contents to verify if API keys or other sensitive information is included

A successful test will confirm the SSRF vulnerability by showing that the application makes requests to arbitrary servers specified by the user, potentially exposing sensitive information and allowing access to internal resources.

## Path Traversal in Evaluation Routes

### Vulnerability name
Path Traversal in Evaluation Routes

### Description
The application has multiple API endpoints in the evaluation routes (`/evals`, `/pairwise-evals`, and `/best-of-n-evals`) that accept folder paths as parameters. These paths are used to read files from the specified folders without proper validation to ensure they are within allowed directories. An attacker can exploit this by using path traversal sequences (like `../../../`) to access files from arbitrary locations on the server's filesystem.

Steps to trigger the vulnerability:
1. Access the application's API endpoint, for example: `/evals?folder=../../../etc`
2. The application will attempt to list files in the specified folder, traversing up the directory structure
3. If successful, the attacker can access files outside the intended directory scope
4. By iterating with different paths, an attacker could locate and access sensitive configuration files, credentials, or other private data

### Impact
This vulnerability has severe impact because:
1. It allows unauthorized access to files outside the intended application scope
2. Attackers could read sensitive system files, configuration files with credentials, or other private data
3. In some cases, it might reveal information that could facilitate further attacks
4. It potentially exposes the application's internal directory structure

### Vulnerability rank
High

### Currently implemented mitigations
The application performs existence checks on the specified folders but does not validate that they are within allowed boundaries:
```python
folder_path = Path(folder)
if not folder_path.exists():
    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

### Missing mitigations
1. Implementation of path normalization and validation to prevent directory traversal
2. Restricting access to a specific allowlist of directories
3. Using directory jails or chroot environments to contain file access
4. Implementing proper access controls to ensure users can only access authorized files
5. Converting relative paths to absolute paths and validating they are within allowed directories

### Preconditions
1. The attacker needs access to the evaluation endpoints of the application
2. The server process must have read permissions on the target files
3. The target files must be on the same filesystem as the application

### Source code analysis
In `evals.py`, the vulnerable code patterns appear in multiple places:

1. In the `/evals` endpoint:
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
        # Further processing of files
        # ...
```

2. In the `/pairwise-evals` endpoint:
```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(...),
    folder2: str = Query(...),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}

    # Get all HTML files from first folder
    files1 = {
        f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html")
    }
    # Further file operations
    # ...
```

3. In the `/best-of-n-evals` endpoint:
```python
@router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
async def get_best_of_n_evals(request: Request):
    # Extract all folder paths (folder1, folder2, folder3, etc.)
    folders = []
    i = 1
    while f"folder{i}" in query_params:
        folders.append(query_params[f"folder{i}"])
        i += 1

    # Validate folders exist
    for folder in folders:
        if not os.path.exists(folder):
            return {"error": f"Folder does not exist: {folder}"}

    # Further file operations on these folders
    # ...
```

In all these cases, the code:
1. Takes folder paths directly from user input
2. Checks only if the paths exist but not if they are within allowed directories
3. Uses these paths to list files and read their contents
4. Does not normalize or validate the paths to prevent directory traversal

This allows an attacker to use path traversal sequences to access files outside the intended directory scope.

### Security test case
1. Set up the screenshot-to-code application locally following the instructions in the README
2. Create a test file with recognizable content in a location outside the application's directory, e.g., `/tmp/test-file.html` with content `<html><body>Secret test content</body></html>`
3. Use a tool like curl to access the `/evals` endpoint with a path traversal sequence:
   ```
   curl -X GET "http://localhost:8000/evals?folder=../../../../tmp"
   ```
4. Observe the response to see if the endpoint returns information about files in the `/tmp` directory
5. If successful, attempt to access the test file's content:
   ```
   curl -X GET "http://localhost:8000/evals?folder=../../../../tmp"
   ```
6. Check if the response contains the secret test content, confirming that the application is vulnerable to path traversal

A successful test will confirm that the application allows access to files outside its intended directory scope through path traversal, potentially exposing sensitive information and system files.
