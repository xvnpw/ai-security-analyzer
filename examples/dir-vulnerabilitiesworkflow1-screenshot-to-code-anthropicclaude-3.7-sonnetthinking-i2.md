# VULNERABILITIES

## Server-Side Request Forgery (SSRF) via Configurable OpenAI Base URL

The application allows users to configure a custom OpenAI base URL through the UI settings or environment variables. This URL is passed directly to the OpenAI client without proper validation, which can allow attackers to specify arbitrary URLs and trigger server-side requests to internal resources or unauthorized external services.

### Description
To trigger this vulnerability:
1. Access the publicly available instance of the application
2. Navigate to the settings dialog (gear icon)
3. Enter a malicious URL in the OpenAI base URL field (e.g., http://internal-service.local:8080)
4. Submit the form
5. Trigger an action that uses the OpenAI API

The application will make requests to the specified URL when attempting to communicate with OpenAI's API.

### Impact
This vulnerability allows attackers to:
- Probe and scan internal network services that shouldn't be accessible from the internet
- Access and potentially exploit internal systems by leveraging the server's trust relationship
- Exfiltrate data from internal services
- Potentially bypass firewall and network security measures
- Conduct attacks against arbitrary external services using the server as a proxy

### Vulnerability Rank
High

### Currently Implemented Mitigations
There is a partial mitigation for production environments:
```python
# Disable user-specified OpenAI Base URL in prod
if not IS_PROD:
    openai_base_url = get_from_settings_dialog_or_env(
        params, "openAiBaseURL", OPENAI_BASE_URL
    )
```

This disables user-specified base URLs in production environments but still allows custom base URLs in development environments.

### Missing Mitigations
1. Validate the OPENAI_BASE_URL against a whitelist of allowed domains
2. Implement network-level protections to prevent connections to internal services
3. Use a proxy service for all external API calls with its own validation mechanisms
4. Input sanitization to prevent malformed or malicious URLs

### Preconditions
- The attacker must have access to the application's UI settings
- The application must be running in a non-production environment (based on IS_PROD flag)
- The server running the application must have network access to the targeted internal or external resources

### Source Code Analysis
Looking at the code flow in `routes/generate_code.py`:

1. The application gets the OpenAI base URL from user settings or environment variables:
```python
openai_base_url = get_from_settings_dialog_or_env(
    params, "openAiBaseURL", OPENAI_BASE_URL
)
```

2. This URL is passed directly to the OpenAI client without validation:
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

3. Inside the `stream_openai_response` function, the base URL is used to create the OpenAI client:
```python
client = AsyncOpenAI(api_key=api_key, base_url=base_url)
```

When a user initiates an action that uses the OpenAI API, the application will make HTTP requests to whatever URL is specified in the base_url parameter, allowing attackers to target arbitrary hosts.

### Security Test Case
To verify this vulnerability:

1. Set up a local instance of the screenshot-to-code application in development mode
2. Set up a simple HTTP server on a different port (e.g., using Python: `python -m http.server 8081`)
3. In the application settings, set the OpenAI base URL to `http://localhost:8081`
4. Upload a screenshot and trigger code generation
5. Observe your HTTP server logs to confirm it receives requests from the application

If the HTTP server logs show incoming requests that were intended for the OpenAI API, the vulnerability is confirmed. The application is making requests to an arbitrary URL specified by the user without proper validation.

## Cross-Site Scripting (XSS) via HTML Code Generation and Preview

The application generates HTML code based on user-provided screenshots, designs, or imported code and then renders this code in the browser preview. Since the application is designed to generate functional code including JavaScript, the generated code is executed when displayed in the preview area.

### Description
To trigger this vulnerability:
1. Craft a screenshot or design that contains elements which might prompt the AI to generate JavaScript code with malicious functionality
2. Upload the crafted image to the application
3. The AI generates code which includes the malicious JavaScript
4. The code is executed in the browser when displayed in the preview pane

### Impact
An attacker could:
- Execute arbitrary JavaScript in the context of other users' browsers
- Steal sensitive information such as API keys entered in the settings
- Perform actions on behalf of other users
- Redirect users to phishing sites
- Install client-side malware or cryptominers

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The application is specifically designed to generate and execute HTML and JavaScript code.

### Missing Mitigations
1. Content Security Policy (CSP) to restrict what resources can be loaded and executed
2. Sandboxing the preview iframe with appropriate restrictions
3. Validation and sanitization of AI-generated code before rendering
4. Warning users about the risks of executing generated code

### Preconditions
- The attacker must be able to influence what content is processed by the AI model
- The victim must view the generated code in the application's preview pane

### Source Code Analysis
The application takes user input (screenshots, designs, or imported code) and sends it to AI models to generate HTML, CSS, and JavaScript code. This generated code is then displayed in the browser where it is executed.

From the project's structure and purpose, specifically in `routes/generate_code.py`:

1. The application takes user-provided images or designs
2. It processes these inputs through AI models to generate code
3. The generated code is sent back to the frontend via WebSocket:
```python
for index, updated_html in enumerate(updated_completions):
    await send_message("setCode", updated_html, index)
    await send_message("status", "Code generation complete.", index)
```

4. Since the application is specifically designed to create functional websites with interactive elements, this code includes JavaScript that is executed when rendered

Since the AI model could potentially generate harmful code (either by being explicitly manipulated or through unexpected behaviors), and this code is executed in the browser, this creates an XSS risk.

### Security Test Case
To verify this vulnerability:

1. Create an image containing visual elements that suggest a website with interactive JavaScript (e.g., a form with buttons, counters, etc.)
2. Upload this image to the application
3. Examine the generated code for any JavaScript functions
4. Modify the generated code to include a simple test alert: `<script>alert('XSS Test')</script>`
5. If the alert executes in the preview pane, this confirms that arbitrary JavaScript can be executed

For a more advanced test, try to craft an image that would suggest to the AI to include JavaScript event handlers or scripts that could access cookies or perform other sensitive operations, and see if the generated code includes these elements and if they execute.

## Path Traversal in Evaluation Routes

The application allows users to specify arbitrary file paths in several API endpoints in the evaluation routes. These paths are used directly to read files from the filesystem without proper validation or path normalization.

### Description
To trigger this vulnerability:
1. Access the publicly available API endpoints in `routes/evals.py`
2. Provide a path parameter that uses path traversal sequences (e.g., `../../../etc/passwd`)
3. The application will attempt to read files from this path
4. If successful, the contents of sensitive files can be exposed to the attacker

### Impact
This vulnerability allows attackers to:
- Read sensitive files from the server's filesystem
- Access configuration files containing API keys or credentials
- Obtain information about the server's internal structure
- Potentially get access to user data or business logic files
- Escalate the attack by discovering additional vulnerabilities through exposed code

### Vulnerability Rank
High

### Currently Implemented Mitigations
The application performs existence checks on paths but does not restrict where these paths can point:
```python
folder_path = Path(folder)
if not folder_path.exists():
    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

### Missing Mitigations
1. Path validation to ensure paths are within allowed directories
2. Path normalization to resolve and check for directory traversal attempts
3. Restricting file access to specific directories using a whitelist approach
4. Implementing proper access controls for file operations

### Preconditions
- The attacker must have access to the API endpoints
- The application must be running with sufficient filesystem permissions to access the targeted files

### Source Code Analysis
In `routes/evals.py`, several endpoints take folder paths directly from user input:

1. The `/evals` endpoint takes a folder parameter with no path validation beyond checking existence:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    # ...proceeds to read files from this folder
```

2. The `/pairwise-evals` endpoint has even more concerning default values:
```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(
        "...",
        description="Absolute path to first folder",
    ),
    folder2: str = Query(
        "..",
        description="Absolute path to second folder",
    ),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
```

The default values are `"..."` and `".."` which are parent directories, and the description even specifies "Absolute path" encouraging users to provide full paths.

In all these cases, the application reads files from these paths without validating that they are within allowed directories, creating a path traversal vulnerability.

### Security Test Case
To verify this vulnerability:

1. Identify a sensitive file on the system that should not be accessible (e.g., `/etc/passwd` on Linux)
2. Craft a path traversal request to one of the vulnerable endpoints:
   ```
   GET /evals?folder=../../../etc
   ```
3. If the endpoint returns file contents from outside the intended directory, the vulnerability is confirmed

For a more targeted test:
1. Set up a local instance of the application
2. Create a test file in a parent directory that should not be accessible
3. Make a request to the `/pairwise-evals` endpoint with paths pointing to this file
4. Check if the application returns the contents of the test file

## Path Traversal in Debug File Writer

The `DebugFileWriter` class in the application doesn't validate or sanitize the filename parameter before using it in `os.path.join()`. This creates a path traversal vulnerability where an attacker can manipulate the filename to write files to arbitrary locations on the filesystem.

### Description
Step by step to trigger:
1. Access the application when debug mode is enabled (IS_DEBUG_ENABLED=True)
2. Find an endpoint that uses the DebugFileWriter to save debug information
3. Craft a malicious filename containing path traversal sequences like `../../../etc/passwd`
4. Submit this filename to the application
5. The application will write the debug content to the targeted path instead of the intended debug directory

### Impact
An attacker can write files to arbitrary locations on the file system with the permissions of the user running the application. This could lead to:
- Overwriting critical system files
- Creating malicious scripts that could be executed later
- Corrupting application data
- Potentially gaining remote code execution if files can be written to executable paths

### Vulnerability Rank
High

### Currently Implemented Mitigations
The vulnerability is only exploitable when debug mode is enabled (IS_DEBUG_ENABLED=True), which should not be enabled in production environments.

### Missing Mitigations
The application should:
1. Sanitize filenames to remove or escape any path traversal sequences
2. Validate that filenames only contain allowed characters
3. Ensure the final resolved path is within the intended directory
4. Use a secure, random filename generation instead of accepting user input

### Preconditions
- Debug mode must be enabled (IS_DEBUG_ENABLED=True)
- The attacker must have access to an endpoint that accepts user input for filenames
- The application must be running with sufficient permissions to write to the targeted location

### Source Code Analysis
In `backend/debug/DebugFileWriter.py`, the vulnerable code is:

```python
def write_to_file(self, filename: str, content: str) -> None:
    try:
        with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
            file.write(content)
    except Exception as e:
        logging.error(f"Failed to write to file: {e}")
```

The path traversal vulnerability occurs because:
1. The `filename` parameter is directly used in `os.path.join()`
2. No validation or sanitization is performed on the filename
3. Path traversal sequences (like `../`) in the filename can navigate outside the intended directory

For example, if `self.debug_artifacts_path` is "/app/debug" and the filename is "../../../../etc/passwd", the resulting path would be "/etc/passwd", allowing an attacker to overwrite this file.

### Security Test Case
1. Set up the application with debug mode enabled (IS_DEBUG_ENABLED=True)
2. Identify an endpoint that uses the DebugFileWriter to save debug information
3. Send a request to this endpoint with a filename parameter containing path traversal sequences, such as `../../../tmp/malicious_file.txt`
4. Verify that a file was created at `/tmp/malicious_file.txt` containing the debug content
5. Check the application logs to confirm that no error was encountered during the file writing operation

## Overly Permissive CORS Configuration with Credentials

The application uses an overly permissive CORS configuration, allowing requests from any origin (`"*"`) while also allowing credentials. This combination is dangerous as it allows any website to make authenticated requests to the API with the user's credentials.

### Description
Step by step to trigger:
1. Find an authenticated endpoint in the application
2. Create a malicious website that makes requests to this endpoint
3. When a user visits the malicious website while authenticated to the target application, the browser will include their credentials in the request
4. The endpoint will process the request with the user's credentials

### Impact
This vulnerability allows an attacker to:
- Perform actions on behalf of authenticated users
- Access sensitive user data
- Potentially take over user accounts
- Execute unauthorized operations with the privileges of the victim user

### Vulnerability Rank
High

### Currently Implemented Mitigations
None identified.

### Missing Mitigations
The application should:
1. Restrict the allowed origins to specific trusted domains
2. If wildcard origins (`"*"`) must be used, disable credentials
3. Implement CSRF tokens for sensitive operations
4. Add proper authentication checks for all sensitive endpoints

### Preconditions
- The application must have endpoints that perform sensitive operations
- Users must authenticate with the application using cookies or other browser-stored credentials

### Source Code Analysis
In `backend/main.py`, the vulnerable CORS configuration is:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

The vulnerability occurs because:
1. `allow_origins=["*"]` allows requests from any domain
2. `allow_credentials=True` allows requests to include credentials
3. `allow_methods=["*"]` allows all HTTP methods, including potentially sensitive ones like POST, PUT, DELETE
4. `allow_headers=["*"]` allows all headers to be included

This configuration violates the security principle that wildcard origins should not be used when credentials are allowed. Modern browsers will refuse to make requests with credentials when the origin is a wildcard, but this configuration is still problematic as it indicates a lack of proper CORS security understanding.

### Security Test Case
1. Set up the application with the current CORS configuration
2. Create a test HTML page on a different domain with JavaScript that attempts to make a request to the application API with credentials
3. Load the test page in a browser where you're authenticated to the application
4. Observe that modern browsers will block the request due to the invalid CORS configuration, with an error message in the console
5. Modify the application's CORS configuration to use a specific origin instead of a wildcard
6. Observe that the request now succeeds when the origin matches, demonstrating the potential vulnerability
