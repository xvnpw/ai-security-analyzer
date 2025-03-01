# VULNERABILITIES

## Path Traversal in Debug File Writer

### Vulnerability name
Path Traversal Vulnerability in Debug File Writer

### Description
The `DebugFileWriter` class in the application doesn't validate or sanitize the filename parameter before using it in `os.path.join()`. This creates a path traversal vulnerability where an attacker can manipulate the filename to write files to arbitrary locations on the filesystem.

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

### Vulnerability rank
High

### Currently implemented mitigations
The vulnerability is only exploitable when debug mode is enabled (IS_DEBUG_ENABLED=True), which should not be enabled in production environments.

### Missing mitigations
The application should:
1. Sanitize filenames to remove or escape any path traversal sequences
2. Validate that filenames only contain allowed characters
3. Ensure the final resolved path is within the intended directory
4. Use a secure, random filename generation instead of accepting user input

### Preconditions
- Debug mode must be enabled (IS_DEBUG_ENABLED=True)
- The attacker must have access to an endpoint that accepts user input for filenames
- The application must be running with sufficient permissions to write to the targeted location

### Source code analysis
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

### Security test case
1. Set up the application with debug mode enabled (IS_DEBUG_ENABLED=True)
2. Identify an endpoint that uses the DebugFileWriter to save debug information
3. Send a request to this endpoint with a filename parameter containing path traversal sequences, such as `../../../tmp/malicious_file.txt`
4. Verify that a file was created at `/tmp/malicious_file.txt` containing the debug content
5. Check the application logs to confirm that no error was encountered during the file writing operation

## Server-Side Request Forgery (SSRF) via Custom OpenAI Base URL

### Vulnerability name
Server-Side Request Forgery (SSRF) via Custom OpenAI Base URL

### Description
The application allows configuring a custom base URL for the OpenAI API through the OPENAI_BASE_URL environment variable. If an attacker can control this setting (either through a configuration endpoint or by manipulating environment variables in certain deployment scenarios), they can exploit this to perform Server-Side Request Forgery (SSRF) attacks.

Step by step to trigger:
1. Find a way to control the OPENAI_BASE_URL setting (through a configuration endpoint or environment variable manipulation)
2. Set OPENAI_BASE_URL to an internal service URL, such as "http://internal-service:8080/v1"
3. Trigger the application to make an OpenAI API call
4. The application will connect to the specified internal service instead of OpenAI's API

### Impact
This vulnerability allows an attacker to:
- Scan and probe internal networks
- Access internal services that should not be accessible from outside
- Potentially exploit vulnerable internal services
- Bypass network security controls
- Exfiltrate sensitive data from internal services

### Vulnerability rank
High

### Currently implemented mitigations
The base URL is loaded from environment variables rather than directly from user input, which provides some level of protection. Additionally, the code explicitly disables user-specified OpenAI Base URL in production environments with the check `if not IS_PROD`.

### Missing mitigations
The application should:
1. Validate the OPENAI_BASE_URL against a whitelist of allowed domains
2. Implement network-level protections to prevent connections to internal services
3. Use a proxy service for all external API calls with its own validation mechanisms
4. Disable custom base URL functionality in all environments, not just production

### Preconditions
- The application must be running in a non-production environment (IS_PROD=False)
- The attacker must be able to control the OPENAI_BASE_URL environment variable or provide it through the settings dialog
- The application must be deployed in an environment where it can access internal services

### Source code analysis
In `backend/routes/generate_code.py`, the vulnerable code is:

```python
# Base URL for OpenAI API
openai_base_url: str | None = None
# Disable user-specified OpenAI Base URL in prod
if not IS_PROD:
    openai_base_url = get_from_settings_dialog_or_env(
        params, "openAiBaseURL", OPENAI_BASE_URL
    )
if not openai_base_url:
    print("Using official OpenAI URL")
```

And then later, the base URL is used without validation:

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

The vulnerability occurs because:
1. The OPENAI_BASE_URL is loaded from environment variables or user settings without validation in non-production environments
2. The base_url is directly passed to the API client initialization
3. The API client will connect to whatever URL is specified
4. If the URL points to an internal service, the request will be made to that service

This allows an attacker to make the application connect to any accessible network service.

### Security test case
1. Set up the application with IS_PROD=False
2. Set up a test server on an internal network that records incoming requests
3. Configure OPENAI_BASE_URL to point to your test server (e.g., "http://internal-test-server:8080/v1")
4. Trigger the application to make an OpenAI API call by using the generate code functionality
5. Verify that your test server receives a request from the application
6. Check that the request contains the API key and other sensitive information
7. Modify OPENAI_BASE_URL to point to different internal services to determine the scope of accessible networks

## Overly Permissive CORS Configuration with Credentials

### Vulnerability name
Overly Permissive CORS Configuration with Credentials

### Description
The application uses an overly permissive CORS configuration, allowing requests from any origin (`"*"`) while also allowing credentials. This combination is dangerous as it allows any website to make authenticated requests to the API with the user's credentials.

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

### Vulnerability rank
High

### Currently implemented mitigations
None identified.

### Missing mitigations
The application should:
1. Restrict the allowed origins to specific trusted domains
2. If wildcard origins (`"*"`) must be used, disable credentials
3. Implement CSRF tokens for sensitive operations
4. Add proper authentication checks for all sensitive endpoints

### Preconditions
- The application must have endpoints that perform sensitive operations
- Users must authenticate with the application using cookies or other browser-stored credentials

### Source code analysis
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

### Security test case
1. Set up the application with the current CORS configuration
2. Create a test HTML page on a different domain with JavaScript that attempts to make a request to the application API with credentials
3. Load the test page in a browser where you're authenticated to the application
4. Observe that modern browsers will block the request due to the invalid CORS configuration, with an error message in the console
5. Modify the application's CORS configuration to use a specific origin instead of a wildcard
6. Observe that the request now succeeds when the origin matches, demonstrating the potential vulnerability
