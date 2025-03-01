# VULNERABILITIES

## Server-Side Request Forgery (SSRF) via Custom API Base URL

### Vulnerability Name
Server-Side Request Forgery (SSRF) via Custom OpenAI API Base URL

### Description
The screenshot-to-code application allows users to configure a custom base URL for the OpenAI API through the settings UI or environment variables. This feature, intended to support API proxies, can be exploited to force the server to make requests to arbitrary URLs, including internal services that should not be accessible from the internet.

Step by step exploitation:
1. Access the publicly available instance of the application
2. Open the settings dialog (gear icon)
3. Enter a malicious URL in the "OpenAI Base URL" field (e.g., `http://internal-service.local:8080/v1` or `http://169.254.169.254/latest/meta-data/` for AWS metadata)
4. Trigger a code generation action
5. The server will make requests to the specified internal URL, potentially exposing sensitive internal services or metadata

### Impact
An attacker could:
- Access internal services not meant to be exposed to the internet
- Retrieve cloud instance metadata (e.g., AWS metadata service)
- Bypass network access controls
- Potentially access sensitive information from internal systems
- In some cases, this could lead to remote code execution if vulnerable internal services are reached

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The application explicitly allows custom base URLs to be set without validation and uses them directly in API requests.

### Missing Mitigations
1. Implement URL validation to ensure only legitimate API endpoints are allowed
2. Create an allowlist of approved domains for API base URLs
3. Implement network-level controls to prevent the server from accessing internal resources
4. Add logging and alerting for unusual base URL configurations

### Preconditions
- The application must be deployed as a publicly accessible service
- The settings UI must allow changing the OpenAI base URL
- The attacker must have access to use the web interface

### Source Code Analysis
In `config.py`, the application loads the OpenAI base URL from environment variables:
```python
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", None)
```

In `generate_code.py`, this base URL is passed directly to the AsyncOpenAI client without validation:
```python
openai_base_url = get_from_settings_dialog_or_env(
    params, "openAiBaseURL", OPENAI_BASE_URL
)
```

The URL is then used in API requests:
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

When a code generation is triggered, the server will use this base URL to make requests to the OpenAI API, but if the URL has been changed to point to an internal service, the server will instead make requests to that internal service.

### Security Test Case
1. Set up a local test server that responds to API requests and logs the details
2. Deploy the screenshot-to-code application in a test environment
3. Access the application's settings UI
4. Enter the URL of your test server as the OpenAI base URL (ensure it has "/v1" in the path as required)
5. Upload an image and trigger code generation
6. Observe in the test server's logs that it receives API requests from the screenshot-to-code server
7. This confirms the SSRF vulnerability exists

## Unrestricted File Upload Vulnerability

### Vulnerability Name
Unrestricted File Upload with Missing Validation

### Description
The screenshot-to-code application processes user-uploaded images and videos without proper validation of file types, allowing an attacker to upload malicious files that could potentially be executed or used for further attacks.

Step by step exploitation:
1. Craft a malicious file disguised as an image or video (e.g., a file that looks like a PNG but contains malicious code)
2. Upload this file to the application
3. The application will process the file without proper validation
4. If the malicious file is written to disk and later accessed, it could lead to code execution or other attacks

### Impact
An attacker could:
- Upload malicious files that could be executed in certain contexts
- Bypass file type restrictions
- Potentially trigger command injection when files are processed with external tools
- If combined with other vulnerabilities, this could lead to remote code execution

### Vulnerability Rank
High

### Currently Implemented Mitigations
The application does perform some processing on images to ensure they meet size requirements for AI models, but this is not a security control:
```python
def process_image(image_data_url: str) -> tuple[str, str]:
    # Extract bytes and media type from base64 data URL
    media_type = image_data_url.split(";")[0].split(":")[1]
    base64_data = image_data_url.split(",")[1]
    image_bytes = base64.b64decode(base64_data)

    img = Image.open(io.BytesIO(image_bytes))
    # ... [size processing] ...
```

### Missing Mitigations
1. Implement strict file type validation using content analysis, not just extension checking
2. Add file size limitations to prevent resource exhaustion
3. Process uploads in a sandboxed environment
4. Scan uploaded files for malware or dangerous content
5. Implement proper error handling for malformed files

### Preconditions
- The application must be publicly accessible
- The attacker must be able to upload files to the application
- The application must process those files without proper validation

### Source Code Analysis
In the codebase, the application processes images but doesn't validate the file type beyond assuming it's an image:
```python
def process_image(image_data_url: str) -> tuple[str, str]:
    # Extract bytes and media type from base64 data URL
    media_type = image_data_url.split(";")[0].split(":")[1]
    base64_data = image_data_url.split(",")[1]
    image_bytes = base64.b64decode(base64_data)

    img = Image.open(io.BytesIO(image_bytes))
    # ... [processing code] ...
```

This code assumes the data is a valid image and calls `Image.open()` directly, which could fail or behave unexpectedly with malicious input. There's no validation that the claimed media type matches the actual content.

Similarly, for video processing in `video/utils.py`:
```python
# Decode the base64 URL to get the video bytes
video_encoded_data = video_data_url.split(",")[1]
video_bytes = base64.b64decode(video_encoded_data)

mime_type = video_data_url.split(";")[0].split(":")[1]
suffix = mimetypes.guess_extension(mime_type)

with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:
    temp_video_file.write(video_bytes)
    temp_video_file.flush()
    clip = VideoFileClip(temp_video_file.name)
```

The code uses `mimetypes.guess_extension()` which relies on file extensions rather than content analysis.

### Security Test Case
1. Create a file with a valid image extension (e.g., "test.png") but containing invalid or malicious content
2. Use the application's upload feature to upload this file
3. Observe if the application accepts and processes the file or if it properly rejects it
4. Additionally, try uploading extremely large files to test for resource exhaustion
5. If the application processes the malicious file without proper validation or fails insecurely, the vulnerability is confirmed

## Potential Path Traversal in Debug File Writing

### Vulnerability Name
Path Traversal in Debug File Writer

### Description
The screenshot-to-code application contains functionality to write debug information to files. This functionality does not properly validate filenames provided to the `write_to_file` method, potentially allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences.

Step by step exploitation:
1. Find a way to control the `filename` parameter passed to the `write_to_file` method
2. Craft a filename containing path traversal sequences (e.g., `../../../etc/malicious_file`)
3. The application will write the file to the specified location outside the intended directory
4. Depending on the application's permissions, this could allow writing to sensitive system files

### Impact
An attacker could:
- Write files to unauthorized locations on the filesystem
- Overwrite system files if the application has appropriate permissions
- Create configuration files that could be leveraged for further attacks
- In some cases, this could lead to code execution if executable files can be written

### Vulnerability Rank
High

### Currently Implemented Mitigations
The debug file writing is disabled by default (`IS_DEBUG_ENABLED` must be set):
```python
def __init__(self):
    if not IS_DEBUG_ENABLED:
        return
```

However, this is a feature flag, not a security control.

### Missing Mitigations
1. Implement proper validation of filenames to prevent path traversal
2. Sanitize user input before using it in file operations
3. Use safe file operation APIs that prevent writing outside intended directories
4. Apply the principle of least privilege to limit the application's file write permissions

### Preconditions
- Debug mode must be enabled (`IS_DEBUG_ENABLED` set to True)
- The attacker must be able to control the `filename` parameter passed to `write_to_file`
- The application must have appropriate filesystem permissions

### Source Code Analysis
In `debug/DebugFileWriter.py`, the `write_to_file` method performs file operations without properly validating the filename:
```python
def write_to_file(self, filename: str, content: str) -> None:
    try:
        with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
            file.write(content)
    except Exception as e:
        logging.error(f"Failed to write to file: {e}")
```

The method uses `os.path.join()` to create the file path, but does not validate that the resulting path is within the intended directory. If `filename` contains path traversal sequences (e.g., `../../../etc/passwd`), the file could be written outside the intended directory.

The key vulnerability is that `filename` is directly used in the path without any validation to prevent path traversal. This is particularly concerning if this parameter can be influenced by user input.

### Security Test Case
1. Enable debug mode in a test environment
2. Identify a function that calls `write_to_file` with a filename that can be controlled through user input
3. Craft a request with a filename containing path traversal sequences (e.g., `../../../tmp/test.txt`)
4. Execute the request and check if a file was created in the targeted location (e.g., `/tmp/test.txt`)
5. If the file was created in the specified location outside the intended directory, the vulnerability is confirmed

## Path Traversal in Evaluation Endpoints

### Vulnerability Name
Path Traversal in Evaluation Endpoints

### Description
The evaluation endpoints (`/evals`, `/pairwise-evals`, and `/best-of-n-evals`) accept folder paths as parameters without properly validating that these paths are within authorized directories. An attacker can exploit this vulnerability to access arbitrary files on the filesystem by using path traversal sequences (`../`) or absolute paths.

Step by step exploitation:
1. Identify one of the vulnerable evaluation endpoints (e.g., `/evals`)
2. Craft a request with a folder parameter that contains path traversal sequences (e.g., `../../../etc/passwd` or `C:\Windows\System32\drivers\etc\hosts`)
3. Send the request to the endpoint
4. The application will attempt to read files from the specified path, potentially exposing sensitive files

### Impact
An attacker could:
- Access sensitive configuration files (including API keys, passwords)
- Read application source code
- Access system files
- Gather information for further attacks

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The application checks if the folder exists but does not validate that it's within an authorized directory.

### Missing Mitigations
1. Implement path normalization and validation to ensure that specified folders are within authorized directories
2. Use a whitelist of allowed directories
3. Create a dedicated directory for evaluations and restrict access to only that directory
4. Implement proper access controls based on user authentication

### Preconditions
- The application must be accessible to the attacker
- The attacker must be able to send requests to the evaluation endpoints
- The process running the application must have read access to the targeted files

### Source Code Analysis
In `evals.py`, there are several endpoints that accept file paths without proper validation:

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

The application only checks if the folder exists but doesn't validate that it's within an authorized directory. This allows an attacker to specify any accessible path on the filesystem.

Similarly, in the `/pairwise-evals` endpoint:

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

This endpoint explicitly allows absolute paths and only checks if the folders exist.

The vulnerability continues in the logic that processes files within these folders:

```python
files = {
    f: os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html")
}
```

```python
with open(files1[f1], "r") as f:
    output1 = f.read()
```

By controlling the folder parameter, an attacker can read any files with a `.html` extension that the application has access to.

### Security Test Case
1. Identify the `/evals` endpoint in the application
2. Craft a request with a folder parameter containing path traversal sequences:
   ```
   GET /evals?folder=../../../etc
   ```
3. Observe if the application returns a list of HTML files from the `/etc` directory
4. If any are found, attempt to retrieve them
5. Verify if sensitive data is exposed in the response

For a more targeted test:
1. Create a file named `test.html` in a location outside the application directory (e.g., `/tmp/test.html`)
2. Fill the file with a unique string that would not normally appear in responses
3. Request:
   ```
   GET /evals?folder=../../../tmp
   ```
4. Verify if the unique string from your test file appears in the response

## Server-Side Request Forgery via Screenshot API

### Vulnerability Name
Server-Side Request Forgery via Screenshot API

### Description
The application includes a screenshot feature that takes a user-provided URL and forwards it to the external service `screenshotone.com` to capture a screenshot. This could potentially be exploited to perform Server-Side Request Forgery (SSRF) by manipulating the target URL to access internal services or make malicious requests through the external service.

Step by step exploitation:
1. Identify the `/api/screenshot` endpoint
2. Craft a request with a malicious URL targeting internal or sensitive resources (e.g., `http://internal-service.local` or `file:///etc/passwd`)
3. Send the request to the endpoint
4. The application forwards this URL to the external screenshot service, which may attempt to access the specified resource

### Impact
An attacker could:
- Probe internal services not directly accessible from the internet
- Potentially exfiltrate sensitive data if the external service returns the contents
- Make malicious requests that appear to come from the trusted external service
- Abuse the screenshot service's capabilities (for example, if it supports file:// URLs)

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The application forwards the URL to the external service without validation.

### Missing Mitigations
1. Implement URL validation to ensure only safe, public URLs are permitted
2. Create an allowlist of approved domains
3. Filter out internal IP addresses, localhost, and non-HTTP/HTTPS protocols
4. Implement rate limiting to prevent abuse of the screenshot service

### Preconditions
- The application must be accessible to the attacker
- The screenshot API endpoint must be available and functioning
- The external service must process the URLs without sufficient validation

### Source Code Analysis
In `screenshot.py`, the application accepts a URL from the user and forwards it to an external service:

```python
@router.post("/api/screenshot")
async def app_screenshot(request: ScreenshotRequest):
    # Extract the URL from the request body
    url = request.url
    api_key = request.apiKey

    # TODO: Add error handling
    image_bytes = await capture_screenshot(url, api_key=api_key)
```

```python
async def capture_screenshot(
    target_url: str, api_key: str, device: str = "desktop"
) -> bytes:
    api_base_url = "https://api.screenshotone.com/take"

    params = {
        "access_key": api_key,
        "url": target_url,
        # ... other parameters ...
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
        if response.status_code == 200 and response.content:
            return response.content
        else:
            raise Exception("Error taking screenshot")
```

The vulnerability stems from the lack of validation on the `target_url` parameter. The URL is directly passed to the external service without checking if it points to internal resources or uses potentially dangerous protocols.

### Security Test Case
1. Set up a local web server that logs all incoming requests
2. Send a request to the screenshot API with your local server as the target:
   ```
   POST /api/screenshot
   {
     "url": "http://your-server.com/ssrf-test",
     "apiKey": "valid-api-key"
   }
   ```
3. Check if your server receives a request from screenshotone.com
4. Try different URL formats to test the boundaries:
   - `http://localhost:8080`
   - `http://127.0.0.1:8080`
   - `file:///etc/passwd`
   - `http://169.254.169.254/` (AWS metadata endpoint)
5. If any of these URLs result in successful requests or errors that reveal information, the vulnerability is confirmed

## Insecure Temporary File Handling in Video Processing

### Vulnerability Name
Insecure Temporary File Handling in Video Processing

### Description
The application processes user-uploaded videos by writing them to temporary files based on user-controlled MIME types and then uses third-party libraries (moviepy, Pillow) to process these files. This implementation could potentially be exploited by uploading specially crafted videos designed to trigger vulnerabilities in these libraries or by manipulating the MIME type to cause unexpected behavior.

Step by step exploitation:
1. Craft a malicious video file designed to exploit vulnerabilities in the video processing libraries
2. Encode the file as a data URL with a manipulated MIME type
3. Upload the video to the application
4. The application writes the file to disk with a suffix based on the MIME type and processes it with external libraries
5. If successful, the malicious code in the video could be executed when processed

### Impact
An attacker could:
- Execute arbitrary code if the video processing libraries have vulnerabilities
- Cause application crashes or failures
- Potentially escalate privileges or access sensitive information
- Fill disk space with large temporary files

### Vulnerability Rank
High

### Currently Implemented Mitigations
The application uses `tempfile.NamedTemporaryFile` with `delete=True` to ensure temporary files are removed after use.

### Missing Mitigations
1. Implement strict validation of video content and MIME types
2. Set limits on video file sizes and processing durations
3. Process videos in a sandboxed environment
4. Use up-to-date versions of libraries with security patches
5. Consider processing videos without writing them to disk (stream processing)

### Preconditions
- The application must be accessible to the attacker
- The video processing functionality must be available
- The attacker must be able to upload videos to the application
- The video processing libraries must have vulnerabilities that can be exploited

### Source Code Analysis
In `video/utils.py`, the application processes videos using the following code:

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
```

Key vulnerabilities:
1. The MIME type is extracted from the data URL without validation and used to determine the file suffix
2. The video content is written to a temporary file and then processed by external libraries
3. Additionally, there's a debug feature that saves frames to temporary files:
   ```python
   if DEBUG:
       save_images_to_tmp(images)
   ```

If the video processing libraries (moviepy, Pillow) have vulnerabilities, a specially crafted video file could trigger them during processing. Also, if the MIME type is manipulated, it could potentially cause the file to be processed incorrectly or cause unexpected behavior.

### Security Test Case
1. Create a very small valid video file (e.g., 1-second MP4)
2. Modify its MIME type to an unusual but valid value (e.g., `video/x-matroska`)
3. Convert the video to a data URL
4. Submit the video through the application's interface
5. Monitor for errors or unexpected behavior

For a more comprehensive test:
1. Create a set of test videos with various formats and techniques known to cause issues:
   - Extremely large file sizes
   - Invalid file headers but valid extensions
   - Videos with metadata containing command injection payloads
   - Videos targeting known CVEs in the libraries used
2. Submit each test case to the application
3. Monitor for crashes, hangs, or unexpected behavior
4. Check if temporary files are properly cleaned up after processing
