Here is the list of vulnerabilities for the project.

***

### Vulnerability 1: Full-Read Server-Side Request Forgery (SSRF) in Screenshot Functionality

*   **vulnerability name**: Full-Read Server-Side Request Forgery (SSRF) in Screenshot Functionality
*   **description**: The `/api/screenshot` endpoint is vulnerable to a Server-Side Request Forgery (SSRF) attack. An external attacker can craft a request to this endpoint, providing a URL that points to an internal network address or a cloud metadata service. The backend service will then request a screenshot of this URL from the external `screenshotone.com` service. Because the `screenshotone.com` service request originates from the application's server, it can access internal resources that are not exposed to the public internet. The resulting screenshot, which contains the content of the internal resource, is then returned to the attacker. This transforms a typically blind SSRF into a full-read SSRF, allowing the attacker to visually exfiltrate sensitive information.
*   **impact**: An attacker can bypass firewall protections to scan the internal network of the server where the application is hosted. They can access and view sensitive internal services, such as administrative panels, internal APIs, or other non-public applications. Most critically, in a cloud environment (like AWS, GCP, or Azure), an attacker can access the instance metadata service (e.g., `http://169.254.169.245/`) to retrieve sensitive information, including temporary access credentials, which could lead to a full cloud environment compromise.
*   **vulnerability rank**: critical
*   **currently implemented mitigations**: The `normalize_url` function in `backend/routes/screenshot.py` performs a basic check to ensure the URL scheme is `http` or `https` and rejects other schemes like `file://`. This prevents local file inclusion through this vector but does not prevent requests to internal network services over HTTP/HTTPS.
*   **missing mitigations**: The application is missing critical SSRF protection measures. Before making the request to the screenshot service, the backend must:
    1.  Resolve the hostname in the user-provided URL to its IP address.
    2.  Validate the resolved IP address against a deny-list of private, reserved, and loopback IP ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local addresses `169.254.0.0/16`).
    3.  Reject any request that resolves to a restricted IP address.
*   **preconditions**: The attacker must possess a valid API key for the `screenshotone.com` service, which can be obtained by registering on their website.
*   **source code analysis**: The vulnerability exists in the `backend/routes/screenshot.py` file.
    1.  An API endpoint `/api/screenshot` is defined, which accepts a POST request with a JSON body containing a `url`.
        ```python
        # backend/routes/screenshot.py

        @router.post("/api/screenshot")
        async def app_screenshot(request: ScreenshotRequest):
            # ...
            url = request.url
            # ...
        ```
    2.  The `url` is passed to the `normalize_url` function. This function ensures the URL has a protocol (`http` or `https`) but does not check if the hostname resolves to an internal or restricted IP address. The project's own test file, `backend/tests/test_screenshot.py`, confirms that local and private IP addresses are considered valid inputs.
        ```python
        # backend/tests/test_screenshot.py

        def test_ip_address_urls(self):
            """Test IP address URLs."""
            assert normalize_url("192.168.1.1") == "https://192.168.1.1"
            assert normalize_url("http://192.168.1.1") == "http://192.168.1.1"
        ```
    3.  The normalized URL (`normalized_url`) is then passed to the `capture_screenshot` function.
        ```python
        # backend/routes/screenshot.py

        try:
            normalized_url = normalize_url(url)
            image_bytes = await capture_screenshot(normalized_url, api_key=api_key)
            # ...
        ```
    4.  The `capture_screenshot` function makes a GET request to the external service `api.screenshotone.com`, including the user-provided `target_url` as a parameter. The external service then fetches the content from `target_url`. This request originates from the application server, not the user's browser.
        ```python
        # backend/routes/screenshot.py

        async def capture_screenshot(
            target_url: str, api_key: str, device: str = "desktop"
        ) -> bytes:
            api_base_url = "https://api.screenshotone.com/take"

            params = {
                "access_key": api_key,
                "url": target_url, # Attacker-controlled URL
                # ...
            }

            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(api_base_url, params=params) # The SSRF is triggered here
                # ...
                return response.content
        ```
    5.  The screenshot (`image_bytes`) is converted to a data URL and sent back to the attacker, allowing them to see the content of the internal resource.
*   **security test case**:
    1.  **Objective**: Prove that an attacker can access and view the content of a known internal service, such as the AWS EC2 metadata endpoint.
    2.  **Prerequisites**:
        *   The application is running and publicly accessible.
        *   The attacker has a valid API key for `screenshotone.com`.
    3.  **Steps**:
        *   The attacker sends a POST request to the `/api/screenshot` endpoint using a tool like `curl`.
        *   The `url` field in the JSON payload is set to `http://169.254.169.254/latest/meta-data/`. This is the IP address for the AWS instance metadata service.
        *   The `apiKey` field is set to the attacker's valid `screenshotone.com` API key.

        **Example Request:**
        ```bash
        curl -X POST http://<application_host>:<port>/api/screenshot \
        -H "Content-Type: application/json" \
        -d '{
          "url": "http://169.254.169.254/latest/meta-data/",
          "apiKey": "YOUR_SCREENSHOTONE_API_KEY"
        }'
        ```
    4.  **Expected Result**:
        *   The server should respond with a `200 OK` status code.
        *   The JSON response body will contain a `url` field with a base64-encoded data URL (e.g., `data:image/png;base64,iVBOR...`).
        *   When the attacker decodes the base64 string or renders the data URL in a browser, they will see an image of a directory listing, which is the root of the AWS metadata service. This proves the attacker can access and view content from internal network endpoints.

***

### Vulnerability 2: Arbitrary File Write with Controlled Extension Leading to Potential Remote Code Execution

*   **vulnerability name**: Arbitrary File Write with Controlled Extension Leading to Potential Remote Code Execution
*   **description**: The video upload feature is vulnerable to an arbitrary file write with a user-controlled file extension. The endpoint responsible for processing videos accepts a data URL, which includes a MIME type and base64-encoded content, both controlled by the attacker. The backend uses the provided MIME type to determine the file extension for a temporary file and then writes the decoded content into it. This file is then passed to the `moviepy` library for processing. By providing a crafted MIME type (e.g., `application/x-sh`) and malicious content (e.g., a shell script), an attacker can create a file with a dangerous extension (e.g., `.sh`) and arbitrary content on the server's filesystem.
*   **impact**: This vulnerability allows an attacker to write arbitrary files to the server's temporary directory. While the file is short-lived, it creates a critical window for exploitation. The primary impact is the potential for Remote Code Execution (RCE) by exploiting vulnerabilities in the downstream processing library (`moviepy` and its dependency `ffmpeg`). Many media processing libraries have a history of command injection or parsing vulnerabilities when handling files with misleading extensions or crafted content. For example, an attacker could upload a file that triggers a command injection in `ffmpeg`, leading to a full server compromise. Even without a direct RCE, this can be chained with other vulnerabilities like Local File Inclusion (LFI) or used to trigger other parsing vulnerabilities like XXE.
*   **vulnerability rank**: high
*   **currently implemented mitigations**: The file is created using `tempfile.NamedTemporaryFile` which prevents path traversal attacks and places the file in a non-web-accessible temporary directory. The `delete=True` flag ensures the file is removed after the handle is closed, limiting its persistence on the filesystem.
*   **missing mitigations**:
    1.  **MIME Type Validation**: The application does not validate the user-provided MIME type. It should enforce a strict allow-list of expected video MIME types (e.g., `video/mp4`, `video/webm`, `video/quicktime`).
    2.  **Safe File Extension**: The file extension for the temporary file should not be derived from user input. A fixed, non-executable extension like `.tmp` or `.bin` should be used for all uploaded video files before processing.
    3.  **Content Verification**: After writing the file, its type should be verified using its magic bytes, ignoring the user-provided MIME type and extension.
*   **preconditions**: An attacker must be able to access the application's video upload functionality.
*   **source code analysis**: The vulnerability is in `backend/video/utils.py` within the `split_video_into_screenshots` function.
    1.  The function receives a `video_data_url` string from the user, e.g., `data:application/x-sh;base64,...`.
    2.  `mime_type = video_data_url.split(";")[0].split(":")[1]` extracts the attacker-controlled MIME type (`application/x-sh`) without validation.
    3.  `suffix = mimetypes.guess_extension(mime_type)` converts the MIME type to a file extension (`.sh`). This is directly controlled by the attacker.
    4.  `with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:` creates a temporary file with a random name but the attacker-controlled suffix (e.g., `/tmp/tmpXXXX.sh`).
    5.  `video_encoded_data = video_data_url.split(",")[1]` and `video_bytes = base64.b64decode(video_encoded_data)` extract and decode the attacker-controlled content.
    6.  `temp_video_file.write(video_bytes)` writes the malicious content to the file on disk.
    7.  `clip = VideoFileClip(temp_video_file.name)` passes the file path to `moviepy`, which in turn passes it to a backend like `ffmpeg`. This is the trigger point where a vulnerability in the backend processor could be exploited by the crafted file.
*   **security test case**:
    1.  **Objective**: Prove that an attacker can create a file with an arbitrary extension and content on the server's filesystem and force a backend library to process it, potentially triggering a secondary vulnerability.
    2.  **Prerequisites**: Access to the application endpoint that processes video uploads.
    3.  **Steps**:
        *   An attacker crafts non-video content. For this example, a simple text string: `This is not a video`.
        *   The attacker base64-encodes the content: `VGhpcyBpcyBub3QgYSB2aWRlby4=`.
        *   The attacker chooses a MIME type that will resolve to a non-video file extension, for example `text/plain`, which the `mimetypes` library will resolve to `.txt`.
        *   The attacker constructs the malicious data URL: `data:text/plain;base64,VGhpcyBpcyBub3QgYSB2aWRlby4=`.
        *   The attacker sends a request to the application's video processing endpoint, providing the crafted data URL as the video input.
    4.  **Expected Result**:
        *   The application backend will receive the request.
        *   The `split_video_into_screenshots` function will create a temporary file named something like `/tmp/tmpxxxyyy.txt` and write "This is not a video" into it.
        *   The application will pass this file path to `moviepy.editor.VideoFileClip`.
        *   `moviepy`/`ffmpeg` will fail to process the file as a video, and the application will likely return an error to the user.
        *   This outcome proves the vulnerability: the attacker successfully created a `.txt` file with arbitrary content on the server and forced the media processing library to attempt to parse it. A more advanced attack would involve using a file format with known vulnerabilities in `ffmpeg` (e.g., a crafted playlist file, subtitle file, or a specific media container format with a misleading extension) to achieve Remote Code Execution.
