- **Mitigation Strategy**: Validate user-supplied URLs for Screenshot/Video endpoints
  - **Description**:
    Enforce domain or IP checks when users provide a URL for screenshot capture (`/api/screenshot`) or video uploads. Reject private, localhost, or non-public addresses to prevent internal network scans. For videos, reject or limit formats that MoviePy can process safely.
    1. Inspect incoming URL or file before forwarding to external screenshot service or processing the video.
    2. If a private IP or suspicious domain is detected, reject the request.
    3. For videos larger than a set threshold, return an error.
    4. Only permit safe formats to avoid crashes or exploits in `moviepy.editor`.
  - **List of Threats Mitigated**:
    - SSRF and internal network scanning (High severity)
    - Potential DoS from malformed or oversized media (Medium severity)
  - **Impact**:
    Significantly reduces SSRF risk and large-file exploitation attempts, ensuring only valid external URLs and manageable media.
  - **Currently Implemented**:
    None. The code in `routes/screenshot.py` and `video_to_app.py` does not currently restrict URLs or file sizes.
  - **Missing Implementation**:
    - URL validation and private IP blacklist in `routes/screenshot.py`.
    - File size and format checks in `video_to_app.py`.

- **Mitigation Strategy**: Enforce usage and rate limits on code/image generation
  - **Description**:
    Impose per-user or global rate limits on the `/generate-code` WebSocket route and image-generation endpoints. Enforce usage quotas to prevent misuse or cost overruns.
    1. Track each client session or API key usage.
    2. Apply request throttling (e.g., X requests per minute).
    3. If usage is exceeded, return an error or require additional authentication.
  - **List of Threats Mitigated**:
    - Potential cost exhaustion from unbounded requests (High severity)
    - System resource strains or denial-of-service from excessive calls (Medium severity)
  - **Impact**:
    Significantly reduces potential billing exploitation and lowers likelihood of DoS.
  - **Currently Implemented**:
    None. The project code does not show usage-tracking or rate-limiting logic.
  - **Missing Implementation**:
    - Rate-limiting middleware or logic around relevant FastAPI routes.
    - Quota monitoring system for code generation or large batch calls.

- **Mitigation Strategy**: Restrict modifying OpenAI/Anthropic base URL in production
  - **Description**:
    Prevent untrusted overrides of `OPENAI_BASE_URL` (or Anthropic base URL) to avoid proxying requests to malicious endpoints.
    1. In production (`IS_PROD=True`), ignore user-supplied base URLs.
    2. Validate any custom base URL to ensure it’s recognized and not internal or local.
  - **List of Threats Mitigated**:
    - SSRF if an attacker sets `OPENAI_BASE_URL` to an internal domain (High severity)
    - Unauthorized scanning or bridging to local network (Medium severity)
  - **Impact**:
    Ensures LLM traffic only goes to legitimate endpoints. High reduction of internal scanning risk.
  - **Currently Implemented**:
    Partial. The code checks `IS_PROD` to skip user-defined base URLs, but no thorough domain validation.
  - **Missing Implementation**:
    - Strict domain allowlist logic for non-production environments if custom endpoints are permitted.

- **Mitigation Strategy**: Enforce file size and format checks for image/video uploads
  - **Description**:
    Reject or limit huge images/videos in `mock_llm.py`, `image_generation` modules, or video endpoints.
    1. Check the `Content-Length` header or read file size in memory.
    2. Enforce an upper bound (configurable).
    3. Validate supported formats (e.g., PNG/JPEG for images, MP4/MOV for video).
  - **List of Threats Mitigated**:
    - Memory exhaustion or DoS from massive file uploads (Medium severity)
    - Potential crashes in `moviepy.editor` or PIL from unsupported/harmful formats (Medium severity)
  - **Impact**:
    Reduces resource exhaustion or unexpected server crashes.
  - **Currently Implemented**:
    None. Current code does not cap file size or handle partial reads.
  - **Missing Implementation**:
    - Server-side checks for `Content-Length` before reading.
    - Rejection or fallback for unsupported or oversized files.

- **Mitigation Strategy**: Sanitize or disclaim generated code outputs
  - **Description**:
    Clarify that rendered “screenshot-to-code” HTML/JS could contain unsafe scripts if an attacker manipulates prompts. Alternatively, apply HTML sanitization if the app itself tries to display generated markup in the browser.
    1. Tag all generated code as untrusted.
    2. If the code is displayed in-app, apply a sanitization library or run it in a sandboxed iframe.
    3. Warn users that generated code can contain vulnerabilities or malicious scripts.
  - **List of Threats Mitigated**:
    - XSS from malicious code generation (High severity)
    - Unintended script injection (Medium severity)
  - **Impact**:
    Greatly reduces risk to end-users if code is auto-rendered. Sets correct expectation that code is unverified.
  - **Currently Implemented**:
    None. The app streams code directly to the front-end.
  - **Missing Implementation**:
    - Sanitization or sandbox usage in the front-end after code generation.
    - Clear disclaimers that code from the LLM is not automatically safe.

- **Mitigation Strategy**: Protect environment variables and secret tokens
  - **Description**:
    Avoid embedding secret keys in logs, commits, or front-end code. Keep `.env` out of version control and confirm it’s in `.gitignore`.
    1. Confirm `.env` is never checked in.
    2. Mask or redact keys in logs.
    3. Restrict who can set or read secret environment variables.
  - **List of Threats Mitigated**:
    - Secret leakage leading to unauthorized API usage (High severity)
    - Potential credential compromise (High severity)
  - **Impact**:
    High reduction in risk of stolen credentials and expensive misuse of Anthropic/OpenAI/Replicate endpoints.
  - **Currently Implemented**:
    Partial. The instructions in `README.md` show writing the key to `.env`, but no mention of .gitignore usage.
  - **Missing Implementation**:
    - Checking that `.env` is strictly excluded from the repo.
    - Redacting secrets in debug output or logs.

- **Mitigation Strategy**: Implement concurrency and resource limits for video processing
  - **Description**:
    Limit how many videos the server processes concurrently. For example, queue incoming requests or run them asynchronously with a cap.
    1. Use a job queue for video tasks.
    2. Limit concurrency to a configured maximum.
    3. Gracefully reject or defer tasks if the limit is exceeded.
  - **List of Threats Mitigated**:
    - Server overload from multiple large videos at the same time (Medium severity)
    - Crash or performance degradation leading to downtime (Medium severity)
  - **Impact**:
    Strongly reduces risk of DoS from parallel video requests.
  - **Currently Implemented**:
    None. The existing `video_to_app.py` processes each file without concurrency checks.
  - **Missing Implementation**:
    - A concurrency limit or queue system.
    - Mechanism to handle request overflow (e.g., 503 to new requests).
