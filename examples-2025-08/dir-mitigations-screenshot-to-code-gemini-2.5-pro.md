Here is the updated list of mitigation strategies for the `screenshot-to-code` application, incorporating findings from the new project files.

*   **Mitigation Strategy**: Restrict Screenshot URL Targets to Prevent SSRF
    *   **Description**: The `/api/screenshot` endpoint, which uses a third-party service to capture web page screenshots, should be hardened to prevent it from being used to access internal or unintended network resources. An attacker could provide a URL pointing to an internal service (e.g., `http://192.168.1.1/admin` or a cloud metadata service), causing the application's backend to initiate a request to that sensitive endpoint via the screenshot service.
        1.  **Implement IP Address Deny-List**: In the `backend/routes/screenshot.py` file, before making the request to the screenshot service, resolve the hostname from the user-provided URL to its IP address.
        2.  **Validate Resolved IP**: Check if the resolved IP address falls within any private, reserved, or loopback ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
        3.  **Reject Restricted IPs**: If the IP address is in a restricted range, reject the request with an error message, preventing the application from acting as a proxy for internal network scanning.
    *   **Threats Mitigated**:
        *   **Server-Side Request Forgery (SSRF) (High)**: This mitigation directly prevents an attacker from using the screenshot functionality to probe internal networks or access cloud provider metadata services. This protects both the server environment and the user's `screenshotone.com` API key from being abused for malicious scanning.
    *   **Impact**: High. This strategy effectively neutralizes the SSRF threat by validating that all screenshot targets are legitimate, public-facing web pages.
    *   **Currently implemented**: Partial. The `normalize_url` function in `backend/routes/screenshot.py` restricts URL schemes to `http` and `https`, which prevents the use of other potentially dangerous schemes like `file://` or `ftp://`. This is confirmed by tests in `backend/tests/test_screenshot.py`.
    *   **Missing implementation**: The application does not perform any validation of the resolved IP address of the target URL. In fact, tests in `backend/tests/test_screenshot.py` explicitly confirm that URLs containing `localhost` and private IP addresses like `192.168.1.1` are considered valid inputs. The logic to resolve the hostname and check it against a deny-list of private IP ranges is missing from the `/api/screenshot` route handler.

*   **Mitigation Strategy**: Secure API Key Handling by Prioritizing Server-Side Configuration
    *   **Description**: The application allows users to provide their LLM API keys through the frontend UI, which are then transmitted to the backend. This is a less secure pattern than configuring them directly on the server. The application's design and documentation should be updated to treat server-side configuration as the primary, most secure method.
        1.  **Prioritize Environment Variables**: Modify the logic in `backend/routes/generate_code.py` to ensure that API keys loaded from server-side environment variables (e.g., from the `.env` file) are always used if available, ignoring any keys sent from the client.
        2.  **Add Security Warnings**: If the client-side key submission feature is retained for convenience, add a clear warning in the UI settings dialog explaining the security implications: the key will be transmitted over the network to the backend.
        3.  **Update Documentation**: Correct the statement in `Troubleshooting.md` that says "Your key is only stored in your browser." Clarify that for the self-hosted version, keys entered in the UI are sent to the local backend to make API calls.
    *   **Threats Mitigated**:
        *   **API Key Leakage via Transit (High)**: By prioritizing server-side keys, this mitigation reduces the risk of keys being intercepted during transmission from the frontend to the backend.
        *   **Denial of Service (DoS) (Medium)**: Removing reliance on client-sent keys makes CSRF attacks less effective, as a malicious website cannot force the user's browser to submit requests using an API key that is only configured on the backend.
    *   **Impact**: High. This change establishes a more secure default for API key management, which is critical for an application that processes powerful and costly API keys.
    *   **Currently implemented**: The application already supports the use of backend environment variables for API keys.
    *   **Missing implementation**: The logic in `backend/routes/generate_code.py` currently accepts keys from the client even if server-side keys are present. This should be changed to prioritize server-side keys. The documentation and UI also need to be updated to reflect the security trade-offs.

*   **Mitigation Strategy**: Implement a Stricter CORS Policy
    *   **Description**: The backend's current Cross-Origin Resource Sharing (CORS) policy is overly permissive (`allow_origins=["*"]`), allowing any website to send requests to it. This exposes users running the backend locally to Cross-Site Request Forgery (CSRF) attacks, where a malicious website could trigger code generation and deplete the user's API credits.
        1.  **Define Specific Origins**: In `backend/main.py`, change the `allow_origins` parameter in the `CORSMiddleware` from `["*"]` to a specific list containing only the expected frontend URL, such as `["http://localhost:5173"]`.
        2.  **Make Origins Configurable**: To maintain flexibility, allow this list to be configured via a new environment variable (e.g., `ALLOWED_ORIGINS`). The backend can then read this variable to populate the `allow_origins` list at startup.
    *   **Threats Mitigated**:
        *   **Cross-Site Request Forgery (CSRF) (Medium)**: This prevents malicious third-party websites from making unauthorized requests to the user's local backend, thus protecting their API keys and preventing unwanted resource consumption.
    *   **Impact**: High. This is a critical and straightforward fix that closes a significant security hole for anyone running the application, which is its primary distribution model.
    *   **Currently implemented**: Not implemented. The CORS policy in `backend/main.py` is explicitly configured to be a wildcard (`allow_origins=["*"]`).
    *   **Missing implementation**: The `CORSMiddleware` configuration in `backend/main.py` needs to be updated to use a specific, and ideally configurable, list of allowed origins.

*   **Mitigation Strategy**: Introduce Rate Limiting
    *   **Description**: The code generation and screenshot endpoints are resource-intensive, consuming both server resources and potentially expensive API credits. Without any limits, these endpoints are vulnerable to Denial of Service (DoS) attacks from a single malicious actor.
        1.  **Implement IP-Based Rate Limiting**: Integrate a rate-limiting library (e.g., `slowapi` for FastAPI) into the backend application.
        2.  **Apply Limits to Expensive Endpoints**: Apply rate limits to the `/generate-code` WebSocket and the `/api/screenshot` HTTP endpoint. A reasonable starting point would be to limit requests to a few dozen per minute from a single IP address. This should be configurable.
    *   **Threats Mitigated**:
        *   **Denial of Service (DoS) / Financial DoS (Medium)**: Rate limiting makes it significantly more difficult for an attacker to rapidly exhaust API credits or overload the server with requests, mitigating both computational and financial risks.
    *   **Impact**: Medium. This mitigation adds a necessary layer of protection against abuse, especially if an instance of the application is ever exposed to the internet or used in a shared environment.
    *   **Currently implemented**: Not implemented. The project files show no evidence of any rate-limiting mechanisms.
    *   **Missing implementation**: Rate-limiting logic needs to be added to the FastAPI application in `backend/main.py` and applied to the appropriate routes in `generate_code.py` and `screenshot.py`.

*   **Mitigation Strategy**: Harden Video Processing Against Resource Exhaustion
    *   **Description**: The video processing pipeline in `backend/video/utils.py`, which uses the `moviepy` library, is vulnerable to Denial of Service (DoS) attacks. An attacker can upload large or long videos, consuming excessive CPU, memory, and disk I/O during decoding and frame extraction, potentially making the service unavailable for other users.
        1.  **Implement Pre-Processing Size Check**: In the WebSocket handler that receives the video data URL, decode the base64 payload and check its byte size *before* writing it to a file or passing it to `moviepy`. Reject videos exceeding a reasonable threshold (e.g., 25 MB).
        2.  **Implement Duration Check**: After loading the video into `moviepy` using `VideoFileClip` in the `split_video_into_screenshots` function, immediately check the `clip.duration` property. Reject videos longer than a specific limit (e.g., 30 seconds) before starting the frame extraction loop. This prevents CPU exhaustion from processing long videos.
    *   **Threats Mitigated**:
        *   **Denial of Service (DoS) (Medium)**: Prevents attackers from tying up server resources by submitting computationally expensive video files, which could render the service unresponsive or cause it to crash.
    *   **Impact**: High. These checks are simple to implement and effectively block the most common resource exhaustion vectors for video processing, significantly improving the application's resilience.
    *   **Currently implemented**: Not implemented. The code in `backend/video/utils.py` processes any received video without any size or duration validation before passing it to the `moviepy` library.
    *   **Missing implementation**: The size and duration checks need to be added to the video handling logic, ideally before or at the beginning of the `split_video_into_screenshots` function.

*   **Mitigation Strategy**: Sandbox Generated Code in the Frontend
    *   **Description**: The application generates executable code (HTML with JavaScript) based on user input (images and text prompts) and renders it in a preview pane. While the LLMs are prompted to create safe code, they could be manipulated into generating malicious scripts. Rendering this code directly in the main application's context could lead to self-inflicted Cross-Site Scripting (XSS).
        1.  **Render Previews in a Sandboxed `<iframe>`**: Modify the frontend component that displays the generated code to render it inside an `<iframe>` element.
        2.  **Apply a Strict `sandbox` Attribute**: Configure the `<iframe>` with a strict `sandbox` attribute (e.g., `sandbox="allow-same-origin"`) to disable script execution, plugins, and form submissions by default.
        3.  **Provide a User-Controlled Opt-In for Scripts**: Add a button or toggle that allows the user to explicitly re-enable scripts for the preview (by dynamically adjusting the `sandbox` attribute to `sandbox="allow-same-origin allow-scripts"`), after acknowledging a security warning.
    *   **Threats Mitigated**:
        *   **Generated Code Injection / Cross-Site Scripting (XSS) (Low/Medium)**: This prevents potentially malicious JavaScript in the AI-generated code from executing automatically in the context of the user's session, protecting them from unintended actions.
    *   **Impact**: Medium. This strategy significantly improves the safety of the code preview feature by moving from a model of "trust by default" to "safe by default," giving the user explicit control over running potentially untrusted code.
    *   **Currently implemented**: Not implemented. The frontend appears to render the generated code directly without using a sandboxed `<iframe>`.
    *   **Missing implementation**: The frontend code responsible for displaying the generated code preview needs to be refactored to use a sandboxed `<iframe>`.
