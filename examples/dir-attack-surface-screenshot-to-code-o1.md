Below is the **Attack Surface Analysis** for this application based on the provided project files.
Since no previous analysis was provided, this is a new list. Only **medium**, **high**, or **critical** severity items are included.

---

1. **Arbitrary Directory Read via `/evals` Endpoints**

   - **Description**
     The application’s `/evals` and related endpoints accept a `folder` parameter that is used to list and then read local `.html` files. Because there is no restriction on the folder path, a malicious user can potentially query arbitrary local directories that contain HTML files.
   - **How screenshot-to-code Contributes**
     The code in `backend\routes\evals.py` takes a user-supplied folder path and enumerates `.html` files in it. It will then retrieve and return the file contents without additional validation or path sanitization.
   - **Example**
     An attacker calls `/evals?folder=C:\some_private_dir` (on Windows) or `/evals?folder=/home/username/secret` (on Unix). If any `.html` files exist there, they may be exposed.
   - **Impact**
     This can reveal sensitive or internal `.html` files that would otherwise be inaccessible, potentially including private data or internal artifacts.
   - **Risk Severity**
     **Medium**
     (Limited to reading files with an `.html` extension but can still expose sensitive data if such files exist in unprotected directories.)
   - **Current Mitigations**
     - The code checks if the path exists but does not restrict it beyond existence.
     - It only processes `.html` files, which slightly narrows the exposure.
   - **Missing Mitigations**
     - Enforce a strict whitelist or subdirectory scope for valid `folder` parameters.
     - Reject absolute paths or relative traversal outside a predefined evaluations directory.
     - Optionally remove the ability for the client to specify custom folders at all if not needed.


2. **Malicious or Large Media Files Causing Denial-of-Service or Exploit**

   - **Description**
     Users can upload images or videos that get processed by libraries (`Pillow` in `image_processing/utils.py`, `moviepy/ffmpeg` in `video/utils.py`). With no file-size or dimension checks on the FastAPI endpoints, an attacker can upload very large or malformed files, causing excessive resource consumption or leveraging known library exploits.
   - **How screenshot-to-code Contributes**
     - The backend directly processes user-supplied media with Pillow and MoviePy/FFmpeg without robust validation or size checks.
     - The `video` path extracts frames from user-submitted video using `VideoFileClip`.
     - The `image_processing.utils` resizes images for Claude’s API, but does not enforce robust overall file checks except dimension capping for that single flow.
   - **Example**
     An attacker uploads a gigabyte-sized or specially crafted video file that triggers high CPU/memory usage in `ffmpeg` or a known parsing vulnerability in `Pillow`.
   - **Impact**
     - **DoS**: Crash or severely degrade the server with excessive resource usage.
     - **Potential RCE**: If there is an unpatched exploit in the third-party libraries upon parsing unusual files.
   - **Risk Severity**
     **Medium**
   - **Current Mitigations**
     - Some image resizing for Claude usage, which partially limits dimension-based overhead but not overall file size or type.
   - **Missing Mitigations**
     - Enforce strict size checks and format validation before accepting images or videos.
     - Use a sandboxed or containerized approach when invoking `ffmpeg` or `Pillow` for untrusted files.
     - Limit processing time or memory usage to prevent DoS.


3. **Untrusted HTML Code Generation Leading to Potential XSS**

   - **Description**
     The application can generate raw HTML code by sending user-provided prompts to LLMs (OpenAI/Anthropic). The resulting HTML is streamed back to the client and may later be rendered in a browser context. Because it is untrusted code from an external AI, it can easily contain scripts or malicious HTML.
   - **How screenshot-to-code Contributes**
     - `/generate-code` returns AI-generated HTML directly to the front-end, without sanitization.
     - If this output is rendered by the client application or a user in the same domain, it can execute arbitrary scripts (XSS).
   - **Example**
     A prompt that manipulates the LLM to include `<script>` tags in the returned code. If the front-end displays that HTML in the same origin, it can run attacker-supplied JavaScript on other users’ sessions.
   - **Impact**
     - **High** risk of XSS or script injection. Data exfiltration, session hijacking, or malicious actions in the user’s browser environment could become possible.
   - **Risk Severity**
     **High**
   - **Current Mitigations**
     - None in the codebase. The application simply streams the entire HTML and depends on the user to handle it safely.
   - **Missing Mitigations**
     - Use a separate sandboxed domain or dedicated iframe for rendering AI-generated HTML.
     - Add optional HTML sanitization if the code must be displayed in the same domain.
     - Warn users about the risk of running or blindly trusting generated code.

---

These attack surfaces reflect the most prominent medium-to-high risks **introduced by the application’s unique design**. Addressing them would significantly reduce the overall security exposure of *screenshot-to-code*.
