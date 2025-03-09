# Vulnerability List

## Directory Traversal and Arbitrary File Disclosure in Evaluation Endpoints

**Description:**
- An external attacker can supply arbitrary folder paths via query parameters (e.g. “folder”, “folder1”, etc.) to evaluation endpoints such as `/evals`, `/pairwise-evals`, and `/best-of-n-evals`.
- The endpoints use the provided folder path directly with functions like `os.listdir` and file reads, **without implementing sanitization or whitelist checking**.
- This enables directory traversal (e.g. using `../../`) to access internal HTML evaluation files and potentially other sensitive files.

**Impact:**
- Exposure of internal files including evaluation artifacts, configuration files, and possibly code fragments.
- Sensitive internal information disclosure that could facilitate further attacks on the system.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The code checks for folder existence using Python’s `Path(folder).exists()`, but does not restrict the path to a predetermined safe directory.

**Missing Mitigations:**
- Input validation to restrict folder paths to known, safe subdirectories.
- Authorization checks and canonicalization of the folder path to prevent directory traversal.

**Preconditions:**
- The evaluation endpoints are publicly accessible.
- No authentication is enforced, and folder whitelisting is missing.

**Source Code Analysis:**
- In `routes/evals.py`, the functions (`get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals`) directly use the user-supplied folder parameter with functions like `os.listdir` and file reads **without proper sanitization**.
- This lack of validation allows directory traversal when relative paths (e.g. `../../`) are supplied.

**Security Test Case:**
- **Step 1:** Send a GET request to `/evals?folder=../../` (or similar relative path).
- **Step 2:** Check whether the response lists files outside of the intended directory, including sensitive configuration or internal files.
- **Step 3:** Verify that the attacker is able to access file contents that should not be publicly available.

---

## Server-Side Request Forgery (SSRF) via the Screenshot Endpoint

**Description:**
- The `/api/screenshot` endpoint accepts a JSON payload that includes a URL (in the “url” field) and an API key.
- The backend relays the provided URL as a parameter to an external service at `https://api.screenshotone.com/take` **without validating the URL**.
- An attacker can supply a URL directing to internal or otherwise restricted resources (for example, `http://localhost/admin`), causing unintended internal requests.

**Impact:**
- Enables an attacker to probe, discover, or interact with internal or sensitive network services.
- May facilitate additional attacks by leveraging further interactions with internal endpoints.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- There is no input validation or restriction on the domain of the URL before it is passed to the external screenshot API.

**Missing Mitigations:**
- Robust validation of URL format including the enforcement of a whitelist for allowed domains.
- Filtering or blocking of internal IP addresses and disallowed IP ranges to prevent SSRF.

**Preconditions:**
- The `/api/screenshot` endpoint is publicly accessible.
- The attacker can supply arbitrary URLs in the JSON payload.

**Source Code Analysis:**
- In `routes/screenshot.py`, the `capture_screenshot` function extracts the user-provided URL without any sanitization.
- The URL is then used directly as a parameter in an HTTP GET request to `https://api.screenshotone.com/take`, making SSRF possible.

**Security Test Case:**
- **Step 1:** Submit a POST request to `/api/screenshot` with the JSON payload:
  ```json
  { "url": "http://localhost/admin", "apiKey": "dummy" }
  ```
- **Step 2:** Monitor the server logs or outbound network requests to confirm that an internal URL is being contacted inappropriately.
- **Step 3:** Verify that the response or any accompanying behavior indicates that the internal URL was used.

---

## Information Disclosure via Detailed Error Messages over the Code Generation WebSocket

**Description:**
- The `/generate-code` WebSocket endpoint triggers the `throw_error` function when an error occurs.
- This function sends detailed error messages—including exception details and stack traces—directly back to the client over the WebSocket, rather than a generic error message.
- The detailed error messages can reveal sensitive internal implementation details, such as file paths, configuration settings, and library versions.

**Impact:**
- The disclosed internal details can help an attacker better understand the system’s structure.
- Such information may be used to craft more targeted and effective attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The error handling mechanism sends the error message and then closes the connection immediately.
- **However,** no measures are in place to sanitize the error details before sending them out.

**Missing Mitigations:**
- Only generic error messages should be sent to the client.
- Detailed internal error information should be logged securely on the server side and not exposed externally.

**Preconditions:**
- An attacker must establish a WebSocket connection to `/generate-code`.
- The attacker must be able to send a malformed or malicious payload that causes an error.

**Source Code Analysis:**
- In `routes/generate_code.py`, the `throw_error` function is called when an error occurs, and it sends detailed error messages using a function like `send_json`.
- After sending the error, the WebSocket connection is closed using a custom error code.
- **Visualization:**
  1. **Error Triggered:** Malformed input leads to an exception.
  2. **Error Handled:** `throw_error` is invoked.
  3. **Error Sent:** Full error details (including internal paths and stack traces) are sent to the client.
  4. **Connection Closed:** The WebSocket connection is terminated.

**Security Test Case:**
- **Step 1:** Connect to the `/generate-code` WebSocket endpoint.
- **Step 2:** Send a deliberately malformed JSON payload.
- **Step 3:** Observe the error message returned, checking for disclosure of internal file paths, stack traces, or exception details.
- **Step 4:** Confirm that a generic error message is not provided.

---

## Lack of Output Sanitization Enabling Potential XSS in LLM-Generated Code

**Description:**
- The application uses LLMs (through endpoints like `/generate-code`) to generate HTML code, which is then returned to the client without comprehensive output sanitization.
- An attacker, by influencing the input (e.g., manipulating a screenshot URL or prompt), may trick the LLM into generating HTML that includes malicious JavaScript.
- As a result, if the generated HTML is rendered by a browser, it may execute the injected script.

**Impact:**
- Execution of malicious scripts in the user’s browser can lead to session hijacking, website defacement, and data exfiltration.
- This represents a persistent Cross-Site Scripting (XSS) vulnerability that can compromise client-side security.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- A simple regex-based extractor (`extract_html_content`) is used to process the generated content, but it does not effectively sanitize against script injections.

**Missing Mitigations:**
- Robust output sanitization of the generated HTML to remove dangerous script tags.
- Deployment of a Content Security Policy (CSP) to restrict script execution.
- Additional input validation to ensure that attacker-controlled inputs do not lead to hazardous outputs.

**Preconditions:**
- The attacker must have the ability to influence the LLM prompt or input to induce the generation of HTML that contains embedded `<script>` tags.
- The unsanitized HTML is then delivered to the client.

**Source Code Analysis:**
- In `routes/generate_code.py`, after receiving the HTML generated by the LLM, the output is processed by the `extract_html_content` function.
- This function does not remove or properly sanitize embedded `<script>` tags or other potentially malicious content.
- **Visualization:**
  1. **LLM Generation:** LLM produces HTML code.
  2. **Processing Stage:** The code is filtered by `extract_html_content` (which only performs basic extraction).
  3. **Output:** The resulting HTML, including any malicious code, is returned to the client.

**Security Test Case:**
- **Step 1:** Supply or simulate input (or LLM output) that includes `<script>` tags.
- **Step 2:** Retrieve the final HTML output from the service.
- **Step 3:** Load the HTML in a browser and verify whether the script executes.
- **Step 4:** Confirm that the lack of proper sanitization permits the execution of injected code.
