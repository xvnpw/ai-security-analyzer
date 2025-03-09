# High‑Risk Vulnerabilities

Below is the updated list of vulnerabilities that are valid, not mitigated, and have a vulnerability rank of at least High. These vulnerabilities are exploitable by an external attacker targeting a publicly available instance of the application.

---

## 1. Arbitrary File Disclosure via Unvalidated Folder Parameter in Eval Endpoints

**Description:**
The eval endpoints (such as the GET “/evals”, “/pairwise-evals” and “/best-of-n-evals” in `backend/routes/evals.py`) accept a folder path via user‑controlled query parameters without any validation or sanitization. An attacker can supply an arbitrary folder path (or use directory traversal sequences) to force the API to list and read files from unintended directories on the server.
**Step‑by‑step trigger process:**
1. An attacker sends a GET request to `/evals?folder=<malicious folder path>`, for example, specifying a system directory or using sequences like `../` to traverse directories.
2. The endpoint creates a `Path(folder)` object from the supplied value and then calls `os.listdir(folder)` without verifying that the folder is within an allowed or safe directory.
3. The code filters for files ending in “.html” and returns their contents as part of a JSON response.
4. As a result, if sensitive HTML or other configuration files reside in that folder, their contents will be disclosed to the attacker.

**Impact:**
An attacker can retrieve confidential information from the server’s filesystem (such as internal web pages, configuration files, or other HTML documents). This can lead to further exploitation steps including lateral movement or more sophisticated attacks based on the exposed data.

**Vulnerability Rank:**
High

**Currently Implemented Mitigations:**
There is no sanitization or restriction applied on the user‑supplied folder path.

**Missing Mitigations:**
- Input validation and sanitization for folder path parameters.
- Restrict file access to a dedicated, safe directory (e.g., a specified evals folder).
- Implement whitelisting or canonicalization to ensure only approved directories are accessed.

**Preconditions:**
- The eval endpoints are publicly accessible.
- An attacker is able to supply arbitrary folder paths via query parameters.
- The server's filesystem contains sensitive or unintended HTML files that are readable.

**Source Code Analysis:**
- In `backend/routes/evals.py`, the endpoint `/evals` retrieves the query parameter `folder` without checking it against a whitelist.
- Code snippet analysis:
  - `folder_path = Path(folder)` is executed directly on the input.
  - The function then uses `os.listdir(folder)` to list files in the specified directory.
  - The code proceeds to filter files by checking for the “.html” extension and reads these files for output.
- Similar handling exists in the `/pairwise-evals` and `/best-of-n-evals` endpoints.
- Since there is no sanitization or boundary check, an attacker can trigger disclosure by supplying a malicious folder path.

**Security Test Case:**
1. Send a GET request to `/evals?folder=/etc` (or any directory known to contain sensitive files) using a tool like cURL or a web browser.
2. Confirm that the JSON response includes file names and file contents from that directory.
3. Attempt to inject directory traversal sequences (e.g., `/evals?folder=../`) to verify that the endpoint does not restrict navigation outside the expected directory.
4. Validate that unintended HTML files are disclosed, demonstrating the vulnerability.

---

## 2. Lack of Authentication on Code Generation and Screenshot Endpoints

**Description:**
Critical endpoints, namely the POST `/api/screenshot` endpoint (in `backend/routes/screenshot.py`) and the WebSocket `/generate-code` endpoint (in `backend/routes/generate_code.py`), are exposed publicly without any authentication or authorization. An attacker can directly connect to these endpoints and invoke their functionalities (such as generating code via third‑party LLM calls or capturing remote screenshots) without proper credentials.
**Step‑by‑step trigger process:**
1. An attacker opens a WebSocket connection to `/generate-code` or sends a POST request to `/api/screenshot` using cURL, Postman, or another HTTP client.
2. The attacker submits a valid JSON payload (or WebSocket message) to invoke code generation or screenshot capture.
3. The endpoints process the request (invoking external APIs like GPT‑4, Claude, or screenshotone.com) and return the generated content without validating the identity of the requester.

**Impact:**
- Unauthorized use of these endpoints can lead to resource exhaustion and unexpected financial costs due to premium API calls.
- The service may be abused to generate malicious outputs or to launch further attacks, and the lack of authentication compromises the principle of least privilege.

**Vulnerability Rank:**
High (potentially Critical if the associated costs and abuse are significant)

**Currently Implemented Mitigations:**
- CORS is configured to allow all origins (`allow_origins=["*"]`), but no authentication or rate limiting is enforced at the endpoint level.

**Missing Mitigations:**
- Implement proper authentication and authorization (e.g., OAuth tokens or API keys) to restrict endpoint access.
- Add rate limiting to prevent abuse and resource exhaustion.
- Segregate administrative and public endpoints to follow the principle of least privilege.

**Preconditions:**
- The application is deployed in a publicly accessible environment.
- The endpoints accept requests without verifying user credentials.
- An attacker can directly establish WebSocket connections or make HTTP requests to these endpoints.

**Source Code Analysis:**
- In `backend/main.py`, the FastAPI app is configured with CORS allowing all origins; no routers apply any in‑code authentication checks.
- In `backend/routes/screenshot.py`, the POST `/api/screenshot` endpoint simply parses a JSON body containing a URL and an API key, then calls the screenshot service.
- In `backend/routes/generate_code.py`, the WebSocket endpoint accepts incoming JSON parameters to build prompts and stream responses without any identity verification.

**Security Test Case:**
1. Use a WebSocket client or browser developer tools to connect to `ws://<server>:7001/generate-code`.
2. Send a properly formatted JSON message and verify that the endpoint accepts and processes it without requiring any credentials.
3. Similarly, send a POST request to `/api/screenshot` with valid values for `url` and `apiKey` and observe that the response (e.g., a base64-encoded image) is returned without authentication challenges.
4. Confirm that unauthorized access is possible, thereby validating the vulnerability.

---

## 3. Insecure Handling of User‑Supplied API Keys in the Screenshot Endpoint

**Description:**
The `/api/screenshot` endpoint in `backend/routes/screenshot.py` accepts an API key supplied in the request body (`apiKey` field) and directly uses it to call an external screenshot service. This design requires users to submit their sensitive third‑party API keys over the network in clear text, and the server relays them without any server‑side verification, exposing the keys to potential interception.
**Step‑by‑step trigger process:**
1. An attacker or legitimate user sends a POST request to `/api/screenshot` with a JSON payload that includes `{ "url": "http://example.com", "apiKey": "sk-..." }`.
2. The server extracts the API key from the received JSON and immediately injects it into the HTTP request to `https://api.screenshotone.com/take`.
3. If an attacker manages to intercept the HTTP traffic (e.g., via a man‑in‑the‑middle attack), the API key is exposed in clear text and can be misused.

**Impact:**
- Exposed third‑party API keys can be captured and exploited by attackers to make unauthorized requests, leading to unexpected costs and service abuse.
- The confidentiality of sensitive credentials is undermined, potentially leading to broader security compromises.

**Vulnerability Rank:**
High

**Currently Implemented Mitigations:**
- The project documentation advises that the API key “only stored in your browser.” Despite this, the endpoint still accepts and transmits the user-supplied API key in clear text to the external service.

**Missing Mitigations:**
- The endpoint should avoid using user-supplied API keys; instead, API keys should be securely stored on the server or supplied via an authenticated configuration.
- Enforce HTTPS for all communications and implement authentication checks to ensure the integrity of API key handling.

**Preconditions:**
- The `/api/screenshot` endpoint is publicly accessible and accepts API keys in its JSON payload.
- An attacker can intercept network traffic or perform a man‑in‑the‑middle attack.

**Source Code Analysis:**
- In `backend/routes/screenshot.py`, the `ScreenshotRequest` model defines two fields: `url` and `apiKey`.
- The endpoint function (e.g., `app_screenshot`) retrieves these fields directly from the incoming request and passes the `apiKey` to the `capture_screenshot` function, which makes an HTTP call to the external screenshot service.
- There is no server‑side verification, transformation, or obfuscation of the API key before it is transmitted.

**Security Test Case:**
1. Intercept a POST request to `/api/screenshot` using a proxy tool like Burp Suite, ensuring the JSON payload contains a valid API key.
2. Verify that the API key is transmitted exactly as provided, without any encryption or masking.
3. Attempt to reuse the captured API key in a separate request (or directly against the third‑party API) to determine whether it can be exploited.
4. Confirm that the API key’s exposure and subsequent misuse validate the vulnerability.
