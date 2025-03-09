# High-Severity Vulnerabilities

---

## Vulnerability Name: Unauthenticated Access to Code Generation WebSocket Endpoint

**Description:**
An attacker can open a WebSocket connection to the publicly exposed “generate‑code” endpoint without any authentication. By sending a properly formatted JSON payload (for example, including keys like “image”, “generatedCodeConfig”, etc.), the attacker can trigger calls to AI models that stream code back over the socket. This enables an adversary to generate code on demand, abusing expensive AI calls. The steps to trigger the vulnerability are as follows:
1. Connect to the WebSocket endpoint located at `/generate-code` on the publicly available instance.
2. Send a valid JSON payload with the necessary keys (e.g., `"image"`, `"generatedCodeConfig"`).
3. Receive code streamed from the server as no authentication or access controls are enforced.

**Impact:**
- **Financial Loss:** Unauthorized usage of expensive AI API calls can lead to significant financial loss as each call may consume costly API credits.
- **Performance Degradation:** Repeated abuse of the endpoint can degrade overall system performance, affecting legitimate users.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- No authentication or access control is enforced on the WebSocket endpoint.
- The developers designed this endpoint to be publicly reachable without enforcing access restrictions.

**Missing Mitigations:**
- **Authentication & Authorization:** Implement authentication and authorization checks so that only approved users can access this service.
- **Rate Limiting & Quotas:** Enforce rate limits and usage quotas to prevent possible abuse.
- **Input Validation & Sanitization:** Validate and sanitize incoming parameters before processing them.

**Preconditions:**
- The application is running in a publicly accessible environment.
- The WebSocket endpoint is accessible at `/generate-code`.
- The attacker must be capable of initiating a WebSocket connection and providing a properly structured JSON payload.

**Source Code Analysis:**
- **File:** `backend/main.py`
  - The FastAPI application is initialized without any authentication middleware.
- **File:** `backend/routes/generate_code.py`
  - The endpoint is defined as:
    ```python
    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        await websocket.accept()
        params: dict[str, str] = await websocket.receive_json()
        # (Parameters are extracted and then directly passed to AI services)
    ```
  - **Observation:** There are no checks to verify the identity or authorization of the client connecting via the WebSocket, which directly enables abuse of the expensive AI operations.

**Security Test Case:**
1. Use a WebSocket client (such as `wscat`) to connect to the endpoint:
   ```
   wscat -c ws://<server>:7001/generate-code
   ```
2. Send a minimal JSON payload (e.g., including the required keys `"image"` and `"generatedCodeConfig"`).
3. Observe that the server streams code back without prompting for any authentication.
4. Confirm via monitoring/logs that there are no rate limits or access controls in place.

---

## Vulnerability Name: Arbitrary File Read via Unvalidated Folder Path in Evaluation Endpoints

**Description:**
Several evaluation endpoints (e.g., GET `/evals` and `/pairwise-evals`) accept a folder name as a query parameter. The provided folder name is used to construct file system paths (using functions like `Path(folder)`, `os.listdir()`, and `open()`) without sanitizing the input or restricting access to a safe directory. An attacker can insert path traversal sequences (for example, `"../../"`) to access files outside of the intended evaluation directory. The steps to trigger the vulnerability are:
1. Send a GET request to the evaluation endpoint with a folder parameter containing a path traversal payload (e.g., `"../../"`).
2. The server constructs the file path directly from the input and retrieves the file list or file contents.
3. Sensitive files outside the allowed directory (configuration files, logs, etc.) may be disclosed.

**Impact:**
- **Information Disclosure:** An attacker can read sensitive files stored on the server, including configuration files and logs.
- **Security Breach:** Access to internal files can aid an attacker in further compromising the system.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- A basic check is performed to ensure that the folder exists (using `Path(folder).exists()`), but no validation is performed to ensure the folder is within a permitted directory.

**Missing Mitigations:**
- **Input Sanitization:** Validate and sanitize the “folder” parameter to ensure that only subdirectories within the allowed evaluation directory (e.g., `./evals_data/`) can be accessed.
- **Authorization Enforcement:** Ensure that only authenticated users with the proper permissions can access evaluation data.

**Preconditions:**
- The evaluation endpoints are publicly accessible without any form of authentication or access control.
- The application process has file-read permissions on directories outside the intended evaluation directory.

**Source Code Analysis:**
- **File:** `backend/routes/evals.py`
  - The GET `/evals` endpoint function starts with:
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder)
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
        # Further processing using os.listdir(folder) and open(file)
    ```
  - **Observation:** The folder parameter is used directly to construct a file path without ensuring that it is a subdirectory of a controlled directory. An attacker can supply relative paths (e.g., `"../../etc"`) to access unauthorized files.

**Security Test Case:**
1. Using a tool like curl or Postman, issue a GET request to the endpoint with a folder parameter containing a path traversal payload:
   ```
   GET http://<server>:7001/evals?folder=../../
   ```
2. Inspect the response to determine if file data (or sensitive file contents) outside the intended evaluation directory is returned.
3. Test with multiple relative path payloads to confirm that the directory traversal vulnerability allows accessing files outside the safe directory.
```

This markdown list contains all the valid, unmitigated vulnerabilities with a vulnerability rank of at least high, and includes the required detailed descriptions, impacts, source code analysis, and security test cases.
