### Vulnerability Name: Path Traversal in `/evals` Endpoint
**Description**
The `/evals` route in `routes/evals.py` accepts a `folder` parameter without input validation. Attackers can inject paths like `../../etc/passwd` to access arbitrary files on the server.

**Trigger Steps**
1. Send a GET request to `/evals?folder=/etc/passwd`.
2. The backend reads the requested file and returns its contents.

**Impact**
- **Critical system access**: Exposure of sensitive system files or source code.

**Vulnerability Rank**: Critical
**Currently Implemented Mitigations**: None. The code directly uses the supplied path.
**Missing Mitigations**:
- Validate and sanitize the `folder` parameter to prevent path traversal.
- Restrict access to allowed directories using a whitelist.

**Preconditions**: None; the endpoint is publicly accessible.

**Source Code Analysis**:
1. In `routes/evals.py`, the `/evals` endpoint processes the `folder` query parameter.
   ```python
   @app.get("/evals")
   async def get_evals(folder: str = Query(...)):
       # Read the folder contents directly using 'folder' parameter
       ...
   ```
2. The code lacks validation to prevent traversal sequences like `../`, allowing attackers to navigate outside the intended directory.

**Security Test Case**:
1. Use a tool like curl or Postman to send a request:
   ```bash
   curl "http://<app-url>/evals?folder=../../etc/passwd"
   ```
2. Observe if the server returns contents of `/etc/passwd`.

---

### Vulnerability Name: Lack of Rate Limiting for API Key Usage
**Description**
The application does not enforce rate limits on API key usage (whether client-provided or environment variables). Attackers can send excessive requests, leading to quota exhaustion or financial loss.

**Trigger Steps**
1. An attacker floods the `/generate-code` endpoint with requests using a valid API key.
2. The backend processes all requests, depleting API quotas or incurring costs.

**Impact**
- **High financial risk**: Uncontrolled API usage costs.

**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Implement rate limiting based on client IP or API key usage.
- Monitor and alert on unusual API activity.

**Preconditions**: A valid API key (either client-provided or from environment variables).

**Source Code Analysis**:
1. The `routes/generate_code.py` file lacks any rate-limiting logic or middleware.
2. The `/generate-code` endpoint processes all incoming requests without restricting request volume.

**Security Test Case**:
1. Use tools like `ab` (Apache Bench) or a script to send 1000+ requests to `/generate-code` within seconds.
   ```bash
   ab -n 1000 -c 100 http://<app-url>/generate-code
   ```
2. Check if the backend processes all requests without blocking or throttling.

---

The remaining vulnerabilities are included after applying the exclusion criteria.
