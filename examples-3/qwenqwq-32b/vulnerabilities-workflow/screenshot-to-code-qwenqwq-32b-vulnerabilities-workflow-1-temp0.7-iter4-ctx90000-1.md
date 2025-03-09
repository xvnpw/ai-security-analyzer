### Vulnerability Name: CORS Misconfiguration Leading to Cross-Origin Exploitation

**Description**:
The FastAPI backend's CORS middleware allows requests from any origin (`allow_origins=["*"]`). Attackers can exploit this by creating a malicious website that tricks users into making requests to the backend, leveraging the user's session or credentials. For example, attackers can force the backend to generate costly API calls (e.g., using GPT-4) using the victim's session, incurring financial losses for the backend owner.

**Triggering Steps**:
1. The attacker creates a malicious website with JavaScript that sends requests to the backend's `/generate-code` endpoint.
2. A victim visits the attacker's site, which triggers requests using the victim's browser session.
3. The backend processes these requests, treating them as legitimate due to the CORS misconfiguration.

**Impact**:
- Unauthorized resource consumption (financial loss due to paid API usage).
- Potential data leakage if sensitive data is exposed in API responses.

**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None. CORS is configured to allow all origins.
**Missing Mitigations**: Restrict `allow_origins` to specific trusted domains.
**Preconditions**: The backend is publicly accessible and API keys are exposed.
**Source Code Analysis**:
- File `backend/main.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Vulnerable setting
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Security Test Case**:
1. Use curl to send a `GET` request to `http://backend:7001` with a `Origin: attacker.com` header.
2. Verify the response includes `Access-Control-Allow-Origin: attacker.com`, confirming the misconfiguration.

---

### Vulnerability Name: Path Traversal in /evals Endpoints

**Description**:
The `/evals` endpoint directly uses the `folder` parameter in file operations without validation. Attackers can manipulate the parameter to access sensitive files outside the intended directory.

**Triggering Steps**:
1. An attacker sends a request to `/evals` with a malicious `folder` parameter like `folder=/etc`.
2. The backend processes the request, exposing the contents of `/etc` to the attacker.

**Impact**:
- Exposure of sensitive system files (e.g., `/etc/passwd`), leading to credential leakage or configuration discovery.

**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None. No input validation occurs.
**Missing Mitigations**: Sanitize the `folder` parameter using path normalization (e.g., `os.path.abspath` with a base directory).
**Preconditions**: The backend is publicly accessible.
**Source Code Analysis**:
- File `backend/routes/evals.py`:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    folder_path = Path(folder)  # No validation/sanitization
    if not folder_path.exists():
        raise HTTPException(...)
    # Proceed to list files in folder_path
```

**Security Test Case**:
1. Use curl to send a `GET` request to `http://backend:7001/evals?folder=/etc`.
2. Verify the response includes contents of `/etc` or similar sensitive directories.

---

### Vulnerability Name: Exposure of Environment Variables via Debugging

**Description**:
The `config.py` file retrieves API keys from environment variables. If `IS_DEBUG_ENABLED` is `True` in production, debug logs may expose these keys. Additionally, Docker `.env` files might be exposed in the build context.

**Triggering Steps**:
1. The backend is deployed with `IS_DEBUG_ENABLED=True`.
2. An error occurs (e.g., invalid input), and logs include API keys due to unfiltered logging.

**Impact**:
- Exposure of API keys allows attackers to impersonate the service and perform unauthorized operations.

**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Disable debug mode in production; use secret management for environment variables.
**Preconditions**: Debug mode is enabled in production.
**Source Code Analysis**:
- File `backend/config.py`:
```python
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", None)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", None)
IS_DEBUG_ENABLED = bool(os.environ.get("IS_DEBUG_ENABLED", False))
```

**Security Test Case**:
1. Deploy the backend with `IS_DEBUG_ENABLED=True`.
2. Trigger an error (e.g., invalid API key formatting).
3. Inspect logs for exposed API keys (e.g., via `docker logs` or log files).
```

This final list excludes any DoS issues, excludes vulnerabilities caused by explicit insecure code patterns (since the CORS and path traversal are configuration and input validation issues, not explicit "insecure code patterns"), and includes only high-ranked, valid vulnerabilities.
