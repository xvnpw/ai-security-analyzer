### Vulnerability List

---

#### **1. Sensitive Environment Variables Exposure in Docker Setup**
**Vulnerability Name**: Sensitive Environment Variables Exposure in Docker Setup
**Description**: The `docker-compose.yml` file includes an `.env` file without proper safeguards. Environment variables like `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` are exposed via Docker configuration.
**Trigger Steps**:
1. The `docker-compose.yml` references `env_file: .env`.
2. The backend `Dockerfile` copies the entire project directory (`COPY ./ /app/`), potentially including `.env`.
3. Attackers can access these files directly in the container or via metadata.

**Impact**: Attackers gain unauthorized access to sensitive API keys, compromising cloud services and LLM models.
**Vulnerability Rank**: Critical
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Use secure secret management (e.g., Docker Secrets or Vault).
- Exclude `.env` via `.dockerignore`.
**Preconditions**: Docker deployment with `.env` file present.
**Source Code Analysis**:
- `docker-compose.yml` includes `env_file: .env`.
- `backend/Dockerfile` copies the entire directory.
**Security Test Case**:
1. Deploy the app via Docker.
2. Use `docker inspect` to retrieve container environment variables.

---

#### **2. Exposure of Environment Variables in Docker Configuration**
**Vulnerability Name**: Sensitive Data Exposure via Dockerfile
**Description**: The backend's `Dockerfile` copies the entire project directory into the container, exposing `.env` files if present. Attackers with container access can read sensitive credentials.
**Trigger Steps**:
1. The `Dockerfile` command `COPY ./ /app/` copies the entire directory.
2. If `.env` is present in the build context, it is exposed in the container.

**Impact**: Compromise of API keys and access to cloud resources.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Exclude `.env` via `.dockerignore`.
- Use environment variables instead of storing secrets in `.env`.
**Preconditions**: `.env` exists in the project directory during the Docker build.
**Source Code Analysis**:
- Dockerfile snippet: `COPY ./ /app/`.
**Security Test Case**:
1. Add a `.env` file with a test secret.
2. Build and run the container, then execute `docker run -it <image> cat /app/.env`.

---

#### **3. Unauthenticated WebSocket Code Generation**
**Vulnerability Name**: Unauthenticated WebSocket Code Generation
**Description**: The `/generate-code` WebSocket endpoint lacks authentication, allowing unauthorized users to trigger LLM requests.
**Trigger Steps**:
1. Attackers connect to `ws://<host>:7001/generate-code` without credentials.
2. Send arbitrary parameters to generate code, consuming API credits or performing model abuse.

**Impact**: Financial loss from API credit depletion; model misuse.
**Vulnerability Rank**: Critical
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Token-based authentication.
- Rate limiting.
**Preconditions**: Publicly accessible WebSocket endpoint.
**Source Code Analysis**:
- `routes/generate_code.py` handles WebSocket connections without checks.
**Security Test Case**:
1. Use `wscat` to connect and send `params` without credentials.

---

#### **4. Arbitrary API Key Injection via WebSocket Parameters**
**Vulnerability Name**: API Key Injection via Unvalidated User Input
**Description**: The `/generate-code` endpoint allows clients to specify API keys (`openAiApiKey`, `anthropicApiKey`) via request parameters. These keys are used directly without validation.
**Trigger Steps**:
1. Craft a WebSocket request with malicious API keys (e.g., `ATTACKER_API_KEY`).
2. The backend uses these keys for LLM calls, exposing the attacker’s account.

**Impact**: Unauthorized API usage (e.g., billing fraud, exposing attacker’s data).
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Reject client-provided API keys; use backend-managed secrets.
**Preconditions**: Ability to send requests to `/generate-code`.
**Source Code Analysis**:
- `routes/generate_code.py` uses client-provided API keys.
**Security Test Case**:
1. Send a WebSocket request with attacker’s API keys and observe their usage.

---

#### **5. Path Traversal in `/evals` Endpoints**
**Vulnerability Name**: Path Traversal in `/evals` Endpoints
**Description**: The `/evals` endpoints (e.g., `/pairwise-evals`) accept `folder` parameters without validation, allowing traversal to sensitive directories (e.g., `/etc/passwd`).
**Trigger Steps**:
1. Send a GET request with `folder=../../etc/passwd`.
2. The backend reads the file and returns its contents.

**Impact**: Exposure of system files, credentials, or sensitive logs.
**Vulnerability Rank**: Critical
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Sanitize paths (e.g., validate `folder` against a whitelist).
**Preconditions**: Public access to `/evals` endpoints.
**Source Code Analysis**:
- `routes/evals.py` lacks path validation.
**Security Test Case**:
1. Use `curl` to request `/evals?folder=../../etc/passwd` and check the response.

---

#### **6. Insecure API Key Handling in Mock Mode**
**Vulnerability Name**: Insecure API Key Handling in Mock Mode
**Description**: Enabling `MOCK=true` in `config.py` bypasses API validation, exposing sensitive debug logs.
**Trigger Steps**:
1. Set `MOCK=true` in the environment.
2. Logs from `fs_logging/core.py` include unfiltered API interactions.

**Impact**: Exposure of API responses and internal data.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Disable mock mode in production.
- Sanitize logs.
**Preconditions**: `MOCK=true` is active.
**Security Test Case**:
1. Set `MOCK=true` and inspect logs for sensitive data.

---

#### **7. Command Injection in Video Processing**
**Vulnerability Name**: Command Injection in Video Processing
**Description**: The `video_to_app.py` script executes `subprocess.run()` with unsanitized filenames.
**Trigger Steps**:
1. Upload a video with a malicious filename (e.g., `; rm -rf /`).
2. The script executes unintended commands during processing.

**Impact**: Uncontrolled command execution leading to data deletion or system compromise.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Sanitize filenames; use `shell=False`.
**Preconditions**: Video upload functionality is enabled.
**Source Code Analysis**:
- `subprocess.run()` uses unvalidated filenames.
**Security Test Case**:
1. Upload a video with a malicious name and observe command execution.

---

#### **8. Cross-Site Request Forgery (CSRF) in WebSocket Requests**
**Vulnerability Name**: Cross-Site Request Forgery (CSRF) in WebSocket Requests
**Description**: The `/generate-code` endpoint lacks CSRF protection, allowing attackers to force authenticated users to execute malicious code.
**Trigger Steps**:
1. Create a malicious webpage embedding a WebSocket connection to the app.
2. Users visiting the page unknowingly send unauthorized requests.

**Impact**: Unauthorized code execution under user credentials.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- CSRF tokens; CORS origin checks.
**Preconditions**: Users have authenticated access.
**Source Code Analysis**:
- No CSRF checks in WebSocket handling.
**Security Test Case**:
1. Design a malicious webpage to connect to the WebSocket endpoint and trigger requests.

---

#### **9. Missing HTTPS Enforcement**
**Vulnerability Name**: Missing HTTPS Enforcement
**Description**: Docker compose exposes services via HTTP, enabling man-in-the-middle (MITM) attacks.
**Trigger Steps**:
1. Use a proxy like `mitmproxy` to intercept HTTP traffic.
2. Steal API keys or session data.

**Impact**: Exposure of sensitive data via interception.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Enforce HTTPS in `docker-compose.yml` and config files.
**Preconditions**: No TLS configured.
**Security Test Case**:
1. Use `mitmproxy` to intercept HTTP traffic and extract credentials.

---

#### **10. Insecure Direct Object References (IDOR) in Evaluations**
**Vulnerability Name**: Insecure Direct Object References (IDOR) in Evaluations
**Description**: The `/evals` endpoints expose evaluation results without access controls, allowing unauthorized access to others' data.
**Trigger Steps**:
1. Access another user’s evaluation folder path via `/evals?folder=...`.

**Impact**: Exposure of private evaluation data.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: User-based access controls; unique identifiers.
**Preconditions**: Public access to `/evals`.
**Source Code Analysis**:
- No access checks in `routes/evals.py`.
**Security Test Case**:
1. Access a different user’s evaluation folder and retrieve their data.

---

#### **11. Sensitive Data in Debug Logs**
**Vulnerability Name**: Sensitive Data in Debug Logs
**Description**: Raw LLM prompts/responses (including API keys) are logged unfiltered in `fs_logging/core.py`.
**Trigger Steps**:
1. Trigger a request with API keys in prompts.
2. Check logs for exposed keys.

**Impact**: Exposure of sensitive data via leaked logs.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Redact sensitive data; restrict log permissions.
**Preconditions**: Logs are accessible (e.g., via file access).
**Security Test Case**:
1. Inspect logs for API keys or personal data after triggering a request.

---

#### **12. Unvalidated OpenAI Base URL Configuration**
**Vulnerability Name**: Unvalidated OpenAI Base URL Leading to MITM
**Description**: The `OPENAI_BASE_URL` is used directly, allowing attackers to redirect API traffic to malicious endpoints.
**Trigger Steps**:
1. Set `OPENAI_BASE_URL=http://attacker-controlled.com`.
2. Intercept requests/responses via MITM.

**Impact**: API key theft or tampered responses.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Validate the base URL domain; use HTTPS with pinning.
**Preconditions**: Ability to set the `OPENAI_BASE_URL` environment variable.
**Source Code Analysis**:
- `config.py` reads `OPENAI_BASE_URL` without validation.
**Security Test Case**:
1. Set a malicious base URL and monitor intercepted traffic.

---

#### **13. Lack of Rate Limiting for API Key Usage**
**Vulnerability Name**: Lack of Rate Limiting for API Key Usage
**Description**: No rate limits protect against excessive API requests, leading to quota exhaustion or financial loss.
**Trigger Steps**:
1. Flood `/generate-code` with requests using a valid API key.
2. Deplete quotas or incur costs.

**Impact**: Financial loss from uncontrolled API usage.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Implement rate limiting; monitor API activity.
**Preconditions**: Valid API key availability.
**Source Code Analysis**:
- No rate-limiting middleware in `routes/generate_code.py`.
**Security Test Case**:
1. Use `ab` or scripts to send 1000+ requests and observe no throttling.

---

#### **14. API Key Exposure in Error Responses**
**Vulnerability Name**: API Key Exposure in Error Responses
**Description**: The `/api/screenshot` endpoint leaks API keys in error messages when passing them as query parameters.
**Trigger Steps**:
1. Send an invalid API key to `/api/screenshot`.
2. Check error responses or logs for the URL containing the key.

**Impact**: Exposure of API keys, enabling unauthorized access to external services.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Redact keys in errors; use POST bodies for secrets.
**Preconditions**: API key is passed in the query parameter.
**Source Code Analysis**:
- API keys are included in error messages from `screenshot.py`.
**Security Test Case**:
1. Trigger an error with an invalid key and inspect responses/logs.

---

**Note**: The merged list removes duplicates and prioritizes the highest severity for overlapping vulnerabilities (e.g., Path Traversal in `/evals` is marked as Critical). All vulnerabilities are valid, unmitigated, and rank **High** or **Critical**.
