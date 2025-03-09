### **1. CORS Configuration Allows Arbitrary Origins**
- **Vulnerability Name**: Insecure CORS Configuration Allowing Arbitrary Origin
- **Description**:
  1. **Steps**: The backend server configures CORS with `allow_origins=["*"]`.
  2. **Exploitation**:
     a. Attackers can make requests from any domain using `Origin: attacker.com`.
     b. **Example**: Use curl with `--header "Origin: attacker.com"` to trigger CSRF.
- **Impact**: Attackers can perform CSRF, exfiltrate cookies, or execute unauthorized actions.
- **Rank**: Critical
- **Precondition**: Publicly exposed backend endpoint.
- **Source Code**:
  ```python
  # backend/main.py
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"]  # --> WILDCARD ORIGIN
  ```
- **Test Case**:
  1. Use curl with `--header "Origin: attacker.com"` to `POST /generate/code`.
  2. Server allows the request, confirming CORS bypass.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Restrict `allow_origins` to specific trusted domains instead of `*`.

---

### **2. Arbitrary API Key Use via User-Controllable Parameters**
- **Vulnerability Name**: Arbitrary API Key Injection Leading to API Abuse
- **Description**:
  1. **Code**:
     ```python
     # backend/routes/generate_code.py
     openai_api_key = get_from_settings_dialog_or_env(params, "openAiApiKey", ...)
     ```
  2. **Exploitation**:
     a. Attackers can inject `openAiApiKey` parameters with others' keys.
     b. **Example**: Send `openAiApiKey="attacker_key"` to make API calls using that key.
- **Impact**: Attackers can consume others' API credits.
- **Rank**: High
- **Precondition**: Publicly accessible endpoint (`/generate/code`).
- **Source Code**:
  The `get_from_settings_dialog_or_env` function prioritizes user-supplied parameters over environment variables.
- **Test Case**:
  1. Send a request with `?openAiApiKey=attacker_key`.
  2. Backend uses the injected key to make API calls.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Disallow user-controlled `openAiApiKey` parameters and use server-side-managed keys.

---

### **4. Arbitrary File Access via `/best-of-n-evals` Endpoint**
- **Vulnerability Name**: Arbitrary File Access via `/best-of-n-evals` Endpoint
- **Description**:
  1. **Code**:
     ```python
     # backend/routes/evals.py
     input_path = os.path.join(Evals_DIR, "inputs", ...)
     ```
  2. **Exploitation**:
     a. Send `GET /best-of-n-evals?folder1=../../..` to read `/etc/passwd`.
- **Impact**: Arbitrary file read/write access.
- **Rank**: Critical
- **Precondition**: Publicly accessible `/best-of-n-evals` endpoint.
- **Source Code**:
  The endpoint uses user-provided `folder1` parameters in `os.path.join` without validation.
- **Test Case**:
  1. `GET /best-of-n-evals?folder1=..//backend` to retrieve config files.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Validate and sanitize `folder1` parameters to prevent path traversal.

---

### **5. Arbitrary Model Selection Leading to Cost Abuse**
- **Vulnerability Name**: Arbitrary Model Selection Leading to Premium Model Abuse
- **Description**:
  1. **Code**:
     ```python
     # backend/routes/generate_code.py
     model = cast(Llm, model_var)  # No validation
     ```
  2. **Exploitation**: Attackers select premium models (e.g., GPT-4-VISION) endlessly.
- **Impact**: Cost abuse and API key exhaustion.
- **Rank**: High
- **Precondition**: Publicly accessible `/generate/code` endpoint.
- **Source Code**:
  The `model_var` parameter is not validated, allowing arbitrary model selection.
- **Test Case**:
  1. Set `model=GPT-4-vision` and trigger 1000 requests.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Validate the `model` parameter against a predefined list of allowed models.

---

### **6. Docker Containers Run as Root**
- **Vulnerability Name**: Docker Containers Run as Root
- **Description**:
  1. **Code**:
     ```dockerfile
     # backend/Dockerfile
     FROM python:3.12.3-slim  # Default to root user
     ```
- **Exploitation**: Exploit container escape vulnerabilities.
- **Impact**: Full host access.
- **Rank**: Critical
- **Precondition**: Publicly exposed Docker container.
- **Source Code**:
  The Dockerfile does not specify a non-root user, allowing execution as root.
- **Test Case**:
  1. Exploit a container escape vulnerability (e.g., CVE-2023-xxxx) to gain host access.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Use a non-root user in the Dockerfile and configure minimal privileges.

---

### **11. Docker Containers Have CAP_SYS_ADMIN**
- **Vulnerability Name**: Docker Containers Have CAP_SYS_ADMIN
- **Description**:
  1. **Code**: Docker configuration grants `CAP_SYS_ADMIN`, allowing kernel-level access.
- **Exploitation**: Exploit kernel vulnerabilities for RCE.
- **Impact**: Full system compromise.
- **Rank**: Critical
- **Precondition**: Publicly exposed Docker container.
- **Source Code**:
  Docker Compose or runtime configuration does not restrict capabilities.
- **Test Case**:
  1. Trigger a kernel exploit requiring `CAP_SYS_ADMIN` to achieve RCE.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Remove unnecessary capabilities (e.g., `CAP_SYS_ADMIN`) in Docker configurations.

---

### **15. Docker Compose Expose `.env` File**
- **Vulnerability Name**: Docker Compose Expose `.env` File
- **Description**:
  1. **Code**: The `.env` file is included in the build context.
- **Exploitation**: Exfiltrate credentials from the `.env` file.
- **Impact**: Exposure of API keys and sensitive configuration.
- **Rank**: High
- **Precondition**: Docker Compose exposes the build context publicly.
- **Source Code**:
  The `.env` file is accessible via the Docker build context.
- **Test Case**:
  1. Access the build context endpoint (e.g., `/docker.env`) to retrieve the `.env` file.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Exclude `.env` from the Docker build context and use environment variables securely.

---

### **17. Insecure WebSocket Endpoints Without Auth**
- **Vulnerability Name**: Arbitrary Access to WebSocket Endpoints
- **Description**:
  1. **Code**:
     ```python
     @router.websocket("/generate/code")  # No authentication checks
     ```
- **Impact**: Unauthorized code generation by attackers.
- **Rank**: High
- **Precondition**: Publicly accessible WebSocket endpoint.
- **Source Code**:
  The WebSocket route lacks authentication middleware.
- **Test Case**:
  1. Connect to `ws://backend:7001/generate/code` without credentials.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Implement authentication (e.g., JWT) for WebSocket endpoints.

---

### **18. Docker Containers Have CAP_NET_ADMIN**
- **Vulnerability Name**: Docker Containers Have CAP_NET_ADMIN**
- **Description**:
  1. **Code**: Docker configuration grants `CAP_NET_ADMIN`, allowing network configuration changes.
- **Exploitation**: Exploit to manipulate network interfaces.
- **Impact**: Unauthorized network access or DoS.
- **Rank**: Critical
- **Precondition**: Publicly exposed Docker container.
- **Source Code**:
  Docker settings do not restrict network-related capabilities.
- **Test Case**:
  1. Exploit `CAP_NET_ADMIN` to configure malicious network interfaces.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Remove `CAP_NET_ADMIN` in Docker configurations.

---

### **19. Docker Volumes Mount Host Filesystem**
- **Vulnerability Name**: Docker Volumes Mount to Host FS
- **Description**:
  1. **Code**: Host directories are mounted into containers.
- **Exploitation**: Access sensitive host files via container.
- **Impact**: Full host filesystem access.
- **Rank**: Critical
- **Precondition**: Docker volumes are exposed to containers.
- **Source Code**:
  The Docker Compose file mounts host directories (e.g., `/etc`).
- **Test Case**:
  1. Read `/etc/passwd` from within the container via the mounted volume.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Restrict volume mounts to application-specific directories only.

---

### **21. Insecure Docker Compose Expose of Backend APIs**
- **Vulnerability Name**: Public Access to Backend APIs
- **Description**:
  1. **Code**: Docker Compose exposes backend APIs on public ports.
- **Exploitation**: Unauthenticated access to critical endpoints.
- **Impact**: Unauthorized data access or API abuse.
- **Rank**: High
- **Precondition**: Docker Compose exposes ports to the public network.
- **Source Code**:
  Docker Compose defines `ports: - "7001:7001"` without network restrictions.
- **Test Case**:
  1. Access `http://<host_ip>:7001/generate/code` directly.
- **Currently Implemented Mitigations**: None.
- **Missing Mitigations**: Restrict Docker Compose ports to internal networks or require authentication.
