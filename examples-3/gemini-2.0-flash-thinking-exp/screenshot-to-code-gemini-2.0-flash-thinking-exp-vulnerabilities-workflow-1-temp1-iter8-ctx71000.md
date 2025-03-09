## Vulnerability List

### Path Traversal in Evals Endpoints

- Vulnerability Name: Path Traversal in Evals Endpoints
- Description:
    - The application exposes endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) in `backend\routes\evals.py` that allow users to retrieve evaluation data.
    - These endpoints take folder paths as input parameters (`folder`, `folder1`, `folder2`, etc.).
    - The application uses `os.listdir()` and `os.path.join()` functions to list files and construct file paths within the user-provided folders.
    - There is insufficient validation or sanitization of the input folder paths.
    - An attacker can provide a malicious folder path containing path traversal sequences (e.g., `../`, `..\\`) to access files and directories outside the intended evaluation folders (`EVALS_DIR`).
    - For example, an attacker could use a path like `../../../../etc/passwd` or `../../../../sensitive_eval_data` to access sensitive system files or evaluation data stored in other directories.
    - This vulnerability allows an attacker to read arbitrary files on the server if the application process has sufficient file system permissions or list directory contents outside of intended directory.

    - **Steps to trigger:**
        1. An external attacker sends a crafted HTTP GET request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoint of the publicly accessible backend application.
        2. The attacker manipulates the `folder`, `folder1`, or `folder2` query parameter in the request, injecting a path traversal sequence like `../../../../etc/passwd`.
        3. The backend application, specifically in the `get_evals` function in `backend\routes\evals.py`, receives this `folder` parameter and uses it in file system operations without proper validation.

- Impact:
    - **High**: Arbitrary File Read and Information Disclosure.
    - An attacker can read arbitrary files from the server's file system.
    - This can lead to the disclosure of sensitive information, including:
        - Application source code.
        - Configuration files, potentially containing API keys or database credentials.
        - Internal evaluation data or results.
        - System files, depending on the server's file system permissions.
    - Attackers could also list directories outside of the intended `EVALS_DIR`, potentially gaining knowledge of the server's file structure.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The code checks if the provided folder exists using `os.path.exists()`. However, this check does not prevent path traversal as it only validates the final resolved path, not the path traversal sequences within the input.
    - The application only reads `.html` and `.png` files. This partially limits the impact but does not prevent reading any `.html` or `.png` file accessible by the application process if path traversal is successful.
    - Directory Existence Check using `folder_path.exists()`.

- Missing Mitigations:
    - **Input validation and sanitization**: Implement robust input validation and sanitization for the folder path parameters.
        - Whitelist approach: Define a restricted set of allowed base directories for evaluations and validate that the user-provided path is within these allowed directories.
        - Path sanitization: Sanitize the input path to remove or neutralize path traversal sequences (e.g., `../`, `..\\`). Use secure path manipulation functions that resolve paths safely and prevent traversal outside allowed directories.
    - **Path Normalization**: Convert the user-provided path to a canonical form to resolve path traversal sequences (e.g., `..`).
    - **Path Confinement**: Ensure the normalized path stays within the intended base directory (e.g., `EVALS_DIR/inputs` or a designated "safe" directory).  Reject requests if the path escapes the base directory.
    - **Secure Path Manipulation:** Utilize secure path manipulation functions provided by the operating system or libraries that prevent traversal (e.g., `os.path.abspath` and checking if it starts with the allowed base path).
    - **Principle of least privilege**: Ensure that the application process runs with the minimum necessary file system permissions to limit the scope of readable files in case of successful path traversal.
    - **Restrict access to eval routes**: Implement authentication and authorization to limit access to these evaluation routes to only authorized users or roles.

- Preconditions:
    - The application must be deployed and accessible to external attackers.
    - An attacker needs to identify and access the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
    - The attacker needs to be able to manipulate the `folder`, `folder1`, `folder2`, etc. query parameters in the HTTP requests to these endpoints.
    - The `screenshot-to-code` backend application is deployed with the `evals.py` routes exposed.
    - An attacker can send HTTP GET requests to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints and control the `folder`, `folder1`, `folder2` query parameters.

- Source Code Analysis:
    - **File:** `..\screenshot-to-code\backend\routes\evals.py`
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str): # [USER INPUT] 'folder' parameter from request
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder) # [PATH CONSTRUCTION] Path object created from user input
        if not folder_path.exists(): # [EXISTENCE CHECK] Checks if the resolved path exists, but allows traversal
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f) # [PATH JOIN] Path is joined using user input
                for f in os.listdir(folder) # [LIST DIRECTORY] Lists files in user provided folder
                if f.endswith(".html")
            }
            # ... (rest of the code) ...
    ```
    - The code directly uses the user-provided `folder` parameters in `os.listdir()` and `os.path.join()` without sufficient validation. The `os.path.exists()` check only verifies if the final path exists, not if the path is within the intended directory, making it vulnerable to path traversal attacks.
    - Similar vulnerable code patterns exist in `/pairwise-evals` and `/best-of-n-evals` endpoints in the same file.

    **Visualization:**

    ```
    [Attacker Request: /evals?folder=../../../etc/passwd] --> backend/routes/evals.py --> get_evals(folder="../../../etc/passwd") --> os.listdir("../../../etc/passwd") --> open("../../../etc/passwd/somefile.html", "r") --> [File Read Attempt Outside Expected Directory] --> [Response with File Content (if successful)]
    ```

- Security Test Case:
    1. Deploy a publicly accessible instance of the `screenshot-to-code` application.
    2. As an attacker, access the `/evals` endpoint by sending a GET request with a malicious `folder` parameter designed to traverse directories. For example:
       ```
       GET /evals?folder=../../../../etc/
       ```
    3. Observe the response from the server. If the server returns a list of files from the `/etc/` directory (or attempts to, potentially encountering permission errors depending on the server setup), it indicates a successful path traversal vulnerability. Check the server logs for file access attempts.
    4. To further confirm the vulnerability and attempt to read a specific sensitive file, try accessing `/evals` with a path like:
       ```
       GET /evals?folder=../../../../etc/passwd
       ```
       or for pairwise-evals:
       ```
       GET /pairwise-evals?folder1=../../../../etc/passwd&folder2=../../../../etc/passwd
       ```
       or for best-of-n-evals:
       ```
       GET /best-of-n-evals?folder1=../../../../etc/passwd
       ```
    5. Analyze the response. If the server returns content that resembles the `/etc/passwd` file (or an error indicating file access was attempted), it confirms the path traversal vulnerability.
    6. For a more controlled test:
        - Setup: Create a folder `/tmp/test_evals_outside` and place a file named `test.html` with content `<h1>External Eval File</h1>` inside it (`/tmp/test_evals_outside/test.html`).
        - Trigger Vulnerability: Send a GET request to the `/evals` endpoint with the `folder` parameter pointing to the externally created folder: `/evals?folder=/tmp/test_evals_outside`.
        - Analyze Response: Examine the response from the `/evals` endpoint. If the vulnerability is present, the response should include an `Eval` object containing the content of `/tmp/test_evals_outside/test.html`.

====================================================================================================

### Unprotected Evaluation and Code Generation Endpoints leading to API Key Abuse

- Vulnerability Name: Unprotected Evaluation and Code Generation Endpoints leading to API Key Abuse
- Description:
    - An external attacker discovers and accesses unprotected evaluation REST API endpoints (`/api/run_evals`, `/api/evals`, `/api/pairwise-evals`, `/api/best-of-n-evals`) and the code generation WebSocket endpoint (`/generate-code`).
    - These endpoints lack authentication and authorization mechanisms.
    - An attacker can craft requests to these endpoints to trigger evaluation or code generation processes.
    - These processes utilize the application's configured API keys (e.g., OpenAI, Anthropic, Gemini) to interact with external AI services.
    - By repeatedly triggering these processes, the attacker can abuse the project's API keys, leading to unexpected API usage costs and potential exposure of API keys.

    - **Steps to trigger:**
        1. An external attacker accesses the publicly available instance of the application.
        2. The attacker discovers unprotected evaluation and code generation endpoints:
            - REST API endpoint: `/api/run_evals` (POST)
            - WebSocket endpoint: `/generate-code`
        3. For the REST API endpoint, the attacker crafts a POST request to `/api/run_evals` to trigger evaluation runs.
        4. For the WebSocket endpoint, the attacker establishes a WebSocket connection to `/generate-code` and sends a JSON message to initiate code generation.

- Impact:
    - **High**: Financial Impact and Resource Exhaustion, Potential API Key Leakage.
    - **Financial Impact:** The attacker can cause unexpected and potentially significant financial charges by abusing the project's API keys for AI services.
    - **Resource Exhaustion:** Repeated requests can consume server resources, impacting application performance.
    - **Potential API Key Leakage:** Inadvertent exposure of API keys through logs or processes could lead to broader malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None apparent. The evaluation REST API endpoints and code generation WebSocket endpoint are exposed without any access control mechanisms.

- Missing Mitigations:
    - **Authentication and Authorization:** Implement authentication to verify user identity and authorization to restrict access to evaluation and code generation endpoints to authorized users.
    - **Rate Limiting:** Implement rate limiting on both REST API and WebSocket endpoints to restrict the number of requests from a single IP address or user within a timeframe, mitigating abuse.
    - **Input Validation and Sanitization:** Thoroughly validate and sanitize inputs to prevent unexpected behavior or injection vulnerabilities.
    - **API Key Security:** Ensure API keys are securely managed, not logged or exposed, and consider regular rotation.
    - **Monitoring and Alerting:** Implement monitoring for unusual activity on these endpoints (high request rates, unusual input patterns) and set up alerts for potential abuse.

- Preconditions:
    - The application must have a publicly accessible instance.
    - Unprotected evaluation REST API and code generation WebSocket endpoints must be exposed without authentication or authorization.
    - The evaluation and code generation functionalities must utilize the application's API keys.

- Source Code Analysis:
    - **`backend/main.py`:** Includes routers for `evals` and `generate_code`, exposing their endpoints.
    - **`backend/routes/evals.py`:** Defines REST API endpoints under `/api/evals`, including `/run_evals` (POST) which directly uses API keys. No authentication or authorization is implemented.
    - **`backend/routes/generate_code.py`:** Defines a WebSocket endpoint `/generate-code` which triggers code generation using API keys. No authentication or authorization is implemented.
    - **`backend/evals/core.py` and `backend/llm.py`:** Contain functions that use API keys (e.g., `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`) when calling LLM services.
    - **Absence of Authentication/Authorization Code:** None of the provided files contain explicit code implementing authentication or authorization.

- Security Test Case:
    1. Deploy the `screenshot-to-code` application in a publicly accessible environment.
    2. **Test for REST API Endpoint (/api/run_evals):**
        - Send a POST request to `/api/run_evals` endpoint with a JSON body like `{"models":["gpt-4o"], "stack":"react"}` using `curl` or `Postman`.
        - Monitor API usage dashboards for AI services (OpenAI, Anthropic, Gemini, Replicate) and observe if usage increases.
        - Repeat requests and observe if API usage continues to increase.
    3. **Test for WebSocket Endpoint (/generate-code):**
        - Establish a WebSocket connection to `/generate-code` (e.g., using a WebSocket client or browser's developer console).
        - Send a JSON message through the WebSocket connection to trigger code generation, e.g., `{"inputMode": "screenshot", "screenshot": "data:image/png;base64,...", "generatedCodeConfig": "react", "isImageGenerationEnabled": false}`.
        - Monitor API usage dashboards for AI services and observe if usage increases.
        - Send multiple code generation requests and observe if API usage continues to increase.
    4. If API usage increases without legitimate user activity for both tests, it confirms unprotected endpoints and API key abuse.

====================================================================================================

### API Key Exposure via Debug Logs

- Vulnerability Name: API Key Exposure via Debug Logs
- Description:
    - If debug mode is enabled (`IS_DEBUG_ENABLED=True`), the application writes detailed debug logs, including full LLM streams to files in the `DEBUG_DIR`.
    - The `pprint_prompt` function logs full JSON prompts to standard output if debug mode is enabled.
    - If API keys or other sensitive information are inadvertently included in prompts or LLM responses and debug logging is active, these secrets could be logged in plain text.
    - If the debug directory or standard output logs are publicly accessible or can be accessed by an attacker, these log files could be read, leading to the exposure of sensitive API keys.

    - **Steps to trigger:**
        1. An attacker gains access to publicly exposed debug logs (e.g., due to misconfigured web server).
        2. The application is configured with `IS_DEBUG_ENABLED=true`.
        3. The application logs prompts or full LLM streams when interacting with AI services.
        4. Sensitive information like API keys is inadvertently logged.
        5. The attacker extracts API keys from the accessible debug logs.

- Impact:
    - **High**: Compromise of API keys.
    - If OpenAI, Anthropic, Gemini or Replicate API keys are exposed, an attacker could:
        - Consume the victim's API credits, leading to financial costs.
        - Potentially gain access to other services or data associated with the exposed API keys.
        - Incur significant costs for the application owner due to unauthorized API usage.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - API keys are stored as environment variables, which is a security best practice.
    - The application is intended to store API keys only client-side when users input them in settings.

- Missing Mitigations:
    - **Restrict access to the `DEBUG_DIR`**: Ensure `DEBUG_DIR` is not publicly accessible by hardening web server configurations and cloud storage permissions.
    - **Disable debug logging in production**: Set `IS_DEBUG_ENABLED` to `false` by default and enforce this in production deployments.
    - **Sensitive data redaction in logs**: Implement input sanitization or redaction techniques to remove or mask sensitive information, especially API keys, from log messages. Filter API keys from `pprint_prompt` and other logging mechanisms.
    - **Secure logging practices:** Implement filtering or scrubbing of sensitive data from debug logs before writing them to disk.
    - **Regular security audits**: Conduct periodic security reviews to identify and remediate potential vulnerabilities, including misconfigurations leading to log exposure.

- Preconditions:
    - `IS_DEBUG_ENABLED` environment variable is set to `True` in a publicly accessible instance.
    - Sensitive information (API keys) is inadvertently included in the prompts or messages sent to the LLM.
    - The debug directory specified by `DEBUG_DIR` or standard output logs are accessible to external attackers.

- Source Code Analysis:
    - **`backend/config.py`**: Defines `IS_DEBUG_ENABLED` and `DEBUG_DIR` based on environment variables.
    - **`backend/debug/DebugFileWriter.py`**: `DebugFileWriter` is active only if `IS_DEBUG_ENABLED` is true and writes to `DEBUG_DIR`.
    - **`backend/llm.py`**: `DebugFileWriter` is instantiated in `stream_claude_response_native`. The entire `full_stream` (raw response from Claude API) is written to `full_stream.txt` if `IS_DEBUG_ENABLED` is true. `pprint_prompt` is called in `stream_openai_response` if `IS_DEBUG_ENABLED` is true.
    - **`backend/utils.py`**: `pprint_prompt` serializes `prompt_messages` to JSON and prints it to standard output using `print`.

    **Visualization:**

    ```
    [Request to Backend] --> backend/llm.py --> pprint_prompt(messages) --> utils.py:print(json.dumps(messages)) --> [Standard Output/Logs] --> [Debug Log Files in DEBUG_DIR (if IS_DEBUG_ENABLED)] --> [Publicly Accessible DEBUG_DIR due to Misconfig] --> Attacker Access --> API Key Extraction
    ```

- Security Test Case:
    1. **Setup:** Deploy the application in a test environment with `IS_DEBUG_ENABLED=True` and simulate public access to debug logs (e.g., expose `DEBUG_DIR` via web server misconfiguration).
    2. **Trigger:** Send a request to generate code, ensuring environment variables (including API keys) are set. Use Claude models to trigger logging in `stream_claude_response_native` or any LLM call to trigger `pprint_prompt`.
    3. **Access Debug Logs:** As an attacker, access `full_stream.txt` within `DEBUG_DIR` (or standard output logs depending on setup) from the publicly exposed location.
    4. **Verify API Key Exposure:** Open `full_stream.txt` or standard output logs and check if OpenAI, Anthropic, Gemini, or Replicate API keys are present. If found, the vulnerability is confirmed.

====================================================================================================

### Permissive CORS Configuration

- Vulnerability Name: Permissive CORS Configuration
- Description:
    - The backend application is configured with a permissive Cross-Origin Resource Sharing (CORS) policy, allowing requests from any origin (`allow_origins=["*"]`).
    - This bypasses the Same-Origin Policy, enabling any website to make cross-origin requests to the backend API.
    - An attacker can host a malicious website that makes unauthorized requests to the backend API on behalf of a victim user.
    - This could lead to various attacks, including unauthorized API usage, cross-site request forgery (CSRF) if sessions or cookies are used for authentication, or information disclosure if sensitive data is exposed through APIs.

    - **Steps to trigger:**
        1. An attacker hosts a malicious website on a different domain or port than the frontend application.
        2. The victim user visits the malicious website in their browser.
        3. The malicious website executes JavaScript code to make cross-origin requests to the vulnerable backend API.
        4. Due to the permissive CORS configuration (`allow_origins=["*"]`), the backend allows these cross-origin requests.

- Impact:
    - **High**: Increased CSRF risk, Unauthorized API access, Information disclosure.
    - **Cross-site request forgery (CSRF):** Permissive CORS increases CSRF risk if sessions or cookies are used for authentication.
    - **Unauthorized API access:** Any website can utilize the API, potentially leading to abuse of paid services.
    - **Information disclosure:** Malicious sites can access sensitive data exposed through API endpoints due to relaxed CORS policy.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The application explicitly sets permissive CORS using `allow_origins=["*"]`.

- Missing Mitigations:
    - **Restrict `allow_origins`**: Configure `allow_origins` in `backend/main.py` to specific, trusted origins, such as the frontend domain (e.g., `allow_origins=["https://your-frontend-domain.com"]`).
    - **Origin-based Whitelisting**: Instead of a wildcard, explicitly list allowed origins.
    - **Implement proper authentication and authorization**: Implement authentication and authorization to further protect API endpoints, regardless of CORS policy.

- Preconditions:
    - The `screenshot-to-code` backend application is deployed with the default permissive CORS configuration (`allow_origins=["*"]`) in `backend/main.py`.
    - The frontend and backend are intended to be served from different origins, or the application aims to control cross-origin access.

- Source Code Analysis:
    - **File:** `backend/main.py`
    ```python
    from fastapi.middleware.cors import CORSMiddleware

    # Configure CORS settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    - `CORSMiddleware` is instantiated with `allow_origins=["*"]`, allowing all origins to bypass CORS restrictions. `allow_credentials=True`, `allow_methods=["*"]`, and `allow_headers=["*"]` further widen the permissive nature.

    **Visualization:**

    ```
    [Browser (malicious-website.com)] --> [Request to screenshot-to-code Backend API]
           ^
           | CORS Check (Permissive: allow_origins=["*"])
           |
    [screenshot-to-code Backend] --> [Response allowed due to permissive CORS]
    ```

- Security Test Case:
    1. Deploy the backend application with the default CORS configuration in `backend/main.py`.
    2. Create a malicious HTML file (malicious.html) and host it on a different domain or port.
    3. Include JavaScript in `malicious.html` to make a cross-origin request to the `/generate-code` endpoint of the backend.
    4. Open `malicious.html` in a web browser from `http://malicious-website.com`.
    5. Click a button to trigger the cross-origin request.
    6. Observe that the request is successful and no CORS errors are reported in the browser's developer console, confirming permissive CORS.

====================================================================================================

### Potential Server-Side Request Forgery (SSRF) via Gemini API image URL

- Vulnerability Name: Potential Server-Side Request Forgery (SSRF) via Gemini API image URL
- Description:
    - The `stream_gemini_response` function in `backend/llm.py` processes user-provided messages and extracts image URLs.
    - When calling the Gemini API, the application uses these image URLs to fetch images server-side.
    - If an attacker can control the input messages and inject a malicious `image_url` (non-`data:` URL), the Gemini API server-side might attempt to access this attacker-controlled URL.
    - This can lead to Server-Side Request Forgery (SSRF), allowing interaction with internal resources or external services from the server hosting the Gemini API call.

    - **Steps to trigger:**
        1. As an attacker, set up a malicious server to monitor requests or prepare an internal resource URL.
        2. Initiate a code generation request through the application, selecting a Gemini model.
        3. Craft a request that includes a message with a malicious `image_url` (e.g., `http://attacker.example.com/ssrf-test`).
        4. Submit this crafted request to the application.
        5. The backend calls `stream_gemini_response` with the user-provided messages.
        6. Within `stream_gemini_response`, the malicious URL is extracted and used in a call to the Gemini API.
        7. The Gemini API server-side makes an HTTP request to the attacker-specified URL.
        8. The attacker observes this interaction through server logs or potentially gains access to internal resources.

- Impact:
    - **High**: Access to Internal Resources, Internal Port Scanning, Information Disclosure, Chain Attacks.
    - Attackers could potentially access internal services or data behind the server's firewall.
    - Internal port scanning to identify open ports and services.
    - Information disclosure by accessing sensitive files or internal application configurations.
    - SSRF can be a stepping stone for more severe attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - No specific mitigations for SSRF are evident. The application processes image URLs without input validation or sanitization against SSRF attacks.

- Missing Mitigations:
    - **Input Validation and Sanitization for URLs**: Implement robust validation for user-supplied URLs.
        - **URL Schema Whitelisting**: Restrict allowed URL schemas to `data:` URLs only, or a very limited whitelist. Block `http://`, `https://` if external URLs are not intended.
        - **URL Format Validation**: Validate URL format for safe patterns.
        - **Content-Type Validation (if external URLs are allowed)**: If external URLs must be supported, validate the `Content-Type` of the response from fetched URLs to confirm they are images.
    - **Network Segmentation**: Isolate the backend server from sensitive internal networks.
    - **Principle of Least Privilege**: Run the backend service with minimal necessary permissions.

- Preconditions:
    - The application is configured to use a Gemini model.
    - An attacker can influence the image input, ideally by providing or manipulating an image URL parameter.

- Source Code Analysis:
    - **File:** `backend/routes/generate_code.py`, Function: `stream_code` (WebSocket handler) calls `stream_gemini_response`.
    - **File:** `backend/llm.py`, Function: `stream_gemini_response` processes messages, extracts `image_url`, and uses it in Gemini API calls. The code lacks validation for non-`data:` URLs, leading to potential SSRF.

- Security Test Case:
    1. **Set up a controlled server:** Register a domain (e.g., `attacker.example.com`) and configure a web server to log all incoming HTTP requests.
    2. **Craft a malicious image URL:** Construct a URL pointing to your controlled server: `http://attacker.example.com/ssrf-test`.
    3. **Prepare the SSRF payload:** Access the application's frontend, select Gemini model, and find a way to include or inject a message with the malicious URL.
    4. **Send the request:** Submit the crafted request to the application via the websocket connection.
    5. **Monitor for SSRF:** Check the logs of your controlled server (`attacker.example.com`) for a new HTTP request to `http://attacker.example.com/ssrf-test` originating from the application's backend server.
    6. **Analyze results:** If an HTTP request is logged, SSRF vulnerability is confirmed.

**Remediation:** Implement **Missing Mitigations**, especially **Input Validation and Sanitization for URLs** in `stream_gemini_response`. Restricting input to `data:` URLs is the most secure approach.
