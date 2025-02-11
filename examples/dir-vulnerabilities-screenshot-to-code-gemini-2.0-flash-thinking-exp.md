### Vulnerability List

- Vulnerability Name: Permissive Cross-Origin Resource Sharing (CORS) Configuration

- Description:
    1. An attacker hosts a malicious website on their own domain (e.g., `attacker.com`).
    2. The attacker crafts JavaScript code on their malicious website to make requests to the vulnerable application's backend API (e.g., `screenshottocode.com/api/generate_code`).
    3. Due to the permissive CORS configuration `allow_origins=["*"]`, the browser, upon receiving the response from `screenshottocode.com`, will not block the JavaScript code on `attacker.com` from accessing the response content.
    4. The attacker can then extract potentially sensitive data from the API response, or perform actions on behalf of a legitimate user if the API is not properly secured with authentication and authorization mechanisms beyond CORS.

- Impact:
    - **Medium**: Information Disclosure, Cross-Site Scripting (XSS) like attacks, and potential Cross-Site Request Forgery (CSRF) if combined with other vulnerabilities or missing security measures in the backend API. While CORS is meant to prevent malicious scripts from *reading* cross-origin responses, a wildcard `"*"` origin policy effectively disables this protection for all origins. This could allow attackers to probe the API, potentially extract non-sensitive data, or prepare for more sophisticated attacks. If the API were to return sensitive information without proper authentication, this vulnerability would become significantly more severe.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The code explicitly sets `allow_origins=["*"]` in `backend/main.py`, which disables CORS protection.
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```

- Missing Mitigations:
    - **Restrict `allow_origins`**: Instead of `"*"` which allows all origins, the `allow_origins` should be restricted to a specific list of trusted domains, such as the frontend's domain (`screenshottocode.com` or `localhost` for development). For development, it can conditionally include `localhost` origins.
    - **Proper Backend Authentication and Authorization**: While CORS helps, it's not a substitute for proper backend security. Ensure that API endpoints that handle sensitive data or actions require authentication and authorization to prevent unauthorized access, regardless of CORS policy.

- Preconditions:
    - The application backend must be publicly accessible.
    - The permissive CORS configuration `allow_origins=["*"]` must be in place.

- Source Code Analysis:
    - File: `backend/main.py`
    - Line:
    ```python
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    - The `CORSMiddleware` is added to the FastAPI application with `allow_origins` set to `"*"` . This configuration tells the browser to allow requests from any origin to access resources from this backend.

- Security Test Case:
    1. **Setup Attacker Website**: Create a simple HTML file on `attacker.com` with the following JavaScript code:
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attacker Website</title>
    </head>
    <body>
        <h1>Malicious Website</h1>
        <button id="fetchData">Fetch API Data</button>
        <div id="output"></div>

        <script>
            document.getElementById('fetchData').addEventListener('click', function() {
                fetch('http://localhost:7001/api/generate-code', { // Replace with the actual backend URL if not running locally, e.g., 'https://screenshottocode.com/api/generate-code'
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        image: 'data:image/png;base64, ...some_dummy_image_data...', // Replace with a dummy base64 image
                        stack: 'html_tailwind'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('output').innerText = JSON.stringify(data, null, 2);
                })
                .catch(error => {
                    document.getElementById('output').innerText = 'Error: ' + error;
                });
            });
        </script>
    </body>
    </html>
    ```
    2. **Access Attacker Website**: Open `attacker.com` in a browser.
    3. **Click "Fetch API Data"**: Click the button on the attacker's webpage.
    4. **Observe Output**: Check the "output" div on `attacker.com`. If the request to `http://localhost:7001/api/generate-code` (or the actual backend URL) is successful and the response data (even if it's an error or mock response) is displayed on `attacker.com`, it confirms that the permissive CORS policy is allowing cross-origin requests and access to the response. In a real scenario, a successful response containing generated code would be accessible to the attacker's script.

---

- Vulnerability Name: Local File Inclusion (LFI) in Evals Endpoints

- Description:
    1. An attacker identifies that the application exposes endpoints `/evals`, `/pairwise-evals`, and `/best-of-n-evals` which take folder paths as query parameters (`folder`, `folder1`, `folder2`, etc.).
    2. The attacker crafts a malicious URL to access one of these endpoints, providing a manipulated `folder` parameter that points to a location outside of the intended evaluation directories, potentially using path traversal techniques like `../` to navigate up the directory structure.
    3. The backend application, due to insufficient input validation and sanitization of the `folder` parameter, uses the attacker-controlled path to list files and read file contents.
    4. The attacker can then potentially read arbitrary files from the server's filesystem that the backend application has access to, by crafting the path to point to sensitive files.

- Impact:
    - **High**:  Confidential Information Disclosure. An attacker can read sensitive files from the server, potentially including application source code, configuration files, environment variables, or other sensitive data, depending on file system permissions and the application's access rights. This can lead to further attacks, such as exposing credentials, API keys, or internal application logic.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The application directly uses the user-provided folder paths without validation or sanitization in the `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` endpoints in `backend/routes/evals.py`.

- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement strict validation on the `folder` parameters to ensure they conform to expected formats and do not contain path traversal sequences like `../`. Sanitize the input paths to remove or neutralize any path traversal attempts.
    - **Path Normalization**: Normalize the user-provided paths to resolve symbolic links and remove redundant path separators and components like `.` and `..` before using them to access the file system. This can help prevent attackers from bypassing path traversal checks.
    - **Restrict Access**: Limit the directories that the application is allowed to access for evaluation purposes to a specific, controlled directory or set of directories. Use secure file access methods that respect these restrictions.
    - **Principle of Least Privilege**: Ensure that the application runs with the minimum necessary privileges to access files on the server. Avoid running the application as a highly privileged user (like root).

- Preconditions:
    - The application backend must be publicly accessible.
    - The endpoints `/evals`, `/pairwise-evals`, or `/best-of-n-evals` must be accessible without authentication (or with easily bypassed authentication).
    - The backend application must have file system read permissions to the files the attacker is trying to access.

- Source Code Analysis:
    - File: `backend/routes/evals.py`
    - Endpoint: `/evals` (and similar in `/pairwise-evals`, `/best-of-n-evals`)
    - Lines (example from `/evals`):
    ```python
    @router.get("/evals", response_model=list[Eval])
    async def get_evals(folder: str):
        if not folder:
            raise HTTPException(status_code=400, detail="Folder path is required")

        folder_path = Path(folder)
        if not folder_path.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

        try:
            evals: list[Eval] = []
            # Get all HTML files from folder
            files = {
                f: os.path.join(folder, f)
                for f in os.listdir(folder) # Vulnerable line: os.listdir(folder)
                if f.endswith(".html")
            }
            # ... rest of the code using 'files' ...
    ```
    - The code takes the `folder` query parameter directly and uses it in `os.listdir(folder)` and `os.path.join(folder, f)` without proper validation. An attacker can provide a path like `/etc/` or `/app/../sensitive_folder/` to access files outside the intended evaluation directories. The `Path(folder).exists()` check only verifies if the path exists but does not prevent path traversal.

- Security Test Case:
    1. **Identify an LFI endpoint**: Determine the base URL of the application and identify the `/evals` endpoint (or `/pairwise-evals`, `/best-of-n-evals`).
    2. **Craft a malicious URL**: Construct a URL that includes a path traversal payload in the `folder` parameter to attempt to access a known file outside the expected evaluation directories. For example, if the application is running on Linux, try to access `/etc/passwd`. Example URL: `http://localhost:7001/evals?folder=../../../etc/`.
    3. **Send the malicious request**: Use a browser or a tool like `curl` or `Postman` to send a GET request to the crafted URL.
    4. **Analyze the response**: Examine the response from the server.
        - If the application successfully processes the request and returns a response that includes data from `/etc/passwd` (or another targeted sensitive file), it confirms the LFI vulnerability. The response might contain file contents embedded in the `evals` data structure, or error messages that reveal file access.
        - If the application returns an error indicating "Folder not found" or similar, it might still be vulnerable, but the path might not be correctly constructed or the application might not have permissions to access the target file. Try different path traversal techniques and file paths.
        - If the application blocks the request or returns a generic error without revealing file system information, it might indicate some form of mitigation, but further testing is needed to confirm.

---
