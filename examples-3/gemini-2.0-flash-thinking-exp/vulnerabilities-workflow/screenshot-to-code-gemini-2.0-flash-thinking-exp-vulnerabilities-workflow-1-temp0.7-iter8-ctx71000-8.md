## Vulnerability List:

- Vulnerability Name: Cross-Origin Resource Sharing (CORS) Misconfiguration

- Description:
    1. An attacker can host a malicious website on a different domain (e.g., `attacker.com`).
    2. The attacker crafts JavaScript code on their website that sends requests to the backend API of the `screenshot-to-code` application (e.g., `api.screenshottocode.com`).
    3. Due to the permissive CORS configuration in the backend, the browser allows these cross-origin requests.
    4. The attacker can then potentially interact with the backend API on behalf of a user who visits their malicious website.
    5. This could lead to unauthorized actions, data exfiltration (if API endpoints are vulnerable), or other malicious activities depending on the application's functionality and API design.

- Impact:
    - **High:**  If the backend API has endpoints that perform sensitive actions or expose data, a CORS misconfiguration can allow attackers to bypass the same-origin policy and potentially exploit these endpoints from a different domain. This could lead to unauthorized access to functionality, data manipulation, or information disclosure. In the context of `screenshot-to-code`, while the primary function is code generation, future features or vulnerabilities in API endpoints could be exposed due to this misconfiguration.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The CORS middleware is configured to `allow_origins=["*"]`, which explicitly disables CORS protection.

- Missing Mitigations:
    - **Restrict `allow_origins` to specific, trusted domains:** Instead of allowing all origins (`"*"`), the backend should be configured to only allow requests from the frontend's domain (e.g., `screenshottocode.com` or `localhost:5173` for development).
    - **Implement proper authentication and authorization:** While CORS helps prevent some cross-site attacks, it's not a substitute for robust authentication and authorization mechanisms. The API endpoints should still require proper authentication and authorization to ensure that only legitimate requests are processed, regardless of the origin.

- Preconditions:
    - The `screenshot-to-code` backend must be publicly accessible.
    - The frontend and backend must be hosted on different origins (domains or ports).
    - A threat actor needs to host a website on a different origin than the frontend.

- Source Code Analysis:
    1. Open `backend/main.py`.
    2. Observe the following code block:
    ```python
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    # Configure CORS settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    3. The `CORSMiddleware` is added to the FastAPI application.
    4. `allow_origins=["*"]` configuration is set, which means requests from **any** origin are allowed.
    5. `allow_credentials=True` is also set, which means that cross-origin requests can include cookies and HTTP authentication credentials. While `allow_credentials=True` is often needed for legitimate cross-origin requests, when combined with `allow_origins=["*"]`, it widens the attack surface as it allows malicious sites to send credentialed requests.
    6. `allow_methods=["*"]` and `allow_headers=["*"]` further widen the permissive nature of the CORS policy, allowing all HTTP methods and headers for cross-origin requests.

- Security Test Case:
    1. **Setup:**
        - Deploy the `screenshot-to-code` backend to a public server (e.g., `api.screenshottocode.com`) and frontend to another domain or port (e.g., `screenshottocode.com` or `localhost:5173`).
        - Create a simple HTML file (e.g., `attacker.html`) to be hosted on `attacker.com` (or `localhost:8080` for local testing).
        - Replace `api.screenshottocode.com` with the actual backend URL and `http://localhost:5173` with the frontend URL if testing locally.

    2. **Attacker Website (`attacker.html`):**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attacker Website</title>
    </head>
    <body>
        <h1>Malicious Website</h1>
        <button id="exploitButton">Trigger API Call</button>
        <script>
            document.getElementById('exploitButton').addEventListener('click', function() {
                fetch('http://api.screenshottocode.com/generate-code', { // Replace with your backend URL
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        image: 'data:image/png;base64, ... (some base64 encoded image data) ...', // Example image data
                        stack: 'html_tailwind'
                    }),
                    credentials: 'include' // Include credentials if needed for the API
                })
                .then(response => response.json())
                .then(data => {
                    alert('API Response: ' + JSON.stringify(data)); // Display API response (for demonstration)
                    console.log('API Response:', data); // Log API response to console
                })
                .catch(error => {
                    alert('Error calling API: ' + error);
                    console.error('Error calling API:', error);
                });
            });
        </script>
    </body>
    </html>
    ```

    3. **Steps:**
        - Host `attacker.html` on `attacker.com` (or `localhost:8080`).
        - Open `attacker.html` in a browser.
        - Click the "Trigger API Call" button.
        - Observe that the browser successfully sends a POST request to `http://api.screenshottocode.com/generate-code` (or your backend URL).
        - Observe that the API response is successfully received and displayed in an alert and logged to the console. This indicates that the CORS policy is not preventing the cross-origin request.

    4. **Expected Result:**
        - The API call from `attacker.com` to `api.screenshottocode.com` should succeed, and the API response should be displayed/logged in the attacker's website. This confirms the CORS misconfiguration vulnerability. If CORS was correctly configured, the browser would block this cross-origin request.

- Vulnerability Name: Path Traversal in Evaluation File Handling

- Description:
    1. An attacker can craft a malicious request to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints.
    2. In this request, the attacker provides a manipulated `folder`, `folder1`, `folder2`, ..., `folderN` parameter value containing path traversal sequences like `../` to escape the intended evaluation directories.
    3. The backend, without proper validation, uses these paths in `os.listdir()` and `os.path.join()` operations within the `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` routes.
    4. This allows the attacker to list files and potentially read the content of files outside the designated evaluation folders, potentially accessing sensitive information or application files.

- Impact:
    - **High:** An attacker can read arbitrary files on the server if the application process has the necessary permissions. This could lead to disclosure of sensitive application code, configuration files, or data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The application directly uses user-provided folder paths without sanitization or validation beyond existence check.

- Missing Mitigations:
    - **Input Validation and Sanitization:**  Validate and sanitize the folder path inputs to ensure they are within the expected evaluation directories. Use functions like `os.path.abspath()` and `os.path.commonpath()` to restrict access to intended directories.
    - **Principle of Least Privilege:** Ensure that the application process runs with minimal necessary permissions to limit the impact of a successful path traversal attack.

- Preconditions:
    - The `screenshot-to-code` backend must be publicly accessible.
    - The `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints must be accessible to the attacker.
    - The attacker needs to know or guess the file paths they want to access.

- Source Code Analysis:
    1. Open `backend/routes/evals.py`.
    2. Examine the `get_evals`, `get_pairwise_evals`, and `get_best_of-n-evals` functions.
    3. In `get_evals`:
       ```python
       @router.get("/evals", response_model=list[Eval])
       async def get_evals(folder: str):
           # ...
           folder_path = Path(folder)
           if not folder_path.exists():
               raise HTTPException(...)
           # ...
           files = {
               f: os.path.join(folder, f)
               for f in os.listdir(folder)
               if f.endswith(".html")
           }
           # ...
       ```
       - The `folder` parameter is taken directly from the query string and used in `os.listdir` and `os.path.join` without sanitization.
    4. Similar pattern is observed in `get_pairwise_evals` and `get_best_of-n-evals`.
    5. The `os.path.exists()` check only verifies if the path exists, but does not prevent traversal outside intended directories.

- Security Test Case:
    1. **Setup:**
        - Deploy the `screenshot-to-code` backend to a public server (e.g., `api.screenshottocode.com`).
        - Create a file outside the expected evaluation directories that the attacker wants to read (e.g., `/tmp/sensitive_file.txt` - the content of the file is not important for this test case, only its existence is).
        - Assume the expected evaluation directories are within `EVALS_DIR` (defined in `evals.py`).

    2. **Attacker Request:**
        - Send a GET request to the `/evals` endpoint with a crafted `folder` parameter to attempt path traversal. For example:
          ```
          GET /evals?folder=../../../../tmp HTTP/1.1
          Host: api.screenshottocode.com
          ```

    3. **Steps:**
        - Send the crafted GET request to the `/evals` endpoint.
        - Observe the response. Check if the response lists files from outside of the intended `EVALS_DIR`. If there are any `.html` files in the traversed directory (e.g., `/tmp`), the response will include data related to them. Even if there are no `.html` files, a successful traversal can be confirmed by the absence of error and an empty list (if no `.html` files are found in the traversed location), which is different from an error indicating invalid path.

    4. **Expected Result:**
        - The server should respond without an error, and if there are HTML files in the `/tmp` directory (or the directory the attacker traversed to), they will be listed in the response. This indicates a successful path traversal, as the attacker was able to access and list files outside of the intended evaluation directories. If no HTML files are found in `/tmp`, the response will be an empty list of evals, but still without an error, confirming the path traversal. If properly mitigated, the server should either reject the request or return an error message indicating an invalid path.
