- Vulnerability Name: Permissive CORS Configuration
- Description: The backend application is configured with Cross-Origin Resource Sharing (CORS) that allows requests from any origin. This permissive configuration, set by `allow_origins=["*"]`, means that any website can make requests to the backend API, bypassing the Same-Origin Policy. An attacker can host a malicious website that makes unauthorized requests to the backend API on behalf of a victim user who visits the malicious site. This could lead to various attacks depending on the API endpoints and functionality, such as unauthorized usage of AI models via the API or data exfiltration if sensitive information is exposed through API responses.
- Impact:
    - Cross-site request forgery (CSRF): Although not directly shown to be exploitable as authentication mechanism isn't clear, permissive CORS increases CSRF risk if sessions or cookies are used for authentication.
    - Unauthorized API access: Any website can utilize the API, potentially leading to abuse of paid services (like OpenAI API calls) if no other authentication or authorization is in place.
    - Information disclosure: If API endpoints inadvertently expose sensitive data, malicious sites can access this data due to the relaxed CORS policy.
- Vulnerability Rank: High
- Currently implemented mitigations: None. The application code explicitly sets permissive CORS.
- Missing mitigations:
    - Restrict `allow_origins` in `backend/main.py` to specific, trusted origins, such as the domain where the frontend application is hosted (e.g., `allow_origins=["https://your-frontend-domain.com"]`).
    - For development, consider allowing `localhost` origins but ensure it's restricted in production.
    - Implement proper authentication and authorization mechanisms to further protect API endpoints, regardless of CORS policy.
- Preconditions:
    - The `screenshot-to-code` backend application is deployed with the default CORS configuration in `backend/main.py`.
    - The frontend and backend are intended to be served from different origins, or the application aims to control cross-origin access.
- Source code analysis:
    - File: `backend/main.py`
    - Lines:
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
    - The `CORSMiddleware` is instantiated with `allow_origins=["*"]`. This wildcard `*` allows all origins to bypass CORS restrictions when making requests to the backend. The configurations `allow_credentials=True`, `allow_methods=["*"]`, and `allow_headers=["*"]` further widen the permissive nature of the CORS policy, allowing credentials, any HTTP methods, and any headers from cross-origin requests.
    - Visualization:
      ```
      [Browser (malicious-website.com)] --> [Request to screenshot-to-code Backend API]
             ^
             | CORS Check (Permissive: allow_origins=["*"])
             |
      [screenshot-to-code Backend] --> [Response allowed due to permissive CORS]
      ```
- Security test case:
    1. Deploy the `screenshot-to-code` backend application as described in the `README.md`, ensuring the default CORS configuration in `backend/main.py` is active.
    2. Create a simple HTML file (malicious.html) and host it on a different domain or port than the frontend application (e.g., `http://malicious-website.com`).
    3. Include the following JavaScript code in `malicious.html` to make a cross-origin request to the `/generate-code` endpoint of the deployed `screenshot-to-code` backend:
       ```html
       <!DOCTYPE html>
       <html>
       <head>
           <title>Malicious Website</title>
       </head>
       <body>
           <h1>Malicious Website</h1>
           <button id="exploitButton">Trigger Exploit</button>
           <script>
               document.getElementById('exploitButton').addEventListener('click', function() {
                   fetch('http://localhost:7001/generate-code', { // Replace with the actual backend URL if different from localhost:7001
                       method: 'POST',
                       headers: {
                           'Content-Type': 'application/json'
                       },
                       body: JSON.stringify({
                           image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==', // Example base64 encoded PNG - a 5x5 transparent pixel
                           stack: 'html_tailwind'
                       }),
                       mode: 'cors' // Explicitly set mode to 'cors' for clarity
                   })
                   .then(response => response.json())
                   .then(data => {
                       alert('Request successful! Response: ' + JSON.stringify(data));
                   })
                   .catch(error => {
                       alert('Request failed! Check console for details.');
                       console.error('Error:', error);
                   });
               });
           </script>
       </body>
       </html>
       ```
    4. Open `malicious.html` in a web browser from `http://malicious-website.com`.
    5. Click the "Trigger Exploit" button.
    6. Observe that an alert box appears displaying "Request successful!" and the JSON response from the `/generate-code` API endpoint. Check the browser's developer console to confirm no CORS errors were encountered.
    7. If the request is successful and no CORS errors are reported, it confirms that the permissive CORS configuration (`allow_origins=["*"]`) allows cross-origin requests from `http://malicious-website.com` to the `screenshot-to-code` backend API.

- Vulnerability Name: Path Traversal in Evals Route
- Description: Unvalidated folder paths in the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` routes in `evals.py` can allow an attacker to access files and directories outside the intended `EVALS_DIR`, potentially leading to reading sensitive files or listing directory contents on the server.
- Impact:
    - Information Disclosure: Attackers can read arbitrary files on the server if the server process has the necessary permissions. This could include configuration files, source code, or other sensitive data.
    - Directory Listing: Attackers could list directories outside of the intended `EVALS_DIR`, potentially gaining knowledge of the server's file structure.
- Vulnerability Rank: High
- Currently implemented mitigations: None. The code directly uses user-provided folder paths without sanitization.
- Missing mitigations:
    - Input validation and sanitization: Validate and sanitize the `folder`, `folder1`, `folder2` parameters in `evals.py` to ensure they are within the expected `EVALS_DIR` or a set of allowed directories. Use functions like `os.path.abspath`, `os.path.normpath`, and check if the resolved path starts with the intended base directory.
    - Restrict access to eval routes: Implement authentication and authorization to limit access to these evaluation routes to only authorized users or roles.
- Preconditions:
    - The `screenshot-to-code` backend application is deployed with the `evals.py` routes exposed.
    - An attacker can send HTTP GET requests to the `/evals`, `/pairwise-evals`, or `/best-of-n-evals` endpoints and control the `folder`, `folder1`, `folder2` query parameters.
- Source code analysis:
    - File: `backend/routes/evals.py`
    - Routes: `/evals`, `/pairwise-evals`, `/best-of-n-evals`
    - Parameters: `folder`, `folder1`, `folder2`, and further `folder3`, etc.
    - Code snippet (example from `/evals` route):
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
                  for f in os.listdir(folder)
                  if f.endswith(".html")
              }
      ```
    - The code takes the `folder` parameter directly and uses it in `os.path.join(folder, f)` and `os.listdir(folder)` without any validation to ensure it stays within the intended directories. Similar logic applies to `folder1`, `folder2`, etc., in other routes.
    - Visualization:
      ```
      [Attacker] --> [Request to /evals?folder=../../etc/passwd] --> [Backend Application]
                  [Backend Application] --> os.listdir('../../etc/passwd') / os.path.join('../../etc/passwd', ...)
                  [Backend Application] --> Reads files from /etc/passwd (if permissions allow)
                  [Backend Application] --> [Response with error or content based on file access]
      ```
- Security test case:
    1. Deploy the `screenshot-to-code` backend application with the `evals.py` routes enabled.
    2. Send a GET request to the `/evals` endpoint with a crafted `folder` parameter to attempt path traversal. For example:
       ```
       GET /evals?folder=../../etc/passwd HTTP/1.1
       Host: <backend-host>:<backend-port>
       ```
       (Replace `<backend-host>:<backend-port>` with the actual backend URL and port.)
    3. Observe the response. If the application attempts to process the path `../../etc/passwd`, it might return an error (e.g., file not found, or permission denied), or in a misconfigured setup, it could potentially list the contents of the `/etc/passwd` directory or attempt to read files within it. The error message itself can indicate if the path traversal was attempted.
    4. For a more controlled test (assuming you know there are readable files in a parent directory relative to the expected eval folders), you can try accessing a known file. For example, if eval files are expected in `/app/evals`, try `folder=../backend/main.py` to see if you can get an error related to Python files or HTML files, suggesting it attempted to access and process files within the backend directory.
    5. Check server logs for any file system access errors or unusual directory listing attempts related to the path traversal attempt.
