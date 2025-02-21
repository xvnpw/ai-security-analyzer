## 1. Arbitrary File Read via Unrestricted Folder Parameter

- **Description**
  An attacker can pass arbitrary folder paths to the API endpoints (`/evals`, `/pairwise-evals`, or `/best-of-n-evals`) in order to read `.html` files from anywhere on the server’s file system. These endpoints trust the `folder` (and similar) query parameter, check only if the directory exists, then read all `.html` files there and return their contents as part of the API response. By specifying sensitive folders or files, an external attacker can exfiltrate confidential information stored in `.html` files on the server.

  **Step-by-step trigger**
  1. Attacker finds the endpoints that accept a `folder` (or `folder1`, `folder2`) query parameter.
  2. Attacker supplies a path such as `/home/user/secrets/`, `/var/www/`, or any directory containing `.html` files in the system.
  3. The backend checks if that path exists and, if so, reads any `.html` files there.
  4. The backend then returns the file content (base64 or plain text) in the JSON response.
  5. Attacker gains access to contents of sensitive web files or private data stored in those `.html` files.

- **Impact**
  This vulnerability allows reading arbitrary files (where the name ends with `.html`) from the host’s filesystem. Attackers may gain access to logs, API keys, secrets, or any other `.html` file that exists on disk. If any sensitive configuration files or data dumps were saved with an `.html` extension, these could be disclosed. This poses a severe risk to the confidentiality of the application and underlying system.

- **Vulnerability Rank**
  **Critical** (it can directly leak sensitive information to an unauthenticated attacker).

- **Currently Implemented Mitigations**
  None. The server does check if the directory exists but does not restrict or sanitize user-supplied folder paths to any safe subset. There is no path whitelist, nor a check that ensures these folders are within the application’s intended directory.

- **Missing Mitigations**
  - Restrict directory traversal by validating or sanitizing the `folder` (or `folderN`) query parameters to ensure they only point to a predefined safe directory (e.g., `./evals_data/outputs/`).
  - Ensure that user-controlled paths cannot escape the legitimate data folder (e.g., disallow absolute paths, “../”, or other patterns leading outside the intended directory).
  - If external browsing or debugging is truly required, implement strict authorization checks or remove the feature from production.

- **Preconditions**
  - Attacker can connect to the API externally (no authentication required).
  - The server must contain `.html` files outside the intended evaluation folders that the attacker wishes to read (or the attacker has reason to believe such files exist).
  - The attacker knows or guesses pathnames containing `.html` files.

- **Source Code Analysis**
  1. In `routes/evals.py`, functions such as `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` accept a user-supplied `folder` (or `folderX`) query parameter.
  2. The only check performed is `folder_path.exists()`. If it exists and contains `.html` files, these files are read and returned in the API’s JSON response.
  3. There is no logic restricting the path to a known working directory. For instance:
     ```python
     folder_path = Path(folder)
     if not folder_path.exists():
         raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
     ...
     files = {f: os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html")}
     ...
     with open(output_file, "r", encoding="utf-8") as f:
         output_html = f.read()
     ...
     # output_html returned to the client
     ```
     Because `folder` can be any path on the server, an attacker can specify sensitive paths (e.g., `/etc/nginx/`) or any valid path containing `.html` files.

- **Security Test Case**
  1. From an external machine, perform a GET request to `/evals?folder=/` (or any other system path containing `.html` files).
     - Example: `GET /evals?folder=/var/www/html`
  2. Observe the response if `.html` files exist in that folder. The application returns the content of those `.html` files under the `outputs` field.
  3. Verify that the attacker obtains file contents not intended for public access.
  4. Repeat with different folder paths to enumerate and read any `.html` files on the system.
