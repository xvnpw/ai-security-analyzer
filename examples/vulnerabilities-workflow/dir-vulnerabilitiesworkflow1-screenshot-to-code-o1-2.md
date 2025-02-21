## 1) Unrestricted Access to Costly API Endpoints

- **Description (step by step)**
  1. An attacker discovers the publicly-available `/generate-code` route (in `backend/routes/generate_code.py`) and connects via WebSocket with no authentication required.
  2. The attacker repeatedly sends large or numerous requests (for example, providing long base64 images or text prompts).
  3. The backend code invokes external APIs (OpenAI, Anthropic, ScreenshotOne, etc.) using secret keys stored in environment variables.
  4. Because there is no rate limit or authentication, the attacker can drive up API usage indefinitely, incurring substantial costs to the owner of these keys.

- **Impact**
  Large financial losses from excessive OpenAI/Anthropic/ScreenshotOne billing, and the possibility of exhausting account limits. This can effectively cripple the service owner’s account due to unauthorized usage.

- **Vulnerability Rank**
  **High**

- **Currently Implemented Mitigations**
  - None. The code in `generate_code.py` and related routes does not implement any authentication, rate limitation, or API key usage restrictions.

- **Missing Mitigations**
  - Enforce authentication (e.g. API tokens, OAuth, etc.).
  - Implement rate limiting (token bucket or IP-based throttling).
  - Restrict who can invoke the `/generate-code` endpoint.
  - Limit the size or frequency of requests (to prevent abuse).

- **Preconditions**
  - The attacker knows (or finds) the publicly accessible URL where this FastAPI instance is deployed.
  - The application is served on the internet with the environment variables for external APIs set on the backend.

- **Source Code Analysis**
  - In `backend/routes/generate_code.py`, the `/generate-code` WebSocket endpoint accepts untrusted input.
  - There is no check for authentication or usage limits.
  - From lines where `stream_openai_response` or `stream_claude_response` are called, the code sends each user request to third-party LLMs using the project’s environment keys.
  - CORS is effectively open (`allow_origins=["*"]` in `main.py`), allowing anyone on the web to initiate these calls.

- **Security Test Case**
  1. Deploy the application publicly without additional protections.
  2. Write a script or simple loop that opens a WebSocket to `/generate-code` and submits large prompts repeatedly.
  3. Confirm that the script can keep generating code and exhausting the project owner’s OpenAI or Anthropic quota with no restriction.

---

## 2) Arbitrary Folder Parameter in `/evals` Routes Leading to Potential Local File Disclosure

- **Description (step by step)**
  1. An attacker calls `GET /evals?folder=ANY_PATH_ON_SERVER` (or `/pairwise-evals` or `/best-of-n-evals` with similar parameters).
  2. The backend code in `backend/routes/evals.py` takes the `folder` query parameter and uses `os.listdir(folder)` to list all files with a `.html` extension in that directory.
  3. For each discovered `.html` file, it attempts to match a corresponding `.png` in the `EVALS_DIR/inputs` folder using the same base filename. If found, the `.html` file contents are loaded and returned to the caller in the HTTP response.
  4. If a developer accidentally places or leaves any `.html` file in an arbitrary folder on the server (matching a `.png` in `EVALS_DIR/inputs`), an attacker can fetch its contents, potentially revealing sensitive information.

- **Impact**
  Disclosure of internal local `.html` files that match certain names, potentially revealing debug logs, administrative pages, or other confidential data unintentionally placed on the server in HTML form.

- **Vulnerability Rank**
  **High**

- **Currently Implemented Mitigations**
  - None. The folder parameter is trusted as-is, and the code makes no whitelist checks.

- **Missing Mitigations**
  - Restrict permitted folders to known safe directories (e.g., only read from a strict internal evals subfolder).
  - Enforce authentication or at least confirm that the path is within a dedicated project subdirectory.
  - Avoid returning file contents for `.html` files outside a strictly-coded path.

- **Preconditions**
  - The attacker must guess or discover that there is a `.png` in `EVALS_DIR/inputs` with a base name that matches a `.html` file placed under some accessible folder path.
  - The server has .html data in that folder that the attacker wishes to read.

- **Source Code Analysis**
  - In `backend/routes/evals.py`, the `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` endpoints read `.html` files from arbitrary folders.
  - There is no verification that `folder` is restricted to within `EVALS_DIR`, nor any authentication.
  - The relevant lines use `os.listdir(folder)`, `f.endswith('.html')`, and then open and return those files once a base-named `.png` is found.

- **Security Test Case**
  1. Place a `.html` file named `secret.html` with sensitive data in `/some/hidden/folder` on the server.
  2. Put a file named `secret.png` in `EVALS_DIR/inputs`.
  3. Make a GET request to `/evals?folder=/some/hidden/folder`.
  4. Observe that `secret.html` is returned if `secret.html` and `secret.png` share the same base name.
