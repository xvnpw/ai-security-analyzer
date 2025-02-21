Below is the updated list of externally exploitable, high‑severity vulnerabilities that remain valid and unmitigated in the current publicly accessible instance of the application.

---

## 1. Vulnerability Name: Improper CORS Configuration with Wildcard Origins and Credentials Allowed

**Description:**
The backend (in `backend/main.py`) configures the CORS middleware with:
- `allow_origins=["*"]`
- `allow_credentials=True`
- `allow_methods=["*"]`
- `allow_headers=["*"]`

According to the CORS specification, when credentials are allowed the use of a wildcard for allowed origins is not permitted. An external attacker may craft a malicious website that, when visited by an authenticated user, makes credentialed cross-site requests to the backend. This can allow the attacker to bypass same-origin restrictions.

**Impact:**
An attacker may force a user’s browser to include sensitive cookies or session tokens with cross-origin requests. This can result in session hijacking, unauthorized actions performed on behalf of the user, and potential disclosure of user data.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
*None.* The code explicitly uses a wildcard with credentials enabled.

**Missing Mitigations:**
- Restrict the allowed origins to a whitelisted set of trusted domains.
- Dynamically set the `Access-Control-Allow-Origin` header based on an approved list rather than using `"*"`.

**Preconditions:**
An attacker must lure an authenticated user to visit a malicious website that issues cross-origin requests with credentials from their browser.

**Source Code Analysis:**
In `backend/main.py`, the following block is used:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```
*Step-by-step analysis:*
1. The configuration sets `allow_origins` to a wildcard (`*`), which is acceptable only if credentials are disabled.
2. With `allow_credentials=True`, the browser will include cookies and HTTP authentication headers.
3. No logic restricts or validates the origin of incoming requests, leading to a violation of CORS recommendations.

**Security Test Case:**
1. Authenticate to the application and capture a valid session cookie or authentication token.
2. From a controlled (malicious) webpage, issue a cross-origin AJAX or Fetch request to one of the backend endpoints using `credentials: 'include'`.
3. Verify that the backend response includes an `Access-Control-Allow-Origin` header that permits the request and that the user’s credentials are being sent.
4. Attempt to perform a sensitive action using the stolen credentials to confirm that unauthorized actions are possible.

---

## 2. Vulnerability Name: Directory Traversal via Unvalidated Folder Parameter in Eval Endpoint

**Description:**
The `/evals` endpoint (in `backend/routes/evals.py`) accepts a `folder` query parameter and directly instantiates a `Path` object with it. There is no validation or sanitization to ensure that the provided folder remains within an allowed directory. An attacker may use relative path segments (e.g., `../../`) to traverse outside the intended directory, potentially accessing sensitive files on the server.

**Impact:**
This vulnerability could allow an attacker to list or retrieve files from arbitrary locations on the server’s filesystem (such as configuration files) resulting in critical information disclosure, which may lead to further attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
*None.* The endpoint only checks for folder existence without restricting the path.

**Missing Mitigations:**
- Validate the folder parameter against a whitelist or enforce that it is a subdirectory within a designated safe location (e.g., a predefined `EVALS_DIR`).
- Sanitize the input to remove directory traversal characters (e.g., `../`).

**Preconditions:**
The backend must run with read permissions beyond the intended evaluation directory, and the endpoint is publicly accessible, allowing an attacker to supply arbitrary folder values.

**Source Code Analysis:**
In `backend/routes/evals.py` the code starts as follows:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```
*Step-by-step analysis:*
1. The function accepts the `folder` parameter without sanitization.
2. It then converts the string to a `Path` object.
3. There is no verification that the resulting path is within a safe directory, leaving it open to traversal attacks.

**Security Test Case:**
1. Send a GET request such as:
   ```
   GET /evals?folder=../../etc HTTP/1.1
   Host: <target>
   ```
2. Observe the response to determine if files from unauthorized directories (e.g., `/etc`) are listed.
3. Confirm whether the access controls properly limit directory access or if sensitive file details are disclosed.

---

## 3. Vulnerability Name: LLM Prompt Injection due to Unvalidated User Input in Prompt Assembly

**Description:**
The system builds prompts for code generation by concatenating system instructions with user‐supplied inputs (e.g., image URLs and optional result image data) in the function `assemble_prompt` (located in `backend/prompts/__init__.py`). Because these user inputs are not validated or sanitized, an attacker might inject additional instructions into the prompt, altering the intended behavior of the LLM.

**Impact:**
Manipulating the prompt can force the LLM to generate code with hidden vulnerabilities or malicious logic, potentially bypassing security restrictions. This undermines the integrity of the code generation process and could lead to the execution of compromised code downstream.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
*None.* The prompt assembly process embeds user-supplied data directly without any sanitization.

**Missing Mitigations:**
- Apply robust input validation and escaping for all user-supplied parameters (e.g., `resultImage`).
- Use a strict schema or whitelist for allowed characters and formats in image URLs and related data.

**Preconditions:**
The attacker must be able to supply or manipulate parameters (such as `resultImage`) later used in composing the LLM prompt.

**Source Code Analysis:**
In `backend/prompts/__init__.py`, the function is implemented as:
```python
def assemble_prompt(
    image_data_url: str,
    stack: Stack,
    result_image_data_url: Union[str, None] = None,
) -> list[ChatCompletionMessageParam]:
    system_content = SYSTEM_PROMPTS[stack]
    user_prompt = USER_PROMPT if stack != "svg" else SVG_USER_PROMPT

    user_content: list[ChatCompletionContentPartParam] = [
        {
            "type": "image_url",
            "image_url": {"url": image_data_url, "detail": "high"},
        },
        {
            "type": "text",
            "text": user_prompt,
        },
    ]
    if result_image_data_url:
        user_content.insert(
            1,
            {
                "type": "image_url",
                "image_url": {"url": result_image_data_url, "detail": "high"},
            },
        )
    return [
        {
            "role": "system",
            "content": system_content,
        },
        {
            "role": "user",
            "content": user_content,
        },
    ]
```
*Step-by-step analysis:*
1. The function accepts `image_data_url` and optionally `result_image_data_url` without sanitization.
2. These values are directly embedded in the LLM prompt as part of the `image_url` objects.
3. An attacker can supply a malicious string (for example, additional instructions) in the `result_image_data_url` parameter that alters the prompt’s behavior.

**Security Test Case:**
1. Craft a request to the code generation endpoint with a malicious `resultImage` parameter, embedding additional instructions (e.g., extra directives to include insecure code segments).
2. Trigger the code-generation process and capture the output.
3. Review the generated code to check whether the injected instructions have altered the intended output.

---

## 4. Vulnerability Name: Inadequate URL Validation in Screenshot Endpoint Leading to SSRF via Third‑Party API

**Description:**
The `/api/screenshot` endpoint (in `backend/routes/screenshot.py`) accepts a URL via the `url` field in the request body and passes it directly into the parameters for an external screenshot API (`https://api.screenshotone.com/take`). There is no validation performed on the URL, allowing an attacker to supply a URL pointing to internal network resources. If the third‑party API does not properly restrict fetching internal addresses, this can lead to a Server‑Side Request Forgery (SSRF).

**Impact:**
An attacker could abuse the endpoint to have the screenshot service fetch screenshots of internal or otherwise protected resources. This can lead to internal network reconnaissance and the exposure of sensitive information.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
*None.* The user-supplied URL is accepted and forwarded directly without checks.

**Missing Mitigations:**
- Validate the supplied URL to ensure it conforms to allowed schemes (e.g., only `http` or `https`) and permitted target domains.
- Implement a whitelist of allowed domains and reject URLs that do not match the approved list.

**Preconditions:**
The attacker must supply a specially crafted URL (for example, pointing to an internal IP address or localhost) and the external screenshot service must not enforce its own restrictions.

**Source Code Analysis:**
In `backend/routes/screenshot.py`, the function `capture_screenshot` is defined as follows:
```python
async def capture_screenshot(target_url: str, api_key: str, device: str = "desktop") -> bytes:
    api_base_url = "https://api.screenshotone.com/take"
    params = {
        "access_key": api_key,
        "url": target_url,
        "full_page": "true",
        # ... other static parameters
    }
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(api_base_url, params=params)
        ...
```
*Step-by-step analysis:*
1. The endpoint reads the target URL from the request body.
2. This URL is included directly in the query parameters for the external API call.
3. No validation is performed to ensure the URL points to a safe, externally accessible resource, opening the door to SSRF.

**Security Test Case:**
1. Send a POST request to `/api/screenshot` with a JSON payload such as:
   ```json
   {
       "url": "http://127.0.0.1:80",
       "apiKey": "<valid_key>"
   }
   ```
2. Observe the response to determine if the screenshot service returns a screenshot of the internal URL.
3. Confirm whether the service properly restricts or blocks requests to internal network resources.

---

By addressing these high‑severity vulnerabilities—through proper input validation, strict configuration controls, and safe coding practices—the security posture of the publicly accessible application can be significantly improved.
