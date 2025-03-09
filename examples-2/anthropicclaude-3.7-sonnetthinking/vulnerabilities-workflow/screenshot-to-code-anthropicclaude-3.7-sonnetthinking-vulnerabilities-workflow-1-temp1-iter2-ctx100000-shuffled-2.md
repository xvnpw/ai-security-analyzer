# VULNERABILITIES

## Path Traversal in Evaluation Routes

### Vulnerability Name
Path Traversal / Directory Traversal Vulnerability

### Description
The application contains multiple endpoints that accept user-provided folder paths directly from query parameters without proper validation or sanitization. These paths are then used in file system operations such as `os.path.join()`, `os.listdir()`, and `os.path.exists()`. This enables attackers to traverse the directory structure outside the intended directory, potentially accessing sensitive files anywhere on the server's file system.

To trigger this vulnerability, an attacker would send requests to the evaluation endpoints with path traversal sequences (such as `../`) in the folder parameters, allowing them to navigate to arbitrary directories on the server.

### Impact
An attacker can read arbitrary files on the server filesystem, potentially accessing:
- Configuration files containing API keys, database credentials, or other secrets
- System files containing sensitive information
- Application source code
- User data stored on the server

This vulnerability effectively bypasses any intended access controls on the file system, giving attackers read access to any files the application process has permission to read.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are minimal mitigations in place:
- Some endpoints check if the provided folder exists but do not validate whether the path is within an allowed directory
- File reading is limited to HTML files (for some operations), but this doesn't prevent the attacker from discovering the existence of other files

### Missing Mitigations
1. Path sanitization to prevent directory traversal
2. Path canonicalization to resolve paths before use
3. Validation that provided paths are within allowed directories
4. Allowlist of permitted directories rather than accepting arbitrary paths
5. Access control on the endpoints themselves

### Preconditions
- The attacker must have access to the application's API endpoints
- The application must be running with permissions to access files of interest to the attacker

### Source Code Analysis
The vulnerability exists in multiple endpoints in the `backend/routes/evals.py` file:

1. In the `/evals` endpoint:
```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    # Get all HTML files from folder
    files = {
        f: os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".html")
    }
```

2. In the `/pairwise-evals` endpoint:
```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(
        "...",
        description="Absolute path to first folder",
    ),
    folder2: str = Query(
        "..",
        description="Absolute path to second folder",
    ),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}

    # Get all HTML files from first folder
    files1 = {
        f: os.path.join(folder1, f) for f in os.listdir(folder1) if f.endswith(".html")
    }
```

3. In the `/best-of-n-evals` endpoint:
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

    # Validate folders exist
    for folder in folders:
        if not os.path.exists(folder):
            return {"error": f"Folder does not exist: {folder}"}
```

The vulnerability stems from several factors:
1. The default values in the `/pairwise-evals` endpoint are particularly concerning: "..." and ".." suggest traversal up the directory tree
2. The application doesn't validate that the provided paths stay within permitted directories
3. There's no path sanitization before using the paths in file operations
4. Once the existence of a folder is confirmed, the application reads directory contents and file contents from the user-specified location without further validation

### Security Test Case
To verify this vulnerability exists:

1. Start the application locally
2. Send a GET request to the `/pairwise-evals` endpoint with traversal sequences:
   ```
   GET /pairwise-evals?folder1=../../../etc&folder2=../../../var HTTP/1.1
   Host: localhost:7001
   ```

3. Observe that the application attempts to access directories outside the intended directory structure
4. For a more targeted test, use a path to a known system file:
   ```
   GET /pairwise-evals?folder1=../../../etc/passwd&folder2=../../../etc/shadow HTTP/1.1
   Host: localhost:7001
   ```

5. If the server is running on a Linux/Unix system, this would attempt to access sensitive password-related files
6. Even if the files aren't fully read (because they aren't HTML files), the application will reveal their existence, which is still an information disclosure vulnerability

## Unvalidated User Input in WebSocket Handlers

### Vulnerability Name
Insufficient Input Validation in WebSocket Message Processing

### Description
The application's WebSocket endpoint for code generation accepts user messages without comprehensive validation of input data. While some parameters are checked, the validation process is incomplete and could allow malicious inputs to be processed by the application.

### Impact
An attacker could send specially crafted WebSocket messages that:
- Trigger application errors or exceptions that might reveal sensitive information
- Cause the application to behave in unintended ways
- Potentially lead to resource exhaustion (since invalid inputs might still be processed by expensive AI operations)

### Vulnerability Rank
High

### Currently Implemented Mitigations
The application does perform some validation:
- Checks for required parameters
- Validates that stack and input mode values are in the expected format
- Has error handling for some conditions

### Missing Mitigations
- Comprehensive validation of all user-supplied fields
- Input sanitization before processing
- Rate limiting to prevent abuse
- Proper error handling that doesn't expose internal details

### Preconditions
- Access to the WebSocket endpoint `/generate-code`
- Ability to send custom WebSocket messages

### Source Code Analysis
In `backend/routes/generate_code.py`, the WebSocket handler accepts messages without thorough validation:

```python
@router.websocket("/generate-code")
async def stream_code(websocket: WebSocket):
    await websocket.accept()
    print("Incoming websocket connection...")

    ## Parameter extract and validation
    params: dict[str, str] = await websocket.receive_json()
    print("Received params")

    extracted_params = await extract_params(params, throw_error)
```

While there is some validation in the `extract_params` function:

```python
async def extract_params(
    params: Dict[str, str], throw_error: Callable[[str], Coroutine[Any, Any, None]]
) -> ExtractedParams:
    # Read the code config settings (stack) from the request.
    generated_code_config = params.get("generatedCodeConfig", "")
    if generated_code_config not in get_args(Stack):
        await throw_error(f"Invalid generated code config: {generated_code_config}")
        raise ValueError(f"Invalid generated code config: {generated_code_config}")
    validated_stack = cast(Stack, generated_code_config)

    # Validate the input mode
    input_mode = params.get("inputMode")
    if input_mode not in get_args(InputMode):
        await throw_error(f"Invalid input mode: {input_mode}")
        raise ValueError(f"Invalid input mode: {input_mode}")
```

This only validates a subset of the possible inputs. The code retrieves other parameters like "image", "history", and "resultImage" with minimal validation. Complex nested data structures in the user input could potentially lead to unexpected behavior.

### Security Test Case
To verify this vulnerability:

1. Start the application locally
2. Establish a WebSocket connection to `/generate-code`
3. Send a malformed JSON message with unexpected field types:
   ```json
   {
     "generatedCodeConfig": "html_tailwind",
     "inputMode": "image",
     "image": {"malicious": "nested object instead of a string"},
     "history": {"another": "invalid object"}
   }
   ```
4. Observe how the application handles the unexpected input (it may crash or reveal errors)
5. Send another WebSocket message with extremely large input values to test for resource exhaustion:
   ```json
   {
     "generatedCodeConfig": "html_tailwind",
     "inputMode": "image",
     "image": "data:image/png;base64,..." // Very large base64 string
   }
   ```
6. Monitor the application's response and resource usage when processing these inputs
