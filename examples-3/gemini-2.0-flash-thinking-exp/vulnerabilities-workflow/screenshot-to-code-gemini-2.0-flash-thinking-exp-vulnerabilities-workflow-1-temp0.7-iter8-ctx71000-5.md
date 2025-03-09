### Vulnerability List

- Vulnerability Name: Accidental Mock AI Response in Production

- Description:
    1. An attacker identifies that the application has a mock AI response mode, intended for debugging and development, which can be enabled using the `MOCK` environment variable.
    2. The attacker determines that if the `MOCK` environment variable is set to `true` in the backend deployment, the application will bypass calls to actual AI models (like OpenAI, Anthropic, Gemini) and instead use predefined, static responses from `mock_llm.py`.
    3. The attacker finds a way to influence the environment variables of the running backend application. This could be through various means depending on the deployment environment (e.g., if the application is deployed in a containerized environment with misconfigured orchestration, or if there are other vulnerabilities allowing environment variable manipulation).
    4. The attacker sets the `MOCK` environment variable to `true`.
    5. Subsequent requests to the application that trigger AI code generation will now be served with mock responses.
    6. This can lead to several unintended consequences, such as:
        - The application behaving in a way that is different from its intended production functionality.
        - Security checks or logic that depend on the real AI model's responses being bypassed.
        - Potential exposure of debugging or testing endpoints or data paths that are not meant for public access.
        - Inconsistent or predictable application behavior that can be exploited for further attacks or to gain unauthorized information.

- Impact:
    - **High**. The impact depends on what the mock responses are and how critical the AI functionality is to the application's security and business logic. If mock responses bypass security checks, provide access to unintended features, or leak information, the impact could be significant.  The application will not function as intended, and potentially expose non-production behavior. This can lead to data integrity issues and potentially security bypasses if security logic relies on real LLM interactions.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - The project relies on environment variables to control the mock mode. This is a standard practice to separate configuration from code.
    - The `config.py` file correctly reads the `MOCK` environment variable and converts it to a boolean value for `SHOULD_MOCK_AI_RESPONSE`.

- Missing Mitigations:
    - **Explicitly prevent mock mode in production environments.** The application should have a clear mechanism to disable mock mode in production deployments, regardless of environment variables. This could involve:
        - Checking for a specific "production environment" flag or environment variable (e.g., `NODE_ENV=production` or `APP_ENVIRONMENT=production`) and forcibly setting `SHOULD_MOCK_AI_RESPONSE` to `False` in production, overriding any `MOCK` environment variable.
        - Removing or disabling the mock functionality entirely in production builds.
        - Implementing a secure configuration management system that prevents accidental or malicious setting of debug/mock flags in production.
    - **Monitoring and alerting for mock mode status.** The application should log or monitor if mock mode is enabled, especially in environments that are expected to be production. Alerts should be triggered if mock mode is unexpectedly enabled in production.

- Preconditions:
    - The application must be deployed in an environment where environment variables can be potentially manipulated by an attacker (directly or indirectly).
    - The backend application must be configured to use the `SHOULD_MOCK_AI_RESPONSE` flag to determine whether to use mock responses or real LLM calls.
    - The attacker needs to identify and exploit a way to set or change the `MOCK` environment variable in the deployment environment.

- Source Code Analysis:
    1. **`backend/config.py`**:
        ```python
        import os

        # ... other configurations ...

        SHOULD_MOCK_AI_RESPONSE = bool(os.environ.get("MOCK", False))
        ```
        This code snippet shows that the `SHOULD_MOCK_AI_RESPONSE` flag is directly controlled by the `MOCK` environment variable. Setting `MOCK` to any truthy value will enable mock mode.

    2. **`backend/mock_llm.py`**:
        ```python
        import asyncio
        from typing import Awaitable, Callable

        from custom_types import InputMode
        from llm import Completion

        # ... mock code and responses ...

        async def mock_completion(
            process_chunk: Callable[[str, int], Awaitable[None]], input_mode: InputMode
        ) -> Completion:
            # ... mock completion logic ...
            code_to_return = (
                TALLY_FORM_VIDEO_PROMPT_MOCK
                if input_mode == "video"
                else NO_IMAGES_NYTIMES_MOCK_CODE
            )
            # ... return mock response ...
        ```
        This file contains the mock implementation of the LLM completion, providing static, predefined code responses.

    3. **`backend/llm.py`**: (While `llm.py` itself doesn't directly use `SHOULD_MOCK_AI_RESPONSE`, it's the module that would be bypassed.)
        ```python
        # ... functions for interacting with real LLMs like stream_openai_response, stream_claude_response, etc. ...
        ```
        This file contains the actual implementation for calling external LLM APIs. The vulnerability lies in the potential bypass of these functions when mock mode is enabled.

    4. **`backend/main.py` and routes (hypothetical `backend/routes/generate_code.py`)**: (Code not provided, but based on project structure and common patterns):
        The application likely uses a routing mechanism (e.g., FastAPI routes) to handle API requests.  The code in these routes would conditionally call either `mock_llm.mock_completion` or the real LLM completion functions from `llm.py` based on the value of `config.SHOULD_MOCK_AI_RESPONSE`.

        **Visualization:**

        ```
        [External Request] --> [Backend Route Handler]
                                  |
                                  | Check config.SHOULD_MOCK_AI_RESPONSE
                                  |
                                  +---(True)-----> [mock_llm.mock_completion()] --> [Mock Response]
                                  |
                                  +---(False)----> [llm.stream_openai_response() or similar] --> [Real LLM Response]
                                  |
        [Response to User] <-------
        ```

- Security Test Case:
    1. **Setup Test Environment:** Deploy the `screenshot-to-code` backend application in a test environment that closely resembles a production setup. Ensure you can set environment variables for this deployment.
    2. **Baseline Test (Mock Mode Disabled):**
        - Access the application's frontend and trigger a code generation request (e.g., upload a screenshot and select a stack).
        - Observe the generated code. It should be generated by a real LLM and be contextually relevant to the input screenshot (though correctness may vary).
    3. **Enable Mock Mode:**
        - In the test environment, set the `MOCK` environment variable to `true` (e.g., `MOCK=true` in Docker Compose or Kubernetes deployment configuration, or directly in the environment if running locally).
        - Redeploy or restart the backend application to apply the environment variable change.
    4. **Test with Mock Mode Enabled:**
        - Access the application's frontend again and trigger the same code generation request as in step 2.
        - Observe the generated code. **Crucially, check if the generated code is now consistently the same mock response** (e.g., `NO_IMAGES_NYTIMES_MOCK_CODE` or `TALLY_FORM_VIDEO_PROMPT_MOCK` from `mock_llm.py`), regardless of the input screenshot. The response should be predictable and match the predefined mock responses.
    5. **Verify Bypass:**
        - If the generated code is indeed the predefined mock response, this confirms that the application is running in mock mode.
        - Further, try to analyze if any security features or expected behaviors are bypassed due to the mock responses. For example, if there are rate limits or content filtering based on LLM responses, these might be ineffective in mock mode.
    6. **Cleanup:** Remove the `MOCK` environment variable and redeploy/restart the application to revert to normal operation.

This test case will demonstrate that setting the `MOCK` environment variable to `true` effectively switches the backend to mock mode, bypassing real LLM calls and using predefined responses instead, confirming the vulnerability.

- Vulnerability Name: Path Traversal in Evaluation Folder Access

- Description:
    1. An attacker identifies that the application exposes endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) that are intended for evaluation purposes.
    2. These endpoints accept user-controlled input in the form of query parameters (`folder`, `folder1`, `folder2`, etc.) which specify the directory path to be scanned for evaluation files.
    3. The application, in `backend/routes/evals.py`, uses these folder paths directly with `os.listdir` and `os.path.join` without sufficient validation or sanitization to prevent path traversal.
    4. An attacker crafts a malicious request with a folder parameter containing path traversal sequences (e.g., `folder=../../`) to escape the intended evaluation directory.
    5. The backend application attempts to access files based on the manipulated path, potentially allowing the attacker to read arbitrary files from the server's filesystem, including sensitive configuration files, source code, or data.

- Impact:
    - **High**. Successful exploitation allows an attacker to read arbitrary files on the server. This can lead to the disclosure of sensitive information, including source code, configuration files, environment variables, and potentially data used in evaluations. Depending on the server configuration and file permissions, this could escalate to further attacks.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - None. The application directly uses user-provided paths without validation against path traversal attempts.

- Missing Mitigations:
    - **Input validation and sanitization:** Implement robust input validation to sanitize the `folder`, `folder1`, `folder2`, etc., query parameters. This should include:
        - **Path canonicalization:** Convert the user-provided path to its canonical form and verify that it still resides within the intended base directory for evaluations (e.g., `EVALS_DIR`).
        - **Path traversal sequence filtering:**  Reject or sanitize paths containing path traversal sequences like `../` or `..\\`.
        - **Allowlisting:** If possible, restrict allowed folder paths to a predefined list or a specific pattern.
    - **Principle of least privilege:** Ensure that the application process runs with minimal necessary privileges, limiting the impact if path traversal is exploited.
    - **Filesystem access control:** Configure filesystem permissions to restrict access to sensitive files and directories, even if a path traversal vulnerability exists.

- Preconditions:
    - The application must be running with the vulnerable `evals.py` code deployed.
    - The evaluation endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) must be accessible to the attacker.
    - The attacker needs to identify and understand that the `folder` query parameter controls the directory path for file access.

- Source Code Analysis:
    1. **`backend/routes/evals.py`**:
        - **`get_evals` function**:
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
                    # ... rest of the code ...
            ```
            - The `get_evals` function takes the `folder` query parameter directly and uses it in `os.path.join(folder, f)` and `os.listdir(folder)` without proper validation to prevent path traversal.
        - **`get_pairwise_evals` function**:
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

                # ... rest of the code using folder1 and folder2 ...
            ```
            - The `get_pairwise_evals` function similarly takes `folder1` and `folder2` query parameters and uses them with `os.listdir` and `os.path.join` without path traversal prevention.
        - **`get_best_of_n_evals` function**:
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

                # ... rest of the code using folders list ...
            ```
            - The `get_best_of_n_evals` function processes multiple folder parameters (`folder1`, `folder2`, etc.) and uses them without validation, making it vulnerable to path traversal as well.

        **Visualization (for `get_evals`):**

        ```
        [Attacker Request: /evals?folder=../../etc/passwd] --> [Backend Route Handler - get_evals]
                                                                  |
                                                                  | folder_path = Path("../../etc/passwd")
                                                                  | files = os.listdir("../../etc/passwd")  <-- Path Traversal
                                                                  | ... file reading operations using manipulated path ...
                                                                  |
        [Response with content of /etc/passwd or error if access denied] <-------
        ```

- Security Test Case:
    1. **Setup Test Environment:** Deploy the `screenshot-to-code` backend application in a test environment.
    2. **Identify Evaluation Endpoints:** Confirm that the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints are accessible.
    3. **Attempt Path Traversal (using `/evals` endpoint):**
        - Send a GET request to `/evals` with the `folder` query parameter set to `../../etc`. For example: `http://<backend-url>/evals?folder=../../etc`
        - Observe the response. If successful path traversal is possible, the response might contain an error message related to accessing files in `/etc` (if listing directories is not allowed) or potentially the content of files within `/etc` if they happen to have `.html` extensions or cause other errors depending on the server setup and files present in `/etc`. A more reliable test is to target a known readable file like `/etc/passwd`.
        - Send a GET request to `/evals` with the `folder` query parameter set to `../../etc/passwd`. For example: `http://<backend-url>/evals?folder=../../etc/passwd`
        - Observe the response. If path traversal is successful and `/etc/passwd` is readable, the response might contain an error message about not finding `.html` files in `/etc/passwd` (since it's not a directory) or a more generic error if file access is restricted, but importantly, it should *not* be a 404 "Folder not found" error, as this would indicate the path traversal is being blocked at some level, or the initial existence check is bypassing traversal.
    4. **Analyze Response and Confirm Vulnerability:**
        - If the response is not a "Folder not found" error (404) and indicates an attempt to process files in `/etc` or `/etc/passwd` (even if it results in an error due to file type or permissions), this confirms path traversal vulnerability. If you can get a listing of `/etc` or read the content of `/etc/passwd` (depending on server configuration), the vulnerability is clearly demonstrated.
    5. **Test other endpoints:** Repeat steps 3 and 4 for `/pairwise-evals` and `/best-of-n-evals` endpoints using `folder1`, `folder2`, etc. parameters with path traversal sequences to confirm the vulnerability exists in these endpoints as well.
    6. **Cleanup:** No specific cleanup is needed for this test, but ensure your test environment is properly secured after testing.

This test case demonstrates that the application is vulnerable to path traversal, allowing an attacker to potentially access files outside the intended evaluation directories by manipulating the `folder` query parameters.
