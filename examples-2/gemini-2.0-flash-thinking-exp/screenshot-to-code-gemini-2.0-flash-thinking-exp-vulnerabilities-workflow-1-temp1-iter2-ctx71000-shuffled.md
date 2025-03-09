## Combined Vulnerability List

This document outlines the identified vulnerabilities by combining and deduplicating information from the provided lists.

### Path Traversal Vulnerability in `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` Endpoints

- **Vulnerability Name:** Path Traversal in `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` Endpoints
- **Description:**
    The `get_evals`, `get_pairwise_evals`, and `get_best_of_n_evals` endpoints in `evals.py` are susceptible to path traversal attacks. These endpoints accept user-supplied folder paths as input parameters (`folder`, `folder1`, `folder2`, `folder{i}`). The application utilizes these paths to list files and read HTML content. Critically, there is a lack of validation to verify that the provided folder paths remain within the intended directories. By providing maliciously crafted paths, such as `../../../../etc`, an attacker can bypass directory restrictions and access files located outside the intended directory structure, potentially leading to the exposure of sensitive files on the server.

- **Impact:**
    Successful exploitation of this vulnerability allows an attacker to read arbitrary files from the server's file system, provided the application process possesses the necessary file system permissions. The consequences of this unauthorized file access include:
    - **Information Disclosure:** Confidential data, such as configuration files containing sensitive credentials (database passwords, API keys), application source code revealing business logic and potential weaknesses, internal documentation detailing system architecture and security measures, or even sensitive system files like `/etc/passwd` (if accessible) can be exposed.
    - **Further Exploitation:** Gaining access to configuration files or internal documentation can provide attackers with the necessary information to launch more targeted and sophisticated attacks. For example, exposed database credentials or API keys can be directly used to compromise other systems or data.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    None. The current implementation includes a check using `os.path.exists()` to verify if the provided folder exists. However, this check is insufficient as it does not validate whether the path is within an allowed or restricted directory. There is no mechanism in place to prevent users from traversing up the directory tree and accessing files outside the intended scope.
- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust path validation to rigorously ensure that all user-provided folder paths are strictly confined to the intended and authorized directories. This mitigation should incorporate the following steps:
        - **Define Allowed Base Directory:** Establish a clearly defined base directory, such as `EVALS_DIR` or a specific subdirectory within it, which represents the root path for all legitimate file access operations via these endpoints.
        - **Resolve Absolute Paths:** Utilize `os.path.abspath()` to convert both the user-provided folder path and the defined allowed base directory into absolute paths. This step resolves symbolic links and normalizes paths, preventing bypasses through path manipulation.
        - **Path Containment Check:** Employ the `startswith()` method to verify that the resolved absolute path of the user-provided folder path begins with the resolved absolute path of the allowed base directory. This ensures that the user-provided path is a subdirectory of or within the allowed base directory.
        - **Reject Invalid Requests:** If the path containment check fails, meaning the user-provided path is outside the allowed base directory, the application should immediately reject the request. Return an appropriate HTTP error code, such as 400 Bad Request or 404 Not Found, along with a clear error message indicating that the requested path is invalid or unauthorized.

- **Preconditions:**
    - The application must be deployed and accessible over a network, making the vulnerable endpoints reachable to potential external attackers.
    - Attackers must have knowledge of the API endpoints and the parameter names used to specify folder paths. This information is typically discoverable through API documentation, reverse engineering, or by observing network requests made by the application's frontend. The relevant endpoints and parameters are:
        - `/evals?folder=<malicious_path>`
        - `/pairwise-evals?folder1=<malicious_path>&folder2=<another_path>`
        - `/best-of-n-evals?folder1=<malicious_path>&folder2=<path2>&folder3=<path3>...`

- **Source Code Analysis:**
    - **File:** `..\screenshot-to-code\backend\routes\evals.py`
    - **Functions:** `get_evals`, `get_pairwise_evals`, `get_best_of_n_evals`

    - **Vulnerable Code Snippet (from `get_evals`):**
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
                    f: os.path.join(folder, f) # [VULNERABLE LINE] - Path is directly joined without validation
                    for f in os.listdir(folder)
                    if f.endswith(".html")
                }

                # ... rest of the code ...
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
        ```
    - **Explanation:**

        1. The `get_evals` function is defined to handle GET requests to the `/evals` endpoint. It expects a query parameter named `folder`, which is intended to specify the directory from which to retrieve evaluation files.
        2. The function first checks if the `folder` parameter is provided. If it's missing, an HTTP 400 error is raised, indicating a bad request.
        3. It then creates a `Path` object from the user-provided `folder` string and uses `folder_path.exists()` to verify if the directory exists on the file system. If the directory does not exist, an HTTP 404 error is raised.
        4. **Vulnerability:** The core of the vulnerability lies in how the code proceeds after validating the existence of the folder. It directly utilizes the user-provided `folder` path in subsequent file system operations, specifically in `os.listdir(folder)` and `os.path.join(folder, f)`. There is no validation or sanitization applied to the `folder` path to ensure it remains within an intended or safe directory.
        5. If an attacker provides a path containing traversal sequences like `../../../../etc`, the `os.listdir()` function will attempt to list the contents of the `/etc` directory on the server's file system. Similarly, `os.path.join()` will construct file paths under the `/etc` directory. This behavior is the essence of a path traversal vulnerability.
        6. The code then proceeds to iterate through the files listed by `os.listdir()`, filters for HTML files (`.html` extension), and attempts to process them as evaluation files. If successful, the content of these files, potentially from a traversed directory, is returned in the API response.

    - The `get_pairwise_evals` and `get_best_of_n_evals` functions contain analogous vulnerabilities. They handle parameters like `folder1`, `folder2`, and `folder{i}` in the same insecure manner, making them equally vulnerable to path traversal attacks.

- **Security Test Case:**
    1. **Target Endpoint:** `/evals`
    2. **HTTP Method:** `GET`
    3. **Parameter:** `folder`
    4. **Malicious Input:** `folder=../../../../etc`
    5. **Test Steps:**
        - Initiate a GET request to the `/evals` endpoint of the application with the `folder` parameter set to the malicious path `../../../../etc`.  Using `curl` as an example:
          ```bash
          curl "http://<application_url>/evals?folder=../../../../etc"
          ```
        - Examine the HTTP response received from the server.

    6. **Expected Vulnerable Response:**
        - In a vulnerable application, the server might respond with a list of `Eval` objects.  If there happen to be any `.html` files within the `/etc` directory (which is generally uncommon but theoretically possible), the response might include their contents. More typically, if no HTML files are found in `/etc`, the response would be an empty list of `Eval` objects (`[]`). Crucially, in a vulnerable scenario, no error would be returned to indicate that path traversal was detected or prevented. The application attempts to access files within the `/etc` directory based on the attacker-controlled input.

    7. **Expected Mitigated Response:**
        - If the path traversal vulnerability is properly mitigated, the application should react to the malicious input by:
            - Returning an HTTP error response. A 400 Bad Request status code would be appropriate to indicate that the input path is invalid due to security restrictions. Alternatively, a 404 Not Found could be returned if the application chooses not to explicitly disclose the reason for rejection.
            - Providing an error message within the response body that clearly states the path is invalid or not allowed due to security policies.
            - Alternatively, the application might silently return an empty list or a generic error message without attempting to access or list files in the traversed path, effectively preventing the path traversal without explicitly revealing the security measure.

    **Note:** To definitively confirm arbitrary file reading, a more targeted test could involve attempting to access a known file that is likely to exist and be readable by the application process but resides outside the intended `EVALS_DIR`. For example, if a configuration file is located in a parent directory, or a common system file (although OS permissions might restrict access to system files). However, testing with `../../../../etc` effectively demonstrates the attempt and presence of the path traversal vulnerability.

### Unprotected Evals Endpoints

- **Vulnerability Name:** Unprotected Evals Endpoints
- **Description:**
    The evaluation endpoints located in `backend/routes/evals.py` are configured to be publicly accessible without any form of authentication or authorization. This lack of access control allows any external, unauthenticated attacker to interact with these endpoints. Specifically, a malicious actor can:
    1. **List Models and Stacks:** Access the `/models` endpoint to retrieve a comprehensive list of available models and stacks that are configured within the application. This provides attackers with information about the application's capabilities and configuration.
    2. **Trigger Evaluations and Consume API Credits:** Utilize the `/run_evals` endpoint to initiate evaluation processes by specifying target models and stacks. This action triggers the application to make calls to external Large Language Model (LLM) APIs (such as OpenAI, Anthropic, Gemini, Replicate) that are configured for use by the application. As a result, each triggered evaluation consumes API credits from the application owner's account with the respective LLM provider. An attacker can repeatedly exploit this to exhaust API credits.
    3. **Access Evaluation Results:** Retrieve evaluation results through the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints. This allows unauthorized access to potentially sensitive evaluation data, which may include input images (screenshots) and the code generated by the AI models as part of the evaluation process. Depending on the nature of the evaluation datasets, this could expose confidential or proprietary information.

    In summary, the absence of authentication and authorization on these endpoints creates a significant security vulnerability, enabling malicious actors to abuse the evaluation functionality for resource consumption, information gathering, and potentially other unauthorized purposes.

- **Impact:**
    The impact of these unprotected endpoints is multifaceted and potentially severe:
    - **Financial Impact**:  An attacker can repeatedly and easily trigger the `/run_evals` endpoint. This can lead to substantial, unauthorized consumption of API credits for the LLM services (OpenAI, Anthropic, Gemini, Replicate) that the application utilizes for evaluations. This directly translates to unexpected and potentially significant financial costs for the application owner as they are billed for the API usage initiated by the attacker.
    - **Information Disclosure**: Evaluation results, which are accessible via the `/evals`, `/pairwise-evals`, and `/best-of-n-evals` endpoints, may contain sensitive information. This can include the input screenshots used for evaluation and the corresponding code generated by the AI models. If the evaluation datasets involve sensitive data, such as proprietary designs, confidential documents represented as screenshots, or code that embodies intellectual property, unauthorized access to these results constitutes a data breach and information disclosure.
    - **Resource Exhaustion (Indirect)**: While not a direct denial-of-service (DoS) vulnerability in the traditional sense, the continuous and unchecked triggering of evaluations by an attacker can indirectly lead to resource exhaustion.  Excessive evaluation requests can overload backend processing resources (CPU, memory, network bandwidth) and potentially degrade the overall performance and responsiveness of the application for legitimate users. In extreme cases, it could lead to service disruptions.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    None. A review of the code in `backend/routes/evals.py` confirms that the API endpoints are defined using FastAPI's `APIRouter` without any implemented authentication or authorization mechanisms. The endpoint definitions lack any security decorators or middleware that would enforce access controls. Furthermore, the inclusion of `evals.router` in the main application setup (`main.py`) ensures that these unprotected endpoints are indeed exposed and publicly accessible.
    ```python
    # backend/main.py
    app.include_router(evals.router)
    ```
    This inclusion confirms that the evaluation endpoints are integrated into the application's API without any security layers.

- **Missing Mitigations:**
    To effectively address the vulnerability of unprotected eval endpoints, the following mitigations are essential:
    - **Authentication**: Implement a robust authentication mechanism to verify the identity of any user or client attempting to access the evaluation endpoints. Common authentication methods suitable for API endpoints include:
        - **API Keys**: Require clients to include a valid API key in their requests. The server validates the API key against a list of authorized keys.
        - **JWT (JSON Web Tokens)**: Implement JWT-based authentication where clients obtain a JWT after successful login and include it in subsequent requests. The server verifies the JWT's signature and claims.
        - **Session-based Authentication**: For browser-based clients, session-based authentication using cookies can be implemented to track authenticated users.

    - **Authorization**: Implement an authorization mechanism that controls access to the eval endpoints based on user roles, permissions, or other criteria. Authorization determines what actions an authenticated user is permitted to perform. Access to the evaluation endpoints should be restricted to authorized users only, such as:
        - **Role-Based Access Control (RBAC)**: Define roles (e.g., administrator, evaluator) and assign permissions to each role. Only users with authorized roles can access the eval endpoints.
        - **Policy-Based Access Control (PBAC)**: Implement more fine-grained access control policies based on various attributes, such as user identity, time of day, or resource being accessed.
        - Restrict access to administrative users, internal services, or specific whitelisted clients as per the application's security requirements.

    - **Rate Limiting**: Implement rate limiting, particularly on the `/run_evals` endpoint. Rate limiting restricts the number of requests from a single IP address or user within a defined time window. While less effective than authentication and authorization in preventing unauthorized access, rate limiting serves as a crucial supplementary mitigation to:
        - **Prevent Abuse**:  Mitigate the impact of abuse by limiting the frequency with which an attacker can trigger evaluations, thus reducing API credit consumption and resource exhaustion.
        - **Slow Down Attacks**: Rate limiting can slow down automated attacks and make large-scale exploitation more difficult.
        - Rate limiting should be configured to a reasonable threshold that allows legitimate use while preventing abuse. Consider implementing adaptive rate limiting that adjusts limits based on traffic patterns.

- **Preconditions:**
    - **Publicly Accessible Application Instance:** A publicly accessible instance of the `screenshot-to-code` application must be deployed and actively running. This makes the vulnerable endpoints reachable over the internet.
    - **Configured LLM API Keys:** For the `/run_evals` endpoint to be fully exploitable (specifically for API credit consumption), API keys for at least one of the supported LLM providers (OpenAI, Anthropic, Gemini, Replicate) must be correctly configured in the backend of the application. Without valid API keys, the `/run_evals` endpoint may still be accessible, but it will likely fail to perform evaluations or consume API credits, reducing the financial impact aspect of the vulnerability. However, the information disclosure vulnerability via `/evals` and other endpoints remains even without configured LLM API keys.

- **Source Code Analysis:**
    1. **File:** `backend/routes/evals.py`
    2. **Router Definition:** The code begins by initializing a FastAPI `APIRouter` to organize and define the evaluation-related API endpoints:
    ```python
    router = APIRouter()
    ```
    This router instance is used to decorate and register the subsequent endpoint functions.

    3. **Endpoint Definitions:** Several key endpoints are defined and associated with the `router`. These include:
        - `@router.get("/evals", response_model=List[Eval])`: Defines the `/evals` endpoint for retrieving evaluation results. It's configured for HTTP GET requests.
        - `@router.get("/pairwise-evals", response_model=List[EvalPair])`: Defines the `/pairwise-evals` endpoint for retrieving pairwise evaluation results. Also for GET requests.
        - `@router.post("/run_evals", response_model=List[str])`: Defines the `/run_evals` endpoint, which is critical for triggering the execution of image evaluations. It's configured for HTTP POST requests, indicating it's intended for actions that modify state (in this case, initiating evaluations).
        - `@router.get("/models", response_model=List[Model])`: Defines the `/models` endpoint for listing available models and stacks. For GET requests.
        - `@router.get("/best-of-n-evals", response_model=List[Eval])`: Defines the `/best-of-n-evals` endpoint for retrieving best-of-n evaluation results, using GET requests.

    4. **Absence of Authentication/Authorization:** A critical observation is that none of these endpoint definitions include any decorators or middleware designed to enforce authentication or authorization. There is no usage of FastAPI's `Depends` with security schemes or custom dependency injection to validate user credentials or roles before processing requests to these endpoints. The endpoints are simply defined as functions decorated with `@router.get` or `@router.post`, making them directly accessible to anyone who can reach the application's API.

    5. **`run_evals` Endpoint Vulnerability:** The `/run_evals` endpoint, defined as:
    ```python
    @router.post("/run_evals", response_model=List[str])
    async def run_evals(request: RunEvalsRequest) -> List[str]:
        """Run evaluations on all images in the inputs directory for multiple models"""
        all_output_files: List[str] = []

        for model in request.models:
            output_files = await run_image_evals(model=model, stack=request.stack)
            all_output_files.extend(output_files)

        return all_output_files
    ```
    directly invokes the `run_image_evals` function from `backend/evals/runner.py`. This `run_image_evals` function is responsible for orchestrating the code generation process using the configured LLM models.  Without authentication, any external user can send a POST request to `/run_evals` with a valid `RunEvalsRequest` payload and initiate these evaluations. This leads to direct and unauthorized API credit consumption, as the application will make calls to the configured LLM provider based on the attacker's request.

    6. **`evals`, `pairwise-evals`, `best-of-n-evals` Endpoint Vulnerability:** The endpoints responsible for retrieving evaluation data (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) also lack any form of access control. This means that if an attacker knows or can guess the folder paths where evaluation data is stored, they can potentially access and download this data without any authentication or authorization checks.

    7. **Permissive CORS Configuration:**  The `main.py` file in the backend configures Cross-Origin Resource Sharing (CORS) with a very permissive setting:
    ```python
    # backend/main.py
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```
    `allow_origins=["*"]` effectively allows requests from any origin (any website, any domain) to access the application's API. While CORS itself is primarily a browser-side security mechanism and not a replacement for server-side authentication, this extremely permissive CORS configuration, combined with the complete lack of authentication on the eval endpoints, significantly widens the attack surface. It makes it trivial for attackers from any origin, including malicious websites or browser extensions, to exploit these vulnerabilities, as they bypass browser-based same-origin policy restrictions. This permissive CORS setting exacerbates the severity of the missing authentication vulnerability on the eval endpoints.

- **Security Test Case:**
    1. **Setup:** Ensure you have a publicly accessible instance of the `screenshot-to-code` application deployed and running.  Crucially, for full testing of the API credit consumption impact, you need to have valid API keys configured for at least one LLM provider (OpenAI, Anthropic, Gemini, or Replicate) in the application's backend. If you only want to test for unauthorized access to endpoints and information disclosure (but not API credit depletion), API keys are not strictly necessary for this specific test case.

    2. **Access `/models` endpoint:** Using a web browser or a command-line tool like `curl`, send an HTTP GET request to the `/models` endpoint of your deployed application instance. For example, if your application is accessible at `http://<your-public-instance-ip>:7001`, use the following `curl` command:
    ```bash
    curl http://<your-public-instance-ip>:7001/models
    ```
    Verify the response. You should receive a JSON-formatted response that lists the available models and stacks configured in the application.  Confirm that this response is received without any authentication challenge or request for credentials. If you can access this information without logging in or providing any API key, it confirms the endpoint is publicly accessible.

    3. **Trigger `/run_evals` endpoint:**  To test the `/run_evals` endpoint, you need to send an HTTP POST request with a valid `RunEvalsRequest` payload in JSON format. You can use `curl`, Postman, or a similar HTTP client tool. The request body should specify the `models` and `stack` for the evaluation. For example:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"models": ["gpt-4o-2024-11-20"], "stack": "html_tailwind"}' http://<your-public-instance-ip>:7001/run_evals
    ```
    Execute this command and then carefully observe the server-side logs of your application. You should see log entries indicating that evaluations are being triggered. More importantly, if you have configured LLM API keys, you should also observe logs showing API calls being made to the configured LLM provider (e.g., OpenAI, Anthropic). To definitively confirm API credit consumption, monitor your API usage dashboard on the LLM provider's platform. An increase in API usage after triggering the `/run_evals` endpoint confirms that unauthorized evaluations are being executed and consuming your API credits.

    4. **Access `/evals` endpoint:** To test the `/evals` endpoint and verify unauthorized access to evaluation results, you first need to have some evaluation output data generated. You can achieve this by successfully running step 3 (triggering `/run_evals`). Once evaluations have been performed, and output files are generated in the designated `EVALS_DIR/outputs` directory on the server, you can attempt to access the `/evals` endpoint. You need to provide the folder path of the evaluation output as a query parameter to the `/evals` endpoint. For instance, if the output folder is named `evals_data/outputs/Jul_10_2024_gpt-4o-2024-11-20_html_tailwind`, the `curl` command would be:
    ```bash
    curl "http://<your-public-instance-ip>:7001/evals?folder=evals_data/outputs/Jul_10_2024_gpt-4o-2024-11-20_html_tailwind"
    ```
    Execute this command and verify the HTTP response. You should receive a JSON response containing evaluation data. This data typically includes input images (screenshots) and the corresponding code outputs generated by the AI models. The critical verification point is that you receive this evaluation data without being prompted for any authentication or authorization. Access to this data without login or API keys confirms the endpoint's lack of protection.

    5. **Repeat for other eval endpoints:**  Apply the same testing methodology (primarily using `curl` GET requests) to the other evaluation data retrieval endpoints: `/pairwise-evals` and `/best-of-n-evals`. You will need to construct appropriate folder paths as query parameters for these endpoints, corresponding to the output directories where pairwise or best-of-n evaluation results are stored. Verify that you can access and retrieve data from these endpoints without any authentication, reinforcing the conclusion that all eval-related endpoints are unprotected and vulnerable to unauthorized access.

By successfully completing these test steps, you will have definitively demonstrated that the evaluation endpoints within the `screenshot-to-code` application are unprotected and vulnerable to unauthorized access and potential abuse, including API credit consumption and information disclosure.
