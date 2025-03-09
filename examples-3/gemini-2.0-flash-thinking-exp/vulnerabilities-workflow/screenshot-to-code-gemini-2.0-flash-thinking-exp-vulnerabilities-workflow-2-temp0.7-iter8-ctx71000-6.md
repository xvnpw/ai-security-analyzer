### Vulnerability 1: Unprotected Backend API Endpoint - Image to Code Conversion

*   **Description:**
    The backend API endpoint responsible for converting images to code lacks authentication and authorization mechanisms. This allows any external user to send requests to this endpoint, providing an image and triggering the AI code conversion process.

    Steps to trigger vulnerability:
    1. Identify the backend API endpoint responsible for handling image to code conversion requests. Based on the file `backend/routes/generate_code.py`, the endpoint is `/generate-code` and it uses WebSocket protocol. The full URL would be something like `ws://<backend-host>:<backend-port>/generate-code`.
    2. Establish a WebSocket connection to this endpoint.
    3. Send a JSON payload to the WebSocket server. This payload should include necessary parameters for code generation, such as `inputMode`, `generatedCodeConfig` (stack), and image data (likely within `params` key, although the exact structure needs to be inferred from frontend or further backend code analysis). For example:

    ```json
    {
      "inputMode": "screenshot",
      "generatedCodeConfig": "react",
      "params": {
        "image": "data:image/png;base64,...[base64 encoded image data]...",
        "isImageGenerationEnabled": true,
        "generationType": "create"
      }
    }
    ```
    4. The backend server, upon receiving the message, will process the image using the configured AI model (e.g., GPT-4 Vision, Claude 3) and send back code chunks and status updates via the WebSocket connection.
    5. Observe that the code generation process starts and code is returned without any prior authentication, API keys in headers, or authorization.

*   **Impact:**
    *   **Abuse of AI API Credits:** Unauthorized users can repeatedly send image conversion requests, consuming the application owner's AI API credits (OpenAI, Anthropic, Replicate, Google Gemini). This can lead to unexpected financial costs for the application owner.
    *   **Resource Exhaustion:** A large number of unauthorized requests can overload the backend server and the AI API, potentially leading to performance degradation or service unavailability.
    *   **Denial of Service (Resource based):** Abuse of resources (AI API credits and backend processing power) can effectively act as a denial of service by making the application economically unsustainable or temporarily unavailable.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    None. Based on the provided files, there is no visible implementation of authentication or authorization checks for the backend API endpoints, including the WebSocket endpoint `/generate-code` in `backend/routes/generate_code.py`. CORS is configured in `backend/main.py`, but it's not a backend security measure.

*   **Missing Mitigations:**
    *   **Authentication:** Implement an authentication mechanism for the WebSocket endpoint `/generate-code`. Consider using WebSocket authentication methods or integrating with existing authentication flows if the application has user accounts.
    *   **Authorization:** Implement authorization to control which users or clients are allowed to use the code generation feature.
    *   **Rate Limiting:** Implement rate limiting on the `/generate-code` endpoint to restrict the number of requests per connection or IP address within a timeframe.
    *   **Usage Quotas:** Consider usage quotas to limit AI API credit consumption per user or client.

*   **Preconditions:**
    *   The backend WebSocket endpoint `/generate-code` must be publicly accessible.
    *   The attacker needs to know the WebSocket endpoint URL and the expected message format. This can be obtained by inspecting the frontend code or network traffic.

*   **Source Code Analysis:**
    1.  **`backend/routes/generate_code.py`**: This file defines the WebSocket endpoint `/generate-code` using `@router.websocket("/generate-code")`.  Reviewing the code within the `stream_code` function, there are no checks for authentication or authorization before processing the incoming WebSocket messages and initiating code generation. The function `stream_code` directly extracts parameters, creates prompts, calls LLM APIs, and streams back the results.

    ```python
    # backend/routes/generate_code.py
    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        await websocket.accept()
        print("Incoming websocket connection...")

        # ... [Error handling and send_message setup] ...

        params: dict[str, str] = await websocket.receive_json() # Receives parameters directly without authentication
        print("Received params")

        extracted_params = await extract_params(params, throw_error) # Extracts parameters
        # ... [Code generation logic using AI models based on parameters] ...
    ```

    2.  **Absence of Security Measures**: Examining `backend/routes/generate_code.py` and other provided backend files (`evals.py`, `screenshot.py`, `home.py`) reveals no middleware, decorators, or explicit code for authentication or authorization on any of the defined API endpoints.

*   **Security Test Case:**
    1.  **Prerequisites:**
        *   Access to a running instance of the `screenshot-to-code` application backend.
        *   An image file for code conversion.
        *   A WebSocket client (e.g., a simple Python script using `websockets` library, or online WebSocket testing tools).

    2.  **Steps:**
        a.  Identify the WebSocket URL for code generation. Assume it is `ws://<backend-host>:<backend-port>/generate-code`.
        b.  Using a WebSocket client, establish a connection to this URL.
        c.  Construct a JSON message as described in the "Description" section (step 3), including an image and necessary parameters.
        d.  Send the JSON message through the WebSocket connection.
        e.  Observe the messages received from the server over the WebSocket.

    3.  **Expected Result:**
        *   The backend server should start sending messages of type `chunk` and `status` over the WebSocket, indicating that code generation is in progress.
        *   Eventually, the server should send messages of type `setCode` containing the generated code.
        *   No authentication challenge or error related to authentication should be received.

    4.  **Success Condition:**
        *   Successfully receiving `chunk` and `setCode` messages containing generated code without any authentication proves that the WebSocket endpoint `/generate-code` is unprotected and vulnerable to unauthorized use.
        *   Monitoring AI API usage (if possible) would further confirm resource consumption due to this unauthenticated request.
