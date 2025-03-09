- Vulnerability Name: PIL Image Processing Vulnerability

- Description:
    1. An attacker uploads a malicious image file to the application.
    2. The backend receives the image as a base64 data URL in the `/generate-code` websocket endpoint.
    3. The `stream_claude_response` function in `backend/llm.py` is called to process the image for Claude API.
    4. Inside `stream_claude_response`, the `process_image` function from `backend/image_processing/utils.py` is invoked.
    5. The `process_image` function decodes the base64 data and uses `PIL.Image.open(io.BytesIO(image_bytes))` to open the image file.
    6. If the uploaded image is maliciously crafted to exploit a vulnerability in PIL's image processing capabilities (e.g., buffer overflows, out-of-bounds reads/writes) during the `Image.open()`, `img.resize()` or `img.save()` operations, it could lead to arbitrary code execution on the server.
    7. This can allow the attacker to gain full control of the server, steal sensitive data, or perform other malicious actions.

- Impact:
    - Critical: Remote Code Execution (RCE). An attacker can execute arbitrary code on the server running the application.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None: The code uses PIL library for image processing without any explicit security measures to sanitize or validate the image file before processing it with PIL.

- Missing Mitigations:
    - Input validation and sanitization: Implement robust validation of uploaded image files to ensure they conform to expected formats and do not contain malicious payloads. This could include:
        - File type validation: Verify that the uploaded file is indeed an image file (e.g., using magic bytes).
        - Format-specific validation: Use libraries to validate the internal structure of image files to detect and reject malformed or malicious files.
    - Use of secure image processing libraries: Consider using more secure image processing libraries or sandboxed environments for image processing to limit the impact of potential vulnerabilities.
    - Regular security updates: Keep the PIL library and other dependencies up-to-date to patch known vulnerabilities.

- Preconditions:
    - The application must be running and accessible over the network.
    - An attacker needs to be able to send a request to the `/generate-code` websocket endpoint with a malicious image. This is possible for any user with access to the application's frontend.

- Source Code Analysis:
    1. `backend\routes\generate_code.py`: The `/generate-code` websocket endpoint is defined in `stream_code` function. This function receives image data as part of `params` from the frontend.
    2. `backend\llm.py`: In `stream_claude_response` function, `process_image(image_data_url)` is called to process the image.
    ```python
    async def stream_claude_response(
        messages: List[ChatCompletionMessageParam],
        api_key: str,
        callback: Callable[[str], Awaitable[None]],
        model: Llm,
    ) -> Completion:
        ...
        for content in message["content"]:  # type: ignore
            if content["type"] == "image_url":
                content["type"] = "image"
                # Extract base64 data and media type from data URL
                image_data_url = cast(str, content["image_url"]["url"])
                # Process image and split media type and data
                # so it works with Claude (under 5mb in base64 encoding)
                (media_type, base64_data) = process_image(image_data_url) # [VULNERABLE CODE]
                ...
    ```
    3. `backend\image_processing\utils.py`: The `process_image` function uses `PIL.Image.open()` which is vulnerable to image processing exploits.
    ```python
    # Process image so it meets Claude requirements
    def process_image(image_data_url: str) -> tuple[str, str]:
        ...
        image_bytes = base64.b64decode(base64_data)
        img = Image.open(io.BytesIO(image_bytes)) # [VULNERABLE CODE]
        ...
        img = img.resize((new_width, new_height), Image.DEFAULT_STRATEGY) # [VULNERABLE CODE]
        ...
        img = img.convert("RGB")  # Ensure image is in RGB mode for JPEG conversion
        img.save(output, format="JPEG", quality=quality) # [VULNERABLE CODE]
        ...
    ```
    4. Data flow visualization:
    ```mermaid
    sequenceDiagram
        participant Frontend
        participant Backend
        participant PIL Library

        Frontend->>Backend: WebSocket request to /generate-code with malicious image (base64 data URL)
        Backend->>llm.py: stream_code receives image data
        llm.py->>image_processing/utils.py: stream_claude_response calls process_image(image_data_url)
        image_processing/utils.py->>PIL Library: process_image calls Image.open(io.BytesIO(image_bytes)) [Vulnerable]
        PIL Library-->>image_processing/utils.py: Potential vulnerability exploited (RCE)
        image_processing/utils.py-->>llm.py: Returns processed image (if exploit didn't crash)
        llm.py-->>Backend: Continues code generation
        Backend-->>Frontend: Sends generated code (if exploit didn't crash)
    ```

- Security Test Case:
    1. Prepare a malicious image file that is designed to exploit a known vulnerability in the PIL library (e.g., a specially crafted PNG or JPEG file). You can find or create such files using online resources or vulnerability research tools related to PIL image vulnerabilities. For example, search for "PIL image vulnerability exploit".
    2. Encode the malicious image file into a base64 data URL.
    3. Open the frontend of the "screenshot-to-code" application in a web browser (e.g., `http://localhost:5173`).
    4. In the application, select any code stack (e.g., HTML + Tailwind).
    5. Instead of uploading a normal screenshot, inject the base64 data URL of the malicious image into the image input field. This might require using browser developer tools to modify the frontend code temporarily or crafting a malicious request directly if input field manipulation is not straightforward. Alternatively, use a tool like `curl` or `websocat` to directly send a malicious websocket message.
    6. Send the code generation request through the application (e.g., by clicking the "Generate Code" button).
    7. Monitor the backend server for signs of successful code execution. This could involve:
        - Checking for unexpected server behavior or crashes.
        - Monitoring server logs for error messages related to PIL or image processing, or signs of shell access or unusual activity.
        - Using a network monitoring tool to observe network traffic for unexpected outbound connections originating from the backend server after processing the malicious image.
        - If you have access to the server environment, try to trigger a "reverse shell" by crafting the malicious image to execute a command that connects back to your attacker machine.
    8. If successful, the attacker will gain remote code execution on the server, confirming the vulnerability. If the server crashes or exhibits other abnormal behavior upon processing the image, it is also a strong indication of a vulnerability, even without achieving direct code execution.
