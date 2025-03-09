### Vulnerability 1: Cross-Site Scripting (XSS) via AI-Generated Code

* Description:
    1. An attacker crafts a malicious image that, when processed by the application, will cause the AI model to generate HTML code containing embedded JavaScript.
    2. The user uploads this malicious image through the frontend application.
    3. The backend processes the image using an AI model (e.g., GPT-4 Vision, Claude).
    4. The AI model, based on the malicious image, generates HTML code that includes the attacker's injected JavaScript.
    5. The backend sends this AI-generated HTML code back to the frontend via WebSocket without sanitization.
    6. The frontend receives the HTML code and dynamically renders it in the user's browser, executing the embedded malicious JavaScript.
    7. The attacker's JavaScript code then runs in the context of the user's browser session, potentially allowing for session hijacking, cookie theft, or redirection to malicious websites.

* Impact:
    * High. Successful XSS attack can lead to:
        - Account takeover: Attacker can steal session cookies or other authentication tokens.
        - Data theft: Attacker can access sensitive information available in the user's browser or local storage.
        - Malicious redirection: Attacker can redirect users to phishing websites or sites hosting malware.
        - Defacement: Attacker can modify the content of the web page viewed by the user.

* Vulnerability Rank: High

* Currently implemented mitigations:
    * None identified in the provided project files. The backend code processes the AI response and sends it directly to the frontend via WebSocket without any apparent sanitization.

* Missing mitigations:
    * **Backend-side sanitization:** Implement HTML sanitization on the backend before sending the AI-generated code to the frontend. Use a library like Bleach in Python to sanitize the HTML and remove potentially malicious JavaScript or other dangerous content.
    * **Frontend-side sanitization/Content Security Policy (CSP):** Although backend sanitization is crucial, consider implementing frontend-side sanitization as a defense-in-depth measure. Additionally, implement a strict Content Security Policy (CSP) to further restrict the execution of inline JavaScript and other potentially dangerous behaviors. However, frontend sanitization alone is not sufficient and backend sanitization is mandatory.

* Preconditions:
    * The attacker needs access to the application's image upload functionality, which is publicly available in the hosted version as mentioned in `README.md`.
    * The application must be configured to use an AI model that can generate code based on images.
    * The frontend must dynamically render the received HTML code without proper sanitization.

* Source code analysis:

    1. **`backend\routes\generate_code.py`:** This file contains the `/generate-code` WebSocket endpoint that handles the code generation process.
    2. **`stream_code` function:** This function in `backend\routes\generate_code.py` is responsible for receiving the image and parameters from the frontend, calling the AI model, and sending the generated code back to the frontend.
    3. **AI Code Generation:** The code calls `create_prompt` in `prompts\__init__.py` to construct prompts for the AI model and then uses functions in `llm.py` (e.g., `stream_openai_response`, `stream_claude_response`) to interact with the AI model.
    4. **Code Streaming via WebSocket:** The AI-generated code chunks are streamed back to the frontend using `await send_message("chunk", content, variantIndex)`.  The final code is sent using  `await send_message("setCode", updated_html, index)`.
    5. **No Sanitization:** Critically, there is **no code within `backend\routes\generate_code.py` or `llm.py` that sanitizes the `content` or `updated_html` before sending it to the frontend**. The code directly forwards the raw AI-generated HTML to the frontend.
    6. **`codegen.utils.extract_html_content`:** This function in `backend\codegen\utils.py` only extracts the HTML content from the AI response but performs no sanitization. It's used like this: `completions = [extract_html_content(completion) for completion in completions]`.

    ```python
    # backend\routes\generate_code.py

    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        # ...
        async def send_message(
            type: Literal["chunk", "status", "setCode", "error"],
            value: str, # <--- AI generated code, potentially malicious
            variantIndex: int,
        ):
            # ...
            await websocket.send_json(
                {"type": type, "value": value, "variantIndex": variantIndex}
            )
        # ...
        # ... AI code generation logic ...
        # Post-processing
        completions = [extract_html_content(completion) for completion in completions] # <--- No sanitization here

        for index, updated_html in enumerate(updated_completions): # <--- No sanitization here
            await send_message("setCode", updated_html, index) # <--- Sending unsanitized HTML to frontend
            # ...
    ```

    **Visualization of Data Flow (Backend):**

    ```mermaid
    graph LR
        Frontend --> WebSocketEndpoint(/generate-code)
        WebSocketEndpoint --> create_prompt(prompts/__init__.py)
        create_prompt --> LLM(llm.py)
        LLM --> WebSocketEndpoint
        WebSocketEndpoint --> extract_html_content(codegen/utils.py)
        extract_html_content --> send_message(WebSocketEndpoint)
        send_message --> Frontend
    ```


* Security test case:

    1. **Prepare a malicious image:** Create a PNG image that visually resembles a simple webpage but is designed to trick the AI model into generating HTML code with embedded JavaScript. This could include text within the image like `<img src=x onerror=alert('XSS')>` or similar XSS payloads subtly embedded within the visual elements.
    2. **Start the application:** Run the frontend and backend of the `screenshot-to-code` application locally or access a publicly hosted instance.
    3. **Navigate to the application in a browser:** Open the application in a web browser (e.g., `http://localhost:5173`).
    4. **Upload the malicious image:** Use the application's interface to upload the prepared malicious image. Select any stack (e.g., HTML + Tailwind).
    5. **Observe the output:** After the AI processing is complete and the generated code is displayed in the frontend, check if the JavaScript code embedded in the malicious image is executed.
    6. **Verify XSS:** If an alert box pops up with 'XSS' or if you observe other JavaScript execution (e.g., in the browser's developer console), it confirms the XSS vulnerability.
    7. **Examine the generated code:** Inspect the HTML code generated by the AI model. Verify that it contains the injected JavaScript payload from the malicious image.
