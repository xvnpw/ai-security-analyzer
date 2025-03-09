### Vulnerability List:

- Vulnerability Name: AI-Generated Code Injection leading to Cross-Site Scripting (XSS)
- Description:
    1. An attacker crafts a malicious screenshot or mockup. This input is designed to subtly influence the AI model to include a JavaScript payload within the generated frontend code. For example, the screenshot might visually suggest a button label like `<button>Click <script>alert("XSS")</script></button>`.
    2. The attacker uploads this crafted screenshot to the application via the frontend.
    3. The frontend sends the screenshot to the backend for processing by the AI model.
    4. The backend, using an LLM (like GPT-4 Vision or Claude), processes the screenshot and generates frontend code (HTML, CSS, and JavaScript) based on the visual information. Due to the crafted screenshot, the generated code includes the malicious JavaScript payload, for example,  `<html><body><button>Click <script>alert("XSS")</script></button></body></html>`.
    5. The backend sends this AI-generated code, containing the embedded XSS payload, back to the frontend as a string in the API response (specifically via WebSocket in `backend/routes/generate_code.py`).
    6. The frontend receives the response via WebSocket and presents the generated code to the user, typically for review and potential use in their own web projects.
    7. If a user copies and pastes this AI-generated code into their web application and deploys it, the malicious JavaScript code will be executed in the browsers of users who access this deployed application. This results in XSS.

- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker can execute arbitrary JavaScript code in the victim's browser when they visit a web application containing the vulnerable AI-generated code.
    - Potential impacts include:
        - **Session hijacking:** Stealing user session cookies to impersonate users.
        - **Defacement:** Modifying the content of the web page to display malicious or unwanted information.
        - **Redirection:** Redirecting users to malicious websites.
        - **Information theft:** Stealing sensitive user data or application data.
        - **Malware distribution:** Injecting scripts that download and execute malware on the user's computer.
        - **Denial of Service:** Causing the user's browser or the web application to become unresponsive.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. Based on the source code analysis of `llm.py`, `evals/core.py`, `codegen/utils.py`, `backend/routes/generate_code.py` and other provided files, there are no visible mitigations implemented to sanitize or encode the AI-generated code before it is returned to the user via WebSocket. The backend directly passes the raw string output from the LLM to the frontend through WebSocket messages.

- Missing Mitigations:
    - **Output Sanitization/Encoding:** The most crucial missing mitigation is sanitizing the AI-generated HTML code on the backend before sending it to the frontend. This should involve:
        - Parsing the generated HTML to an abstract syntax tree (AST).
        - Using a robust HTML sanitization library (e.g., DOMPurify for JavaScript backend environments, or bleach for Python backend) to remove or encode any potentially malicious JavaScript code or HTML attributes (like `onclick`, `onload`, `javascript:` URLs etc.).
        - Re-serializing the sanitized AST back into HTML code.
    - **Content Security Policy (CSP) Guidance:** While not a direct mitigation within the `screenshot-to-code` application, providing clear guidance to users about Content Security Policy (CSP) and encouraging them to implement CSP in their deployed web applications would be a helpful secondary defense. This would limit the impact of XSS even if it were to occur.
    - **User Awareness and Warnings:** Displaying a clear warning to users that the generated code is AI-generated and might contain vulnerabilities. Encourage users to carefully review and sanitize the code before deploying it in production environments.

- Preconditions:
    1. **Successful Crafting of Malicious Screenshot/Mockup:** The attacker needs to be able to create a screenshot or mockup that effectively tricks the AI model into generating code with an XSS payload. This might require some trial and error to determine what visual cues are most effective for the chosen AI model.
    2. **User Adoption of Unsanitized Code:** A user must download or copy the AI-generated code and then deploy it in a web application without performing any manual security review or sanitization.
    3. **Vulnerable Deployment Environment:** The deployed web application must be accessible to other users or handle sensitive information for the XSS vulnerability to have a significant impact.

- Source Code Analysis:
    - **File: `backend/llm.py`**:
        - The functions `stream_openai_response`, `stream_claude_response`, `stream_gemini_response`, and `stream_claude_response_native` are responsible for interacting with the LLMs and retrieving the code.
        - For example, in `stream_openai_response`, the code from the LLM is accumulated in the `full_response` variable:
        ```python
        full_response = ""
        async for chunk in stream:
            ...
            content = chunk.choices[0].delta.content or ""
            full_response += content
            await callback(content)
        ```
        - This `full_response` (or similar in Claude/Gemini functions) is directly returned in the `Completion` dictionary without any sanitization:
        ```python
        return {"duration": completion_time, "code": full_response}
        ```
    - **File: `backend/evals/core.py`**:
        - The `generate_code_core` function calls the LLM streaming functions (like `stream_claude_response`) and returns the `code` field from the `Completion` dictionary:
        ```python
        completion = await stream_claude_response(...)
        return completion["code"]
        ```
        - Again, there is no sanitization step applied to the `completion["code"]` before it's returned.
    - **File: `backend/routes/generate_code.py`**:
        - The `stream_code` function handles the WebSocket connection for code generation.
        - After receiving the AI-generated code (`completions` variable, which is derived from the output of functions like `stream_openai_response` or `stream_claude_response` called in this file), the code is processed by `extract_html_content` (in `codegen/utils.py`, previously analyzed and found to not perform sanitization).
        - The extracted HTML content (`updated_html`) is then sent directly to the frontend via WebSocket using `send_message` with `type="setCode"`:
        ```python
        updated_completions = await asyncio.gather(*image_generation_tasks)

        for index, updated_html in enumerate(updated_completions):
            await send_message("setCode", updated_html, index)
            await send_message("status", "Code generation complete.", index)
        ```
        - **Crucially, there is no HTML sanitization applied to `updated_html` before sending it to the frontend.** This confirms that the unsanitized AI-generated code is directly passed to the frontend, making the XSS vulnerability possible.

    - **File: `backend/main.py` and `routes` (not provided, but implied):**
        - The `main.py` file sets up FastAPI and includes routers (`routes.screenshot`, `routes.generate_code`, `routes.evals`, `routes.home`). These routes handle API endpoints that:
            - Receive the screenshot from the frontend.
            - Call `generate_code_for_image` (or similar functions in `evals/core.py` which is triggered via websocket in `generate_code.py`).
            - Return the generated code in the API response (via WebSocket in `generate_code.py`).
        - Based on the architecture and the lack of sanitization in the code generation logic, these routes pass the unsanitized code received from `evals/core.py` and `llm.py` (via `generate_code.py`) directly back to the frontend in the WebSocket response.
    - **Frontend (React/Vite - code not provided):**
        - The frontend, built using React and Vite, is responsible for:
            - Uploading the screenshot.
            - Making API calls to the backend to generate code (via WebSocket).
            - Receiving the generated code from the backend (via WebSocket).
            - Displaying the generated code to the user (likely in a code editor or text area).
            - If the frontend uses `dangerouslySetInnerHTML` in React (or similar mechanisms in other frameworks) to render the HTML code directly without sanitization, it will execute any embedded JavaScript.

    - **Visualization (Conceptual Flow):**

    ```
    [Attacker-Crafted Screenshot] --> [Frontend (Upload)] --> [Backend WebSocket Endpoint - /generate-code]
                                                                    |
                                                                    v
                                                        [Backend - llm.py] --> [LLM (AI Model)]
                                                                    ^         Generates Code with XSS Payload
                                                                    |
                                                        [Backend - evals/core.py] (No Sanitization)
                                                                    |
                                                        [Backend - routes/generate_code.py] (No Sanitization before sending via WebSocket)
                                                                    |
                                                        [WebSocket Response with Unsanitized Code] --> [Frontend]
    [User Copies Unsanitized Code] --> [User's Web Application] --> [User's Browser Executes XSS Payload]
    ```


- Security Test Case:
    1. **Setup:** Deploy a local instance of the `screenshot-to-code` application as described in the `README.md`. Ensure both backend and frontend are running.
    2. **Craft Malicious Screenshot:**
        - Create a simple image (e.g., using an online image editor or drawing tool).
        - In the image, visually represent a button with text that includes an XSS payload. For example, visually render the text for a button as:  `Click <img src=x onerror=alert('XSS')>` (You might need to adjust this based on how well the AI interprets visual text; a simpler payload like `<button>Click <script>alert('XSS')</script></button>` might also work). Save this image as `xss_screenshot.png`.
    3. **Access the Application Frontend:** Open the `screenshot-to-code` frontend in a web browser (typically `http://localhost:5173`).
    4. **Upload Malicious Screenshot:** Use the application's UI to upload the `xss_screenshot.png` image. Select any supported stack (e.g., HTML + Tailwind).
    5. **Generate Code:** Initiate the code generation process within the application.
    6. **Inspect Generated Code:** Once the AI-generated code is displayed in the frontend, carefully examine the generated HTML code. Look for the XSS payload you intended to inject. It might appear something like:
       ```html
       <html>
       <body>
         <button>Click <img src=x onerror=alert('XSS')></button>
       </body>
       </html>
       ```
       or
       ```html
       <html>
       <body>
         <button>Click <script>alert('XSS')</script></button>
       </body>
       </html>
       ```
    7. **Copy Generated Code:** Copy the entire AI-generated HTML code snippet from the frontend.
    8. **Create Test HTML File:** Create a new file named `test_xss.html` on your local machine.
    9. **Paste Generated Code:** Paste the copied AI-generated HTML code into the `test_xss.html` file.
    10. **Open in Browser:** Open `test_xss.html` in a web browser (e.g., Chrome, Firefox, Safari).
    11. **Verify XSS:** Check if the JavaScript payload executes. If you used `<script>alert('XSS')</script>`, you should see an alert box pop up in the browser window with the text "XSS". If you used `<img src=x onerror=alert('XSS')>`, the alert might trigger immediately or when the browser tries to load the broken image.
    12. **Expected Result:** If an alert box appears, it confirms that the application is vulnerable to XSS because the AI has generated code containing the malicious script based on the attacker-crafted screenshot, and this script executes when the generated code is rendered in a browser.
