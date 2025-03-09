* Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Output

* Description:
    1. A user uploads an image to the application to be converted into code.
    2. The backend uses an AI model to generate frontend code (HTML, CSS, JavaScript) based on the uploaded image.
    3. An attacker crafts a malicious input image that, when processed by the AI model, causes the AI to generate HTML code containing embedded malicious JavaScript. For example, the attacker could create an image that leads the AI to generate code like `<img src="x" onerror="alert('XSS')">` or `<script>alert('XSS')</script>`.
    4. The backend streams the AI-generated code to the frontend via a WebSocket.
    5. The frontend receives the AI-generated code and renders it in the user's browser, likely without sufficient sanitization.
    6. Because the generated code contains malicious JavaScript, the script executes in the user's browser when the generated output is displayed or interacted with. This can lead to Cross-Site Scripting (XSS).

* Impact:
    Successful XSS exploitation can have severe impacts:
    - **Account Takeover:** An attacker can steal session cookies, allowing them to impersonate the user and take over their account.
    - **Data Theft:** Sensitive information displayed on the page or accessible through the user's session can be exfiltrated to a malicious server.
    - **Malware Distribution:** The attacker can redirect the user to malicious websites that host malware, infecting the user's system.
    - **Defacement:** The attacker can modify the content of the web page, displaying misleading or harmful information to the user.
    - **Phishing:** The attacker can inject fake login forms into the page to steal user credentials.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Based on the provided files, there are **no explicit sanitization mechanisms** implemented in the backend or frontend to prevent XSS in the AI-generated output. The application relies on the AI model to generate safe code, which is not a reliable security measure.

* Missing Mitigations:
    - **Output Sanitization:** The most crucial missing mitigation is proper sanitization of the AI-generated code before rendering it in the frontend. This should be implemented on the backend before sending the code to the frontend, or immediately upon receiving it in the frontend before rendering.
    - **Content Security Policy (CSP):** Implementing a strict Content Security Policy (CSP) can significantly reduce the impact of XSS by controlling the resources that the browser is allowed to load and execute.
    - **Regular Security Audits and Testing:** Regularly auditing the code and performing penetration testing, especially focusing on AI-generated output handling, is essential to identify and fix vulnerabilities proactively.

* Preconditions:
    - The attacker needs to be able to upload an image to the application.
    - The application must use an AI model to generate frontend code from the image.
    - The frontend must render the AI-generated code in the user's browser without proper sanitization.
    - The user needs to interact with or view the AI-generated output in their browser for the XSS payload to execute.

* Source Code Analysis:
    1. **`backend/routes/generate_code.py`:** This file handles the `/generate-code` websocket endpoint, which is responsible for generating code.
    2. The `stream_code` function in this file receives user parameters via websocket, including the image and desired stack.
    3. It calls `create_prompt` from `backend/prompts/__init__.py` to assemble the prompt for the AI model.
    4. The code then calls different LLM streaming functions (`stream_openai_response`, `stream_claude_response`, `stream_gemini_response` in `backend/llm.py`) based on configuration and API keys.
    5. The LLM generates code, which is streamed back to the frontend in chunks using `send_message(type="chunk", ...)`.
    6. **Crucially, the generated code chunks are directly sent to the frontend without any sanitization.**
    7. The `extract_html_content` function in `backend/codegen/utils.py` is used, but this function only extracts the HTML part of the response, it does **not sanitize** the HTML content for XSS.
    8. **Frontend (code not provided, analysis based on description):** We assume the frontend receives these code chunks and assembles them, then renders the final HTML in a component, likely using React's `dangerouslySetInnerHTML` or similar methods for dynamic HTML rendering, which, if used without sanitization, will directly execute any JavaScript code present in the AI-generated output.

    ```
    backend/routes/generate_code.py:

    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        ...
        async def process_chunk(content: str, variantIndex: int):
            await send_message("chunk", content, variantIndex) # Sends chunk to frontend WITHOUT sanitization
        ...
        completions = await asyncio.gather(*tasks, return_exceptions=True)
        ...
        completions = [extract_html_content(completion) for completion in completions] # Extracts HTML, but NO sanitization
        ...
        for index, updated_html in enumerate(updated_completions):
            await send_message("setCode", updated_html, index) # Sends final code to frontend WITHOUT sanitization
        ...
    ```

* Security Test Case:
    1. **Prepare a malicious image:** Create or find an image that, when processed by the AI, is likely to generate HTML code containing a JavaScript alert. A simple approach is to create an image depicting HTML code with an XSS payload, for example, an image of text that says `<img src=x onerror=alert('XSS')>`.
    2. **Access the application:** Open the publicly accessible instance of the "screenshot-to-code" application in a web browser.
    3. **Upload the malicious image:** Use the application's interface to upload the prepared malicious image.
    4. **Select code stack and generate code:** Choose any supported frontend stack (e.g., HTML + Tailwind) and initiate the code generation process.
    5. **Observe the output:** Once the AI-generated code is displayed in the frontend:
        - **Check for JavaScript execution:** Verify if an alert box with 'XSS' (or similar payload) appears in the browser. If the alert box appears, it confirms that the malicious JavaScript code generated by the AI has been executed, proving the XSS vulnerability.
        - **Inspect the generated code:** Use browser developer tools to inspect the HTML source code of the generated output. Confirm that the AI-generated code indeed contains the malicious JavaScript payload (e.g., `<img src=x onerror=alert('XSS')>`).

If the alert box appears and the generated code contains the XSS payload, it validates the Cross-Site Scripting vulnerability in the application due to the lack of output sanitization.
