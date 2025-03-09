- Vulnerability name: Cross-Site Scripting (XSS) in AI-Generated Code
- Description:
    1. An attacker crafts a malicious screenshot or video. This malicious input is designed to trick the AI model into generating HTML code that includes a JavaScript payload. For example, the screenshot could depict UI elements with text content that resembles HTML tags or event handlers that, when interpreted by the AI, are turned into actual executable JavaScript.
    2. The user uploads this malicious screenshot or video to the application.
    3. The backend processes the input using an AI model (like GPT-4 Vision or Claude) or, in development/testing scenarios, uses mock responses as defined in `backend\mock_llm.py`, to generate code based on the visual information in the screenshot or video.
    4. Due to the nature of AI models, the use of mock responses, and the lack of specific output sanitization, the AI model or mock responses may inadvertently or intentionally include the malicious JavaScript payload within the generated HTML code, directly embedding the attacker's script within the output.
    5. The backend extracts the generated HTML code using the `extract_html_content` function in `backend\codegen\utils.py`. This function extracts the HTML using regular expressions but does not perform any sanitization or encoding of the HTML content, including any JavaScript code that may be present.
    6. The backend sends this AI-generated and unsanitized HTML code to the frontend via a WebSocket message of type `setCode` in `backend\routes\generate_code.py`.
    7. The frontend receives this message and renders the HTML code, presumably to display the generated code or a preview of the webpage. If the frontend directly injects this HTML into the DOM without proper sanitization (which is assumed based on the backend code analysis and project description), the malicious JavaScript payload embedded in the AI-generated code will be executed in the user's browser.
    8. Any user who views or interacts with the generated code in the frontend could trigger the XSS payload.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the browser of users viewing the AI-generated code. This can lead to various malicious activities, including:
    * **Data theft:** Stealing session cookies, access tokens, or other sensitive information.
    * **Account takeover:** Performing actions on behalf of the user, potentially including changing passwords or accessing private data.
    * **Redirection to malicious sites:** Redirecting users to phishing websites or sites hosting malware.
    * **Defacement:** Altering the appearance of the web page displayed in the frontend.
    * **Further exploitation:** Using the XSS vulnerability as a stepping stone to other attacks.

- Vulnerability rank: High

- Currently implemented mitigations:
    * None detected in the provided backend code. The code focuses on functionality (code generation, image processing) but lacks any visible input or output sanitization mechanisms. The `extract_html_content` function in `backend\codegen\utils.py` specifically does *not* sanitize the HTML.

- Missing mitigations:
    * **Backend-side sanitization:** Implement HTML sanitization on the backend before sending the generated code to the frontend. This should remove or neutralize any potentially malicious JavaScript or HTML tags and attributes. Libraries like Bleach (Python) could be used for this purpose.
    * **Frontend-side sanitization/Content Security Policy (CSP):** Even with backend sanitization, it's best practice to implement frontend-side mitigations. Use a framework or library that automatically sanitizes HTML when rendering or implement a Content Security Policy (CSP) to restrict the sources from which scripts can be executed and prevent inline JavaScript execution.
    * **Input validation:** While preventing malicious screenshots entirely might be impossible, consider adding input validation or pre-processing to detect and potentially flag or reject suspicious screenshots before they are processed by the AI. This is a more complex mitigation and might impact the functionality.

- Preconditions:
    * An attacker needs to craft a malicious screenshot or video that can successfully induce the AI model to generate code containing an XSS payload. This requires some understanding of how AI models interpret images and generate code, but with iterative testing, it is feasible. Alternatively, if mock responses from `mock_llm.py` are used, the attacker could rely on these pre-defined, potentially vulnerable code snippets being returned.
    * The application must be running and accessible to the attacker.
    * Users must interact with or view the AI-generated code in the frontend for the XSS to be triggered.

- Source code analysis:
    1. **`backend\routes\generate_code.py`:** This file handles the `/generate-code` WebSocket endpoint, which is responsible for generating code from user input.
    2. **Line 309:** `completions = [extract_html_content(completion) for completion in completions]` - This line calls the `extract_html_content` function.
    3. **`backend\codegen\utils.py`:** This file contains the `extract_html_content` function.
    4. **Line 5:** `def extract_html_content(text: str):` - Function definition.
    5. **Line 7:** `match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)` - This line uses a regular expression to extract HTML content. It does not include any sanitization logic. It simply finds and returns the HTML block as a string.
    6. **Line 349, `backend\routes\generate_code.py`:** `await send_message("setCode", updated_html, index)` -  The unsanitized `updated_html` (which is the output of `extract_html_content`) is sent directly to the frontend via WebSocket.
    7. **`backend\mock_llm.py`:** This file contains mock responses that simulate the output of an AI model. These mock responses are hardcoded HTML strings, for example `APPLE_MOCK_CODE`, `NYTIMES_MOCK_CODE`, `MORTGAGE_CALCULATOR_VIDEO_PROMPT_MOCK`, `GOOGLE_FORM_VIDEO_PROMPT_MOCK`, and `TALLY_FORM_VIDEO_PROMPT_MOCK`.
    8. **Vulnerability in Mock Responses:** These mock HTML responses within `backend\mock_llm.py` are not sanitized. If these mock responses are used by the application (e.g., in development or testing modes, or if a configuration error occurs), and if they contain malicious JavaScript, they can directly introduce XSS vulnerabilities. While these examples in the provided `mock_llm.py` do not contain explicit XSS payloads, they demonstrate that the system is designed to handle and display unsanitized HTML, and malicious payloads could be easily inserted into these mock responses for testing or exploitation.
    9. **Absence of Sanitization:** Reviewing the code, including `backend\mock_llm.py`, there is no evidence of any HTML sanitization or encoding being applied to the AI-generated code or mock responses either before or after extraction, or before sending it to the frontend.

- Security test case:
    1. **Prepare a malicious screenshot:** Create a screenshot (e.g., PNG or JPEG) that, when processed by the AI, is likely to generate HTML code containing a simple JavaScript XSS payload. For example, the screenshot could visually represent a button with the text  `<button onclick="alert('XSS')">Click Me</button>`. Alternatively, to directly test the XSS vulnerability without relying on AI output, you can craft a screenshot that you expect to produce one of the mock HTML responses from `backend\mock_llm.py` (if the application uses mock responses based on input type or other conditions).
    2. **Directly modify mock responses (for testing):** For a faster test, especially in a development environment, you can directly edit the mock HTML responses in `backend\mock_llm.py`. For example, modify `APPLE_MOCK_CODE` to include `<script>alert('XSS')</script>` within the HTML body. This bypasses the image processing and AI generation steps and directly injects the payload into the code generation pipeline for testing the frontend's vulnerability.
    3. **Start the application:** Ensure both the frontend and backend of the `screenshot-to-code` application are running and accessible (e.g., at `http://localhost:5173`). Configure the backend to use mock responses if necessary for direct mock response testing.
    4. **Upload the malicious screenshot:** In the frontend of the application, use the screenshot upload functionality to upload the malicious screenshot prepared in step 1. Select any stack (e.g., HTML + Tailwind). Or, if testing with modified mock responses, trigger the application flow that uses the mock response you modified in step 2 (e.g., potentially by uploading a video if that triggers the specific mock response).
    5. **Observe the generated code:** After the AI (or mock response mechanism) processes the input and generates the code, inspect the generated code in the frontend. Verify if the generated HTML code contains the JavaScript payload, e.g., `<button onclick="alert('XSS')">Click Me</button>` or `<script>alert('XSS')</script>` (if using modified mock responses).
    6. **Trigger the XSS payload:** If the generated code contains the payload, interact with the rendered output in the frontend in a way that would trigger the JavaScript execution (e.g., click the button in the example screenshot, or simply load the page if the payload is directly injected with `<script>`).
    7. **Verify XSS execution:** Confirm if the JavaScript code is executed. In the example test case, an alert box with the text "XSS" should appear in the browser. If the alert box appears, the XSS vulnerability is confirmed.
    8. **Alternative payload (to test broader XSS context):** If the `alert('XSS')` payload is too basic or filtered by some browser mechanism, try a more robust payload like injecting an image that attempts to load from a non-existent domain and logs errors, or attempts to redirect the page using `window.location`. For example, a screenshot that could generate `<img src="nonexistent.domain/xss" onerror="alert('XSS')">` or similar could be tested. Or, insert a more complex payload into the mock responses in `backend\mock_llm.py` for direct testing.
