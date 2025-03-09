- Vulnerability Name: Cross-Site Scripting (XSS) in AI-Generated Code
- Description:
    1. An attacker crafts a malicious screenshot or design mockup. This image is designed to trick the AI model into generating code containing Javascript or HTML elements that can execute scripts. For example, the screenshot could visually represent a button with text that includes an XSS payload, such as `<img src=x onerror=alert('XSS')>`.
    2. The attacker uses the screenshot-to-code application and uploads this malicious screenshot.
    3. The attacker selects any supported stack (e.g., HTML + Tailwind, React + Tailwind) and any AI model available in the application.
    4. The backend processes the screenshot using the selected AI model to generate code. Due to the nature of Large Language Models and the project's objective to faithfully reproduce the visual elements of the screenshot in code, the AI model is likely to generate code that includes the malicious payload from the screenshot without sanitization. For example, the generated HTML might contain `<button class="..."> <img src=x onerror=alert('XSS')> </button>`.
    5. A user, intending to use the generated code, copies or downloads the code provided by the application.
    6. Unaware of the embedded XSS vulnerability, the user deploys this AI-generated code directly to a web server or application without performing any security review or sanitization.
    7. When another user accesses the deployed web page, their browser executes the Javascript code injected through the malicious screenshot (e.g., `<img src=x onerror=alert('XSS')>`), resulting in an XSS attack. This could lead to various malicious activities, such as displaying an alert box, redirecting the user to a malicious site, stealing cookies or session tokens, or performing actions on behalf of the user.
- Impact:
    - Account takeover: Attackers can potentially steal session cookies or authentication tokens, leading to account hijacking.
    - Data theft: Malicious scripts can be used to extract sensitive information from the user's browser or the web page.
    - Malware distribution: Attackers could redirect users to websites hosting malware or trick them into downloading malicious files.
    - Website defacement: The content of the website can be altered, leading to reputational damage.
    - Redirection to malicious websites: Users can be silently redirected to attacker-controlled websites, potentially for phishing or malware distribution.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project, in its current form, does not implement any input sanitization or output encoding to prevent XSS vulnerabilities in the generated code. It relies entirely on the end-user to review and sanitize the generated code before deployment.
- Missing Mitigations:
    - Input sanitization: Implement sanitization of the input screenshot or design mockup to detect and neutralize potential malicious code injection attempts. However, due to the image-based nature of the input, effective sanitization might be complex and could potentially degrade the functionality of the tool.
    - Output sanitization/encoding: Apply robust sanitization or encoding to the AI-generated code before presenting it to the user. This should focus on preventing the execution of arbitrary Javascript or HTML, for example by escaping HTML entities for user-controlled parts of the generated code. A Content Security Policy (CSP) could also be considered to limit the capabilities of the generated code.
    - User education and warnings: Display clear warnings to users about the inherent security risks of deploying AI-generated code directly without thorough security review and sanitization. Emphasize the importance of understanding and modifying the generated code before deploying it in a production environment.
- Preconditions:
    - An attacker must be able to create a malicious screenshot or design mockup that can trick the AI model.
    - The AI model must successfully generate code that includes the malicious payload from the screenshot.
    - A user must utilize the screenshot-to-code application to process the malicious screenshot and generate code.
    - The user must then deploy the generated code to a web environment accessible to other users, without performing adequate security review or sanitization of the code.
- Source Code Analysis:
    - The source code files provided, particularly within the `backend` directory, are responsible for processing the user-uploaded screenshot and generating code using AI models.
    - Files such as `backend\evals\core.py`, `backend\evals\runner.py`, `backend\image_processing\utils.py`, `backend\llm.py`, and `backend\prompts\__init__.py` are involved in the process of receiving the image, constructing prompts, and calling the AI models (OpenAI, Anthropic, Gemini).
    - The core logic resides in `backend\evals\core.py`, where the `generate_code_for_image` function orchestrates the process. This function calls `assemble_prompt` (defined in `backend\prompts\__init__.py`) to create prompts for the AI model based on the user's input image and selected technology stack.
    - The `assemble_prompt` function uses system prompts defined in `backend\prompts\screenshot_system_prompts.py` and `backend\prompts\imported_code_prompts.py`. These prompts instruct the AI to generate visually accurate and functional code, but they do not include any instructions or constraints related to security or output sanitization.
    - The AI model call is performed in `generate_code_core` within `backend\evals\core.py`, utilizing functions like `stream_openai_response` or `stream_claude_response` from `backend\llm.py`.
    - The AI-generated code, returned as a string, is then used in evaluation processes (as seen in `backend\evals`) or transmitted back to the frontend via WebSocket (in `backend\routes\generate_code.py`).
    - Critically, there is no code in the provided project files that sanitizes or encodes either the input screenshot content before it's processed by the AI, or the AI-generated code before it is returned to the user. The system design assumes that the AI will generate safe code, or that the user will manually review and sanitize the code. This assumption is flawed, as AI models are known to generate code that can contain vulnerabilities, especially when instructed to directly translate visual content into code.
    - The lack of output sanitization in `backend\codegen\utils.py` and throughout the code generation pipeline confirms that the application is vulnerable to XSS if a malicious screenshot is used as input.
- Security Test Case:
    1. Prepare Malicious Screenshot: Create a PNG screenshot file (e.g., `xss_screenshot.png`). This screenshot should visually represent a simple HTML button.  Within the visual text of the button, include an XSS payload. For example, use an image tag with an `onerror` attribute: `<button>Click Me <img src=x onerror=alert('XSS Vulnerability!')> </button>`. Ensure the screenshot visually renders this text as part of the button.
    2. Access the screenshot-to-code Application: Open the screenshot-to-code frontend application in a web browser (typically `http://localhost:5173` if running locally).
    3. Upload Malicious Screenshot: Use the application's UI to upload the `xss_screenshot.png` file.
    4. Select Stack and Model: Choose any available stack (e.g., "HTML + Tailwind") and any available AI model from the application's settings.
    5. Generate Code: Initiate the code generation process by clicking the appropriate button in the application (e.g., "Generate Code").
    6. Review Generated Code: Once the AI has processed the screenshot and generated the code, examine the output. You should observe that the generated HTML code includes the XSS payload that was visually represented in the screenshot. For instance, the generated code is likely to contain a button element that includes the `<img src=x onerror=alert('XSS Vulnerability!')>` tag directly within its HTML structure.
    7. Deploy and Test Generated Code: Copy the generated HTML code. Create a new HTML file (e.g., `test_xss.html`) and paste the generated code into it. Serve this `test_xss.html` file using any local web server (e.g., Python's `http.server`, or simply open the HTML file directly in a browser for testing purposes).
    8. Trigger XSS: Open `test_xss.html` in a web browser. When the browser renders the page and attempts to process the HTML, the `onerror` event within the `<img>` tag will be triggered because the `src` attribute is set to 'x' (an invalid image source). This will execute the Javascript code `alert('XSS Vulnerability!')`, causing an alert box to pop up in the browser.
    9. Observe XSS Confirmation: The appearance of the alert box confirms that the XSS vulnerability is present in the AI-generated code and is successfully exploitable. This demonstrates that a malicious actor can indeed inject XSS payloads into web applications by using crafted screenshots processed by the screenshot-to-code tool, if the generated code is deployed without sanitization.
