### Client-Side Vulnerability Injection via AI-Generated Code (XSS)

*   **Vulnerability Name:** Client-Side Vulnerability Injection via AI-Generated Code (XSS)
*   **Description:**
    An attacker can exploit the screenshot-to-code application to introduce client-side vulnerabilities, specifically Cross-Site Scripting (XSS), through AI-generated code. This vulnerability arises because the AI model, when converting UI design screenshots into frontend code (HTML, React, Vue, etc.), may unintentionally generate code containing security flaws. This can occur due to misinterpretation of the design, prompt injection, or the inherent limitations of AI in producing secure code without explicit security considerations in its training and prompting.

    There are two main attack vectors:

    1.  **Indirect Injection via Social Engineering:** An attacker can operate a modified or attacker-controlled instance of the application, or potentially use a publicly hosted version. They can craft a UI design screenshot that subtly guides the AI to generate vulnerable code or rely on the general likelihood of AI unintentionally creating insecure code. The attacker then socially engineers a victim (e.g., a developer) into using this seemingly legitimate tool to generate code from the prepared screenshot. The victim, trusting the tool or lacking security review, integrates the AI-generated code into their web project, inadvertently introducing an XSS vulnerability.

    2.  **Reflected XSS via Crafted Screenshot:** An attacker crafts a malicious screenshot that includes visual elements or text designed to trick the AI model into generating HTML code containing malicious JavaScript. This might involve embedding text resembling HTML attributes like `onerror` or event handlers like `onclick`, or visually representing UI components that the AI might interpret as requiring JavaScript functionality and generate code that reflects the malicious input back to the user in the application's frontend.

    In both scenarios, if the generated code containing the XSS vulnerability is displayed by the application or integrated into a victim's web application, and a user interacts with this vulnerable code, malicious JavaScript can be executed in the user's browser.

    **Step-by-step trigger:**

    **Scenario 1: Indirect Injection via Social Engineering:**
    1.  The attacker sets up an instance of the `screenshot-to-code` application (locally, a modified version, or potentially using a compromised public instance).
    2.  The attacker crafts or selects a UI design screenshot that may subtly encourage the AI to generate vulnerable code, or simply relies on the general risk of AI-generated code being insecure.
    3.  The attacker socially engineers a victim to use their instance of the `screenshot-to-code` application, promising benefits like speed or AI-powered code generation.
    4.  The victim uploads the screenshot and selects a frontend framework.
    5.  The application uses an AI model to generate code. The generated code unknowingly contains an XSS vulnerability.
    6.  The victim, without security review, integrates the AI-generated code into their web application.
    7.  Users interacting with the victim's application trigger the XSS vulnerability, leading to malicious script execution in their browsers.

    **Scenario 2: Reflected XSS via Crafted Screenshot:**
    1.  The attacker crafts a malicious screenshot containing visual elements or text intended to trick the AI into generating malicious JavaScript code (e.g., embedding `<img src="invalid-image" onerror="alert('XSS')">` as text in the screenshot).
    2.  A user uploads this crafted screenshot to the application for code generation.
    3.  The backend AI processes the screenshot and generates HTML/JavaScript code that includes the attacker's malicious JavaScript.
    4.  The backend sends the AI-generated code back to the frontend.
    5.  The frontend displays the AI-generated code to the user without sufficient sanitization.
    6.  When the user's browser renders the page containing the unsanitized AI-generated code, the malicious JavaScript is executed within the user's browser session in the application itself.

*   **Impact:**
    The impact of this vulnerability is high, potentially leading to:
    *   **Account Hijacking:** Stealing session cookies to gain unauthorized access to user accounts.
    *   **Data Theft:** Exfiltrating sensitive user or application data to attacker-controlled servers.
    *   **Website Defacement:** Modifying webpage content, damaging reputation.
    *   **Redirection to Malicious Sites:** Redirecting users to phishing or malware sites.
    *   **Malware Distribution:** Spreading malware to users of affected applications.
    *   **Phishing Attacks:** Displaying fake login forms to steal credentials.
    *   **Client-Side Denial of Service (DoS):** Injecting scripts that consume excessive browser resources.

*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    None. The project currently lacks any specific security measures to prevent AI models from generating vulnerable code or to sanitize the generated output before displaying it or allowing users to integrate it into their projects. Analysis of files like `backend/routes/generate_code.py`, `backend/routes/evals.py`, and other backend and frontend code does not reveal any output sanitization or security focused prompt engineering. The application's focus is primarily on functionality and visual accuracy of the generated code.
*   **Missing Mitigations:**
    *   **Output Code Sanitization:** Implement robust HTML sanitization of the AI-generated code *in the frontend* before displaying it to the user. Utilize a library like DOMPurify to remove or neutralize potentially malicious JavaScript, including `<script>` tags, event handlers (e.g., `onload`, `onerror`, `onclick`), and JavaScript URLs. This is crucial for preventing reflected XSS within the application itself and mitigating the risk of users copying and pasting vulnerable code.
    *   **Security-Focused Prompt Engineering:** Enhance prompts in `backend/prompts/` to guide AI models toward generating secure code. Include explicit instructions in the prompts emphasizing security best practices and avoidance of common vulnerabilities like XSS.
    *   **Automated Security Scanning of Output Code:** Integrate static analysis tools or regular expression-based patterns into the code generation pipeline in `backend/routes/generate_code.py` to automatically scan the AI-generated code for potential client-side vulnerabilities before presenting it to the user. This could catch easily detectable XSS patterns.
    *   **Content Security Policy (CSP):** Implement a Content Security Policy (CSP) to add a layer of defense. Configure CSP headers to restrict resource loading sources and disable inline JavaScript execution, reducing the impact of XSS.
    *   **User Education and Warnings:** Display prominent disclaimers and warnings within the application's UI and documentation. Emphasize that AI-generated code is not inherently secure and requires thorough security review and testing by experts before deployment. Clearly state that the application does not guarantee secure code generation and users are responsible for the security of the code they use.

*   **Preconditions:**
    1.  **Accessible Application Instance:** The attacker can access or control an instance of the `screenshot-to-code` application (attacker-controlled or public).
    2.  **User Interaction:** A user (potentially socially engineered) interacts with the application by uploading a screenshot for code generation. For reflected XSS, this is a direct user within the application. For indirect injection, this is a developer who will use the generated code in their project.
    3.  **Vulnerable AI Output:** The AI model, when processing the screenshot, generates code containing a client-side vulnerability (XSS). This is probabilistic but a significant risk given current AI code generation capabilities and lack of explicit security focus.
    4.  **Unsanitized Code Display (Reflected XSS) or Integration (Indirect Injection):** For reflected XSS, the application displays the unsanitized AI-generated code. For indirect injection, the victim integrates the unsanitized AI-generated code into their application.

*   **Source Code Analysis:**
    The vulnerability is not due to a direct code defect in the application's codebase, but rather emerges from the nature of AI-generated code and the application's lack of security measures around this generated output. Key areas relevant to the vulnerability are:

    *   **`backend/llm.py` and `backend/prompts/`:** These files handle AI model interaction and define prompts. Prompts in `backend/prompts/` currently prioritize visual and functional accuracy, lacking explicit security instructions. This can lead AI models to generate insecure code.
    *   **`backend/routes/generate_code.py` and Frontend Code (Not Provided):** The `stream_code` websocket endpoint in `backend/routes/generate_code.py` streams AI-generated code chunks to the frontend and sends the complete code. Critically, there is no sanitization of this AI-generated code in the backend before sending it to the frontend, nor is there evidence of frontend sanitization. The code is directly passed from the AI to the user's browser via the application.  `codegen.utils.extract_html_content` extracts HTML but does not sanitize it.
    *   **`backend/routes/evals.py`:** Evaluation routes focus on visual and functional correctness, not security. Security testing is not integrated into the evaluation process.

    **Visualization:**

    ```
    [Attacker/User] --> [Screenshot (Potentially Crafted)]
        ^
        | Upload
        v
    [Frontend Application] --> [Backend API] --> [AI Model (backend/llm.py)]
                                                    ^
                                                    | AI Generates Code (Potentially Vulnerable)
                                                    | Prompts (backend/prompts/) Lack Security Focus
                                                    v
                                        [Backend API (backend/routes/generate_code.py)] --> [Frontend Application]
                                                            ^ Unsanitized AI-Generated Code
                                                            | Displayed/Integrated
                                                            v
                                        [User Browser Executes Malicious Script (XSS)]
    ```

*   **Security Test Case:**

    **Scenario: Reflected XSS in Application Frontend**

    1.  **Setup:** Access the publicly available instance of the `screenshot-to-code` application or run a local instance. Open browser developer console (F12).
    2.  **Craft Malicious Screenshot:** Create a screenshot (e.g., using an image editor). Embed the following HTML snippet as text within the image:  `<img src="invalid-image" onerror="alert('Reflected XSS Detected!')">`  Save as `xss_screenshot.png`.
    3.  **Upload and Generate Code:** In the application, upload `xss_screenshot.png`. Select any stack (e.g., "HTML + Tailwind"). Click "Generate Code".
    4.  **Observe for Alert:** Monitor the browser. If an alert box with "Reflected XSS Detected!" appears, XSS is confirmed.
    5.  **Inspect Generated Code (If No Alert):** If no alert, manually inspect the generated code in the application's editor/preview. Look for the malicious `<img>` tag or similar JavaScript constructs that the AI might have generated based on the screenshot text.
    6.  **Expected Result:**
        *   **Vulnerable:** Alert box appears, or malicious `<img>` tag (or equivalent JavaScript) is present and would execute JavaScript when rendered. This confirms Reflected XSS vulnerability due to unsanitized display of AI-generated malicious code.
        *   **Not Vulnerable (Potentially Mitigated):** No alert, and malicious code is either absent or present but neutralized (no JavaScript execution), suggesting potential mitigation. However, further code review is needed to confirm proper sanitization.

    **Scenario: Indirect Injection leading to XSS in External Application**

    1.  **Setup:** Access the `screenshot-to-code` application.
    2.  **Craft Input Screenshot:** Prepare a screenshot of a simple form with an input field (e.g., "Enter your name").
    3.  **Generate Code:** Upload the screenshot, select "HTML + Tailwind", and generate code.
    4.  **Review Generated Code:** Inspect the generated Javascript, looking for patterns where input field values are directly inserted into the DOM without encoding (e.g., `innerHTML`).
    5.  **Create Test HTML File:** Create `xss_test.html`. Copy the AI-generated HTML into it.
    6.  **Test for XSS:** Open `xss_test.html` in a browser. In the "Enter your name" field, enter `<script>alert('Indirect XSS!')</script>`. Submit the form.
    7.  **Verify XSS:** If an alert box with "Indirect XSS!" appears, it confirms that the AI-generated code contains an XSS vulnerability that can be exploited when integrated into another application.

This combined security test case demonstrates both the reflected XSS within the application due to unsanitized display, and the potential for indirect injection of XSS vulnerabilities into external applications through the use of AI-generated code.
