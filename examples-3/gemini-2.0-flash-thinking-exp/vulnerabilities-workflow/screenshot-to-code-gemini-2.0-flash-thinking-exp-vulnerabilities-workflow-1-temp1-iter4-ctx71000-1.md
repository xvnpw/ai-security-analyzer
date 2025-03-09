* Vulnerability Name: Cross-Site Scripting (XSS) via LLM Generated Code

* Description:
    1. An attacker sends a request to the `/generate-code` websocket endpoint, providing an image or video to be converted into code.
    2. The backend application uses an LLM (like GPT-4 Vision or Claude) to generate HTML, CSS, and JavaScript code based on the input.
    3. The LLM, in some cases, might generate code that includes malicious JavaScript. This could happen if the training data of the LLM contained examples of XSS vulnerabilities, or if the prompt used to query the LLM is manipulated in some way (though in this project prompts are hardcoded).
    4. The backend processes the LLM's response, extracts the HTML code (using regex which might fail in certain cases or be bypassed) using `extract_html_content` function in `backend\codegen\utils.py`, and sends this generated code directly to the frontend through the websocket.
    5. The frontend then renders this generated HTML in the user's browser.
    6. If the generated HTML contains malicious JavaScript, it will be executed in the user's browser in the context of the application's origin, potentially allowing the attacker to perform actions like stealing cookies, redirecting the user, or defacing the website.

* Impact:
    - Account Takeover: An attacker could potentially steal session cookies or other sensitive information, leading to account takeover.
    - Data Theft: Malicious scripts could be used to extract data from the application or the user's browser and send it to an attacker-controlled server.
    - Website Defacement: The attacker could alter the content of the webpage, redirect users to malicious sites, or inject phishing forms.
    - Malware Distribution: Injected scripts could potentially be used to distribute malware to users visiting the application.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None: Based on the provided code, there are no explicit sanitization or content security policy mechanisms implemented to prevent XSS. The `extract_html_content` function in `backend\codegen\utils.py` attempts to extract HTML using regex, but this is not a security mitigation and can be bypassed. It is intended for code extraction, not sanitization.

* Missing Mitigations:
    - HTML Sanitization: Implement robust HTML sanitization on the backend before sending the generated code to the frontend. Libraries like DOMPurify (for JavaScript frontend) or bleach (for Python backend) can be used to remove or neutralize potentially harmful HTML, CSS, and JavaScript code.
    - Content Security Policy (CSP): Implement a strict Content Security Policy to control the resources that the browser is allowed to load and execute. This can significantly reduce the impact of XSS attacks by preventing the execution of inline scripts and restricting the sources from which scripts can be loaded.
    - Input Validation and Output Encoding: While the primary vulnerability here is in the LLM generated output, general input validation on parameters sent to `/generate-code` and output encoding of any other dynamic content in the frontend can help in defense-in-depth.

* Preconditions:
    - The application must be publicly accessible and running the backend service that handles `/generate-code` requests via websocket.
    - A user must interact with the application by providing an image or video and triggering the code generation process.

* Source Code Analysis:
    1. **Entry Point:** The vulnerability is triggered via the `/generate-code` websocket endpoint defined in `backend\routes\generate_code.py`.
    2. **Code Generation:** The `stream_code` function in `backend\routes\generate_code.py` handles websocket connections. It extracts parameters, creates prompts, and uses functions like `stream_openai_response` or `stream_claude_response` from `backend\llm.py` to interact with LLMs and get code.
    3. **HTML Extraction:** The response from the LLM (which is expected to contain HTML code) is processed by `extract_html_content` function in `backend\codegen\utils.py`. This function uses a regular expression `r"(<html.*?>.*?</html>)"` to extract content within `<html>` tags.
    ```python
    # backend\codegen\utils.py
    import re

    def extract_html_content(text: str):
        # Use regex to find content within <html> tags and include the tags themselves
        match = re.search(r"(<html.*?>.*?</html>)", text, re.DOTALL)
        if match:
            return match.group(1)
        else:
            # Otherwise, we just send the previous HTML over
            print(
                "[HTML Extraction] No <html> tags found in the generated content: " + text
            )
            return text
    ```
    As seen in the code, if the regex fails to find `<html>` tags, the function simply returns the original text without any sanitization. This means if the LLM response is crafted to not include `<html>` tags, but still contains malicious JavaScript, it will be passed through. Even if the regex succeeds, the extracted HTML is not sanitized.
    4. **Image Generation (Optional but Relevant):** The generated code is further processed by `generate_images` function in `backend\image_generation\core.py` to replace placeholder image URLs. This step itself doesn't introduce XSS, but it's part of the code generation pipeline.
    5. **Response to Frontend:** The final generated `code` (HTML) is sent back to the frontend via websocket using `setCode` message type in `backend\routes\generate_code.py`.
    ```python
    # backend\routes\generate_code.py
    @router.websocket("/generate-code")
    async def stream_code(websocket: WebSocket):
        # ...
        for index, updated_html in enumerate(updated_completions):
            await send_message("setCode", updated_html, index) # Vulnerable line: sending unsanitized code
        # ...
    ```
    6. **Frontend Rendering (Assumption):** While frontend code is not provided, it is assumed that the frontend receives this `code` from the backend and renders it directly into the DOM, likely within an `iframe` or a `div` using `innerHTML` or similar methods. Without sanitization on the frontend either, this will execute any JavaScript present in the `code`.

* Security Test Case:
    1. **Prepare a Malicious Payload Image:** Create or find an image that, when processed by the screenshot-to-code application, is likely to cause the LLM to generate HTML code containing malicious JavaScript. A simple approach is to create a screenshot of a webpage with a visible XSS payload, or craft a specific image designed to mislead the LLM in generating a specific vulnerable pattern.
    2. **Set up the Environment:** Ensure you have the screenshot-to-code application running locally or access to a public instance.
    3. **Establish WebSocket Connection:** Connect to the `/generate-code` websocket endpoint. You can use a websocket client or a simple JavaScript in browser console.
    4. **Send Malicious Request:** Send a JSON message to the websocket with the following parameters:
        ```json
        {
          "inputMode": "image",
          "generatedCodeConfig": "html_tailwind",
          "image": "<base64_encoded_malicious_image>",
          "promptParams": "{}",
          "model": "gpt-4-vision-preview",
          "generationType": "create"
        }
        ```
        Replace `<base64_encoded_malicious_image>` with actual base64 encoded malicious image.
    5. **Analyze WebSocket Messages:** Monitor the websocket messages received from the backend. Look for messages with `type: "setCode"`. The `value` field in these messages contains the generated HTML. Check if the generated HTML includes malicious JavaScript. A simple payload to test is an `<img>` tag with `onerror` attribute or a `<script>` tag executing `alert()`. For instance, look for code similar to:
        ```html
        <img src="invalid-url" onerror="alert('XSS Vulnerability!')">
        ```
        or
        ```html
        <script>alert('XSS Vulnerability!')</script>
        ```
    6. **Render the Generated Code:** If you have access to the frontend code, trigger the frontend to display the generated code received via websocket. Alternatively, manually render the generated HTML code in a browser.
    7. **Verify XSS Execution:** Check if the JavaScript code within the generated HTML is executed in the browser. If you used `alert('XSS Vulnerability!')`, an alert box should pop up in the browser, confirming the XSS vulnerability. If you used a more sophisticated payload (e.g., cookie stealing), verify if that action was successfully performed.

This test case demonstrates how an attacker can potentially trigger the LLM to generate malicious code, which is then executed in the user's browser, confirming the XSS vulnerability due to the lack of output sanitization.
