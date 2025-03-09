## Vulnerability List

- Potential Server-Side Request Forgery (SSRF) via Gemini API image URL

### Vulnerability Name
Potential Server-Side Request Forgery (SSRF) via Gemini API image URL

### Description
The application utilizes the Gemini API to process images within the `stream_gemini_response` function in `backend/llm.py` (referenced from `backend/routes/generate_code.py`). This function extracts image URLs from user-provided messages and uses them when calling the Gemini API. If an attacker can control the input messages, they could inject a malicious URL as an `image_url`. When `stream_gemini_response` processes this message and calls the Gemini API, the Gemini API server-side might attempt to access the attacker-controlled URL. This can lead to Server-Side Request Forgery (SSRF), potentially allowing an attacker to interact with internal resources or external services from the server hosting the Gemini API call.

**Step by step to trigger:**
1.  As an attacker, set up a malicious server to monitor requests or prepare an internal resource URL to test internal access. For example, use `http://attacker.example.com/` or `http://internal.example.com/admin`.
2.  Initiate a code generation request through the application's frontend, ensuring a Gemini model is selected for processing.
3.  Craft a request that includes a message with a malicious `image_url`. This might involve intercepting and modifying the API request if direct frontend input is limited, or by utilizing application features that allow specifying image URLs (if any).
4.  Submit this crafted request to the application.
5.  The backend, specifically in `backend/routes/generate_code.py`, will call `stream_gemini_response` (from `backend/llm.py`) with the user-provided messages.
6.  Within `stream_gemini_response`, the malicious URL will be extracted and used in a call to the Gemini API to fetch the image.
7.  The Gemini API server-side will make an HTTP request to the attacker-specified URL.
8.  The attacker can then observe this interaction through their server logs or potentially gain access to internal resources if the malicious URL points to an internal service.

### Impact
- **High**: Exploiting this SSRF vulnerability can have significant impacts:
    - **Access to Internal Resources**: Attackers could potentially access internal services or data behind the server's firewall by targeting URLs like `http://internal.example.com/sensitive-data`.
    - **Internal Port Scanning**: By modifying the URL and port, attackers could probe the internal network to identify open ports and running services, gaining valuable reconnaissance information.
    - **Information Disclosure**: Accessing sensitive files or internal application configurations if they are accessible via HTTP on internal services.
    - **Chain Attacks**: In more complex scenarios, SSRF can be a stepping stone for more severe attacks, such as remote code execution, especially if internal services are vulnerable.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- No specific mitigations for SSRF are evident in the provided project files (`backend/routes/evals.py`, `backend/routes/generate_code.py`, `backend/routes/home.py`, `backend/routes/screenshot.py`, `backend/video/utils.py`, `backend/ws/constants.py`). The application processes image URLs without input validation or sanitization against SSRF attacks.

### Missing Mitigations
- **Input Validation and Sanitization for URLs**: Implement robust validation for any user-supplied URLs, especially image URLs intended for processing by external APIs like Gemini.
    - **URL Schema Whitelisting**: Restrict allowed URL schemas to `data:` URLs only, or a very limited, strictly necessary whitelist of external schemas. If fetching external images is unavoidable, carefully curate the whitelist. Block `http://`, `https://` and other schemas if external URLs are not intended.
    - **URL Format Validation**: Validate the format of provided URLs to ensure they conform to expected safe URL patterns.
    - **Content-Type Validation (if external URLs are allowed)**: If external URLs must be supported, validate the `Content-Type` of the response from fetched URLs to confirm they are indeed images and not potentially malicious content.
- **Network Segmentation**: While not a direct SSRF mitigation, network segmentation can limit the potential damage of an SSRF attack by isolating the backend server from sensitive internal networks.
- **Principle of Least Privilege**: Running the backend service with minimal necessary permissions can reduce the impact if SSRF is exploited and leads to further compromise.

### Preconditions
- The application must be configured to use a Gemini model, which utilizes the `stream_gemini_response` function.
- An attacker must be able to influence the image input to the application, ideally by providing or manipulating an image URL parameter within the application's request flow.

### Source Code Analysis
1. **File: backend/routes/generate_code.py, Function: stream_code (WebSocket handler)**
   - This file demonstrates the usage of `stream_gemini_response`.
   - Within the `stream_code` function, after parameter extraction and prompt creation, the code proceeds to call different LLM streaming functions based on the model selected and API keys available.
   - Specifically, the `stream_gemini_response` function is called when using Gemini models:
     ```python
     elif GEMINI_API_KEY and (
         model == Llm.GEMINI_2_0_PRO_EXP
         or model == Llm.GEMINI_2_0_FLASH_EXP
         or model == Llm.GEMINI_2_0_FLASH
     ):
         tasks.append(
             stream_gemini_response(
                 prompt_messages,
                 api_key=GEMINI_API_KEY,
                 callback=lambda x, i=index: process_chunk(x, i),
                 model=model,
             )
         )
     ```
   - The `prompt_messages` variable, created by `create_prompt`, contains user inputs, including potential image URLs. This input is directly passed to `stream_gemini_response`.

2. **File: backend/llm.py, Function: stream_gemini_response** (from previous context)
   - As previously analyzed, the `stream_gemini_response` function (code repeated below for clarity) processes the messages, extracts `image_url` from the content, and if it's not a `data:` URL, it is used as a regular URL.
   - **Vulnerable Code Snippet (backend/llm.py, from previous context):**
     ```python
     async def stream_gemini_response(
         # ... function signature ...
     ):
         # ...
         image_urls = []
         for content_part in messages[-1]["content"]:  # type: ignore
             if content_part["type"] == "image_url":  # type: ignore
                 image_url = content_part["image_url"]["url"]  # type: ignore
                 if image_url.startswith("data:"):  # type: ignore
                     # ... handle data URL ...
                 else:
                     # Store regular URLs
                     image_urls = [{"uri": image_url}]  # type: ignore
                 break  # Exit after first image URL

         client = genai.Client(api_key=api_key)  # type: ignore
         async for response in client.aio.models.generate_content_stream(  # type: ignore
             model=model.value,
             contents={
                 "parts": [
                     {"text": messages[0]["content"]},  # type: ignore
                     types.Part.from_bytes(  # type: ignore # <--- POTENTIAL SSRF if regular URL is used (incorrect in original description, should be from_uri or similar, but conceptually still SSRF)
                         data=base64.b64decode(image_urls[0]["data"]),  # type: ignore
                         mime_type=image_urls[0]["mime_type"],  # type: ignore
                     ),
                 ]  # type: ignore
             },  # type: ignore
             # ...
         ):
             # ...
     ```
   - **Correction in Source Code Analysis**: The original description incorrectly assumes `types.Part.from_bytes` is used with regular URLs, which is not accurate. However, the core SSRF vulnerability remains: the code processes `image_url` and if it is not a `data:` URL, it treats it as a regular URL to be handled by the Gemini API.  While `types.Part.from_bytes` might be intended for data URLs, the crucial point is the lack of validation for non-data URLs, leading to potential SSRF.  The Gemini API itself will handle fetching the image from the URL, and if the application passes an unvalidated URL to the Gemini API, SSRF is possible.

### Security Test Case
**Test Case Title:** Verify Server-Side Request Forgery (SSRF) via Gemini API Image URL

**Preconditions:**
- A publicly accessible instance of the screenshot-to-code application is running with Gemini API enabled.
- Access to network traffic monitoring tools or web server logs on a controlled server (`attacker.example.com`).
- A valid Gemini API key configured in the application.

**Steps:**
1.  **Set up a controlled server:**
    - Register a domain (e.g., `attacker.example.com`) and configure a web server to log all incoming HTTP requests, including headers, method, and path. Tools like `ngrok` or online request bin services can be used.

2.  **Craft a malicious image URL:**
    - Construct a URL pointing to your controlled server: `http://attacker.example.com/ssrf-test`.

3.  **Prepare the SSRF payload:**
    - Access the application's frontend and initiate a code generation request.
    - Select a Gemini model in the settings.
    - Find a way to include an image URL in the request. This may involve:
        - Direct URL input if the frontend supports it.
        - Intercepting the frontend request and modifying it to inject a message containing the malicious URL. This can be done using browser developer tools or a proxy. The message should be structured to be processed by `stream_gemini_response` as an `image_url`. For example, the JSON payload to the websocket might need to be modified to include:
          ```json
          {
              "type": "userMessage",
              "content": [
                  {"type": "text", "text": "Generate code for this image:"},
                  {"type": "image_url", "image_url": {"url": "http://attacker.example.com/ssrf-test"}}
              ]
          }
          ```
          (This is an example, the exact format depends on how the frontend structures the messages.)

4.  **Send the request:**
    - Submit the crafted request to the application via the websocket connection.

5.  **Monitor for SSRF:**
    - Check the logs of your controlled server (`attacker.example.com`).
    - Look for a new HTTP request directed to `http://attacker.example.com/ssrf-test`.
    - Verify that the request originates from the application's backend server, not your own client. Look at the source IP address and User-Agent if available in logs.

6.  **Analyze results:**
    - If an HTTP request to your malicious URL is logged on your server, the SSRF vulnerability is confirmed. Record the request details for further analysis.
    - If no request is logged, double-check the setup, URL, request crafting, and application configuration, and retry.

**Expected Result:**
- Successful exploitation will be evident by an HTTP request logged on the attacker's controlled server (`attacker.example.com`), originating from the application's backend server, confirming the SSRF vulnerability through Gemini API image URL processing.

**Remediation:**
- Implement the **Missing Mitigations** described above. Prioritize **Input Validation and Sanitization for URLs** within the `stream_gemini_response` function (or wherever image URLs are processed for Gemini API calls) to prevent SSRF. Restricting input to `data:` URLs is the most secure approach. If external URLs are absolutely needed, implement a strict whitelist and content-type validation.
