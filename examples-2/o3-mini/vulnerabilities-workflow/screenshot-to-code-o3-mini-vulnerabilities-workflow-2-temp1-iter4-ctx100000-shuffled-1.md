- **Vulnerability Name:** Malicious Crafted Image Injection Leading to Remote Code Execution
  - **Description:**
    An attacker can supply a specially crafted image (embedded as a data URL) to the system via endpoints such as the screenshot API or the WebSocket “/generate‐code” endpoint. In the process, the function `process_image()` (in `backend/image_processing/utils.py`) decodes the base64 image and hands it off to Pillow (*via* `Image.open`). No content sanitization or strict verification is performed on the image’s metadata or overall structure. An attacker who designs an image to exploit vulnerabilities in the image library (or abuses metadata) may cause the downstream AI prompt to be manipulated or even trigger remote code execution when the image is processed and later embedded into generated code.
  - **Impact:**
    Exploitation could allow an attacker to inject malicious code (e.g. JavaScript that executes in the browser) or cause remote code execution on the backend. This in turn might lead to compromise of client devices (if the generated HTML is rendered without further sanitization) or abuse of backend resources.
  - **Vulnerability Rank:** Critical
  - **Currently Implemented Mitigations:**
    • The code enforces basic file size and dimension checks (using constants such as `CLAUDE_IMAGE_MAX_SIZE` and `CLAUDE_MAX_IMAGE_DIMENSION`).
    • However, no verification is performed on the actual content or metadata of the image.
  - **Missing Mitigations:**
    • Introduce strict validation and sanitization for all image inputs (e.g. verifying MIME types, enforcing safe image header formats, and processing images in a sandboxed environment).
    • Ensure that the image library (Pillow) is up–to–date with any patches for known vulnerabilities.
  - **Preconditions:**
    • The attacker must be able to supply an image (as a base64–encoded data URL) via the `/api/screenshot` endpoint or through the client–side code generation endpoint.
    • The target image library (Pillow) must have exploitable weaknesses or the lack of sanitization must permit embedding unexpected payloads.
  - **Source Code Analysis:**
    • In `backend/image_processing/utils.py`, the function `process_image` obtains the image bytes from the user–supplied data URL, then calls `Image.open(io.BytesIO(image_bytes))` without verifying that the payload contains only a valid image.
    • Thereafter the image is resized and saved as JPEG without recoding or sanitizing metadata.
    • Moreover, in `backend/prompts/__init__.py`, the unsanitized `image_data_url` is directly inserted into the prompt messages destined for the LLM.
  - **Security Test Case:**
    1. Craft an image file that embeds a malicious payload (for example, a script injected into EXIF metadata or using a malformed structure known to trigger undesired behavior in Pillow).
    2. Encode this file into a base64 data URL and submit it via a POST request to `/api/screenshot` or through the WebSocket endpoint used for code generation.
    3. Observe the backend logs and the generated HTML code output for any injected JavaScript or anomalies.
    4. In a safe test environment, render the generated HTML and check if the malicious payload executes (e.g. trigger an alert or log a message).

- **Vulnerability Name:** Prompt Injection via Unsanitized Input in the Code Generation Endpoint
  - **Description:**
    The WebSocket endpoint `/generate-code` (in `backend/routes/generate_code.py`) accepts client–supplied parameters (e.g. the `image` and `resultImage` fields) that are then used to construct the AI prompt via the `assemble_prompt()` function inside `backend/prompts/__init__.py`. While some fields (such as `generatedCodeConfig` and `inputMode`) are validated against expected values and whitelists, the actual image data (a base64 data URL) is not further sanitized or encoded. An attacker may craft a malicious “image” parameter containing extra prompt instructions or hidden HTML/JavaScript payloads designed to alter the behavior of the LLM and cause it to generate harmful code.
  - **Impact:**
    Malicious prompt injection may lead the AI to generate code that includes unwanted script tags, malicious payloads, or other forms of code that could result in cross–site scripting (XSS) or even remote code execution when the generated output is rendered by a client.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    • Basic type and value checks (for example, ensuring the `stack` and `inputMode` values fall within allowed literals) are performed.
    • However, fields such as `image` and `resultImage` are taken verbatim.
  - **Missing Mitigations:**
    • Implement strict validation and sanitization specifically for fields containing image data (confirming that data URLs follow an expected and safe format and that no extra payload is appended).
    • Consider encoding or filtering out any embedded control characters or HTML elements that might alter prompt behavior.
  - **Preconditions:**
    • The attacker must be able to supply a crafted WebSocket message to the `/generate-code` endpoint with manipulated values for the `image` (or `resultImage`) parameter.
  - **Source Code Analysis:**
    • In `backend/prompts/__init__.py`, the `assemble_prompt()` function builds the prompt by inserting the user–supplied `image` data URL directly into a JSON message that is sent to the LLM.
    • No output encoding or sanitization is applied to the incoming image data URL, leaving the prompt vulnerable to additional injected instructions.
  - **Security Test Case:**
    1. Connect to the `/generate-code` WebSocket endpoint using a tool such as a WebSocket client.
    2. Craft and send a JSON message where the `image` parameter is set to a data URL that, in addition to a valid image header, appends malicious content (for example, an encoded `<script>alert('XSS')</script>` string inside the payload).
    3. Observe the full prompt assembled (if accessible) on the backend logs or intercept the response stream to see if the injected content appears.
    4. Verify that the final AI–generated output includes the malicious script.
    5. Open the generated HTML in a browser (in a safe test environment) to confirm if the script executes.
