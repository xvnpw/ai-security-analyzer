### Vulnerability List

#### 1. **Malicious Code Injection via Image-Driven Prompt Manipulation**
**Description**:
Attackers can craft images containing hidden or misleading visual cues (e.g., steganography, invisible text layers, or deceptive UI elements) designed to trick the AI into generating malicious code snippets. The AI may interpret these cues as valid instructions, producing code with hidden exploits such as cross-site scripting (XSS), shell commands, or framework-specific vulnerabilities (e.g., React injection, CSS injections).

**How to Trigger**:
1. An attacker uploads a carefully crafted image to the `/generate-code` endpoint.
2. The image includes:
   - Hidden text layers containing `<script>` tags or shell commands.
   - Visual elements mimicking UI components with embedded malicious attributes (e.g., an "harmless" button with an `onclick` handler that executes JavaScript).
3. The backend’s `assemble_prompt` function processes the image without validation, and the AI generates code incorporating the malicious content.

**Impact**:
- Generated code could execute arbitrary JavaScript (XSS) when rendered in a browser.
- Server-side code injection if the AI outputs malicious backend logic (e.g., Node.js/Python commands).
- Bypassing client-side sanitization if users directly copy the generated code into their projects.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**:
- The AI models (e.g., GPT-4, Claude) have built-in content filters, but these can be bypassed with targeted prompts.
- The `extract_html_content` function strips non-HTML content, but malicious code may still reside within valid HTML tags.

**Missing Mitigations**:
- Input image validation to detect and block steganography or hidden text.
- Explicit AI prompts instructing the system to reject/flag suspicious code patterns.
- Output sanitization (e.g., removing `eval()`, `exec()`, or event handlers like `onclick`).

**Preconditions**:
- User has API access to the `/generate-code` endpoint.

**Source Code Analysis**:
- **`backend/routes/generate_code.py`**:
  - The `create_prompt` function constructs the LLM prompt using raw image data from `params["image"]` (line 115).
  - No validation/sanitization of the image content occurs before passing it to the AI.
- **`prompts/__init__.py`**:
  - The `assemble_prompt` function (line 38) directly embeds the image URL into the LLM message without analyzing its content.
  - The system prompts (e.g., `HTML_TAILWIND_SYSTEM_PROMPT`) lack explicit security requirements (e.g., "avoid event handlers").

**Security Test Case**:
1. Create an image with a hidden `script` tag (e.g., using steganography tools like `steghide`).
2. Upload the image via the `/generate-code` endpoint with `stack=html_tailwind`.
3. Verify the response includes the injected `<script>alert('XSS')</script>`.

---

#### 2. **Insecure LLM Prompt Structure Enabling Code Exploits**
**Description**:
The system prompts provided to the AI (`prompts/screenshot_system_prompts.py`) do not explicitly instruct the AI to validate user inputs or avoid generating unsafe patterns. Attackers can exploit this by submitting images that trigger the AI to output vulnerable code (e.g., unescaped user input in templates, lack of sanitization functions).

**How to Trigger**:
1. Upload an image mimicking a "login form" with a "username" field.
2. The AI generates HTML without input validation, producing code like `dangerous.innerHTML = userInput`.

**Impact**:
- Code injection vulnerabilities in the generated code, leading to XSS, SQLi, or command injection when implemented.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
- None. The prompts focus on accuracy, not security practices.

**Missing Mitigations**:
- Adding explicit security guidelines to prompts (e.g., "always sanitize inputs, avoid eval(), and use secure frameworks").

**Preconditions**:
- No mitigation for unsafe code patterns in AI prompts.

**Source Code Analysis**:
- **`prompts/screenshot_system_prompts.py`**:
  - The `HTML_TAILWIND_SYSTEM_PROMPT` (line 12) lacks instructions to enforce security practices.
  - The `SVG_SYSTEM_PROMPT` (line 159) similarly omits security requirements.

**Security Test Case**:
1. Submit an image of a "dynamic content display" component.
2. Check if the AI outputs `innerHTML` usage without sanitization (e.g., `element.innerHTML = user_input`).

---
