# Threat Modeling Analysis for screenshot-to-code Using Attack Trees

## 1. Understand the Project

### Overview
**Project Name**: [screenshot-to-code](https://github.com/abi/screenshot-to-code)
**Purpose**: Converts screenshots into code (HTML/Tailwind, React, etc.) using AI models like GPT-4 Vision and DALL-E 3.
**Key Features**:
- Image upload and processing.
- AI-generated code output.
- Real-time preview of generated code.
**Technologies**: Python (Flask/Streamlit), React, OpenAI API, Vercel, Bun.

### Key Components
1. **Image Processing**: Handles user-uploaded images.
2. **AI Integration**: Communicates with OpenAI APIs for code generation.
3. **Code Rendering**: Displays and executes generated code in a preview pane.
4. **Dependencies**: `openai`, `python-dotenv`, `pillow`, `requests`, `torch` (for local model support).

---

## 2. Define the Root Goal of the Attack Tree
**Attacker's Ultimate Objective**:
Compromise systems using `screenshot-to-code` by exploiting vulnerabilities in its image processing, AI-generated code, or dependencies.

---

## 3. Identify High-Level Attack Paths (Sub-Goals)
1. **Exploit Image Processing to Achieve RCE**
2. **Inject Malicious Code via AI-Generated Output**
3. **Compromise AI Model Integrity to Manipulate Outputs**
4. **Steal or Abuse OpenAI API Keys**

---

## 4. Expand Each Attack Path with Detailed Steps

### 1. Exploit Image Processing to Achieve RCE
- **1.1 Exploit Vulnerable Image Parsing Library**
  - 1.1.1 Upload a crafted image triggering a buffer overflow in `Pillow` (CVE-2023-50447).
  - 1.1.2 Use malicious EXIF metadata to inject shell commands during processing.
- **1.2 Abuse File Upload Logic**
  - 1.2.1 Upload a disguised script (e.g., `malicious.png.exe`) to execute on the server.
  - 1.2.2 Exploit path traversal in temporary image storage (e.g., `../../etc/passwd`).

### 2. Inject Malicious Code via AI-Generated Output
- **2.1 Bypass Output Sanitization**
  - 2.1.1 Craft an image that tricks the AI into generating `<script>alert(1)</script>` in HTML output.
  - 2.1.2 Generate Python code with `os.system("rm -rf /")` if the app executes previews.
- **2.2 Exploit Insecure Preview Rendering**
  - 2.2.1 Use a reflected XSS payload in generated code that steals user sessions.

### 3. Compromise AI Model Integrity
- **3.1 Adversarial Attack on Model**
  - 3.1.1 Modify image pixels to force the model to output malicious code (e.g., SQLi payloads).
- **3.2 Poison Training Data** (if custom models are used)
  - 3.2.1 Submit poisoned screenshots to influence future model behavior.

### 4. Steal or Abuse OpenAI API Keys
- **4.1 Extract Keys from Client-Side Code**
  - 4.1.1 Reverse-engineer the frontend to find hardcoded API keys.
- **4.2 Intercept Unencrypted API Requests**
  - 4.2.1 MITM attack if the app uses HTTP instead of HTTPS for OpenAI calls.

---

## 5. Visualize the Attack Tree
```
Root Goal: Compromise systems using screenshot-to-code by exploiting its weaknesses [OR]
+-- 1. Exploit Image Processing to Achieve RCE [OR]
    +-- 1.1 Exploit Vulnerable Image Parsing Library [OR]
        +-- 1.1.1 Buffer overflow via Pillow CVE-2023-50447 [AND]
        |   +-- (Pillow version < 10.0.0)
        |   +-- (Attacker crafts malicious PNG)
        +-- 1.1.2 EXIF command injection [AND]
            +-- (Image metadata parsed unsafely)
            +-- (Server uses `os.system` for EXIF extraction)
    +-- 1.2 Abuse File Upload Logic [OR]
        +-- 1.2.1 Upload executable disguised as image [AND]
        |   +-- (App lacks file-type validation)
        |   +-- (Server executes uploaded files)
        +-- 1.2.2 Path traversal in temp storage [AND]
            +-- (Filename not sanitized)
            +-- (Server uses user-provided paths)
+-- 2. Inject Malicious Code via AI-Generated Output [OR]
    +-- 2.1 Bypass Output Sanitization [OR]
        +-- 2.1.1 Trick model into generating XSS payload [AND]
        |   +-- (Output not HTML-escaped)
        |   +-- (Preview renders unsanitized HTML)
        +-- 2.1.2 Generate code with RCE payload [AND]
            +-- (App executes generated code in preview)
            +-- (No sandboxing)
    +-- 2.2 Exploit Insecure Preview Rendering [AND]
        +-- (Preview iframe allows parent DOM access)
        +-- (Generated code includes `window.parent.document` access)
+-- 3. Compromise AI Model Integrity [OR]
    +-- 3.1 Adversarial Attack on Model [AND]
        +-- (Model susceptible to pixel-based perturbations)
        +-- (Attacker knows model architecture)
    +-- 3.2 Poison Training Data [AND]
        +-- (App uses user-submitted data for fine-tuning)
        +-- (No data validation)
+-- 4. Steal or Abuse OpenAI API Keys [OR]
    +-- 4.1 Extract Keys from Client-Side Code [AND]
        +-- (API key exposed in frontend bundle)
        +-- (No environment variable separation)
    +-- 4.2 Intercept Unencrypted API Requests [AND]
        +-- (App uses HTTP for OpenAI API)
        +-- (Attacker controls network)
```

---

## 6. Assign Attributes to Each Node

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty |
|---|---|---|---|---|---|
| 1.1.1 Buffer overflow | Low | Critical | High | Expert | Medium |
| 1.1.2 EXIF injection | Medium | High | Medium | Intermediate | High |
| 2.1.1 XSS via model | High | Medium | Low | Low | Medium |
| 2.1.2 RCE in preview | Medium | Critical | Medium | Intermediate | High |
| 3.1 Adversarial attack | Low | High | High | Expert | High |
| 4.1 API key leakage | Medium | High | Low | Low | Low |

---

## 7. Analyze and Prioritize Attack Paths

### High-Risk Paths
- **2.1.1 XSS via Model** (High likelihood, medium impact): Easy to exploit if sanitization is missing.
- **1.1.2 EXIF Injection** (Medium likelihood, high impact): Likely if EXIF parsing uses unsafe functions.

### Critical Nodes
- **Output Sanitization**: Mitigates 2.1.1 and 2.1.2.
- **File-Type Validation**: Blocks 1.2.1 and 1.2.2.

---

## 8. Develop Mitigation Strategies
- **Image Processing**:
  - Use WASM-based image parsing to isolate vulnerabilities.
  - Strip EXIF metadata before processing.
- **Code Generation**:
  - Sanitize outputs with DOMPurify for HTML and AST checks for code.
  - Execute previews in a sandboxed iframe with `sandbox="allow-scripts"`.
- **API Keys**:
  - Enforce server-side key management (never expose in frontend).

---

## 9. Summarize Findings

### Key Risks Identified
1. XSS from unsanitized AI-generated code.
2. EXIF command injection during image processing.

### Recommended Actions
- Implement strict output sanitization.
- Isolate image processing in a restricted environment.

---

## 10. Questions & Assumptions
- **Assumptions**:
  - Preview pane executes generated code unsafely.
  - EXIF parsing uses `os.system` calls.
- **Questions**:
  - Does the app use server-side rendering for previews?
  - Are OpenAI API keys stored in environment variables?
