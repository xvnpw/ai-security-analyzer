Here's the updated attack tree incorporating findings from the new PROJECT FILES:

# Threat Modeling Analysis for screenshot-to-code Using Attack Trees (Updated)

## Attack Tree Visualization

```
Root Goal: Compromise systems using screenshot-to-code
[OR]
+-- 1. Exploit AI Code Generation
    [OR]
    +-- 1.1 Inject malicious code via image input
    +-- 1.2 Poison training data/evals dataset
    +-- 1.3 Manipulate model prompts
    +-- 1.4 Prompt injection via visual patterns
        [AND]
        +-- 1.4.1 Embed hidden text in input images
        +-- 1.4.2 Bypass OCR sanitization

+-- 2. Compromise API Integrations
    [OR]
    +-- 2.1 Steal OpenAI/Anthropic API keys
        [OR]
        +-- 2.1.1 Exploit .env file exposure
        +-- 2.1.2 Sniff unencrypted WebSocket traffic
        +-- 2.1.3 XSS via generated code
    +-- 2.2 Abuse API credentials for crypto mining
    +-- 2.3 SSRF via screenshot API
        [AND]
        +-- 2.3.1 Control screenshot URL parameter
        +-- 2.3.2 Bypass URL validation

+-- 3. Attack Deployment Infrastructure
    [OR]
    +-- 3.1 Exploit Docker misconfigurations
        [AND]
        +-- 3.1.1 Access exposed Docker API
        +-- 3.1.2 Privilege escalation
    +-- 3.2 Compromise CI/CD pipeline

+-- 4. Exploit Vulnerable Dependencies
    [OR]
    +-- 4.1 Exploit Pillow image processing (CVE-2024-28219)
    +-- 4.2 Exploit httpx SSRF vulnerabilities
    +-- 4.3 Exploit Poetry dependency chain
    +-- 4.4 Exploit moviepy video processing

+-- 5. Abuse File Processing
    [OR]
    +-- 5.1 Upload malicious video files
    +-- 5.2 Path traversal in image processing
    +-- 5.3 RCE via image metadata parsing
    +-- 5.4 Insecure code execution during evals
        [AND]
        +-- 5.4.1 Inject malicious code in test HTML
        +-- 5.4.2 Disable sandboxing in eval runner

+-- 6. Exploit WebSocket Protocol
    [OR]
    +-- 6.1 Websocket denial-of-service
    +-- 6.2 Session hijacking via WS auth flaws
    +-- 6.3 Code injection through variant flooding
```

## Key Additions from New Files Analysis

### 1. New Attack Path: Prompt Injection via Visual Patterns (1.4)
- **Source**: `test_prompts.py` system prompts and video processing
- **Risk**: Hidden text/patterns in input images could manipulate LLM output
- **Example**: Steganographic prompts in screenshot bypassing OCR filters

### 2. Enhanced API Risks (2.3)
- **Source**: `routes/screenshot.py` SSRF potential
- **Impact**: Server-side request forgery via manipulated screenshot URLs
- **Trigger**: `capture_screenshot(target_url=internal_resource)`

### 3. Video Processing Risks (4.4, 5.1)
- **Source**: `video/utils.py` moviepy integration
- **Vulnerability**: Malicious video files could exploit moviepy/PIL vulnerabilities
- **Exploit**: Crafted video metadata causing RCE during frame extraction

### 4. Evaluation Sandbox Escape (5.4)
- **Source**: `routes/evals.py` HTML test execution
- **Risk**: Generated test HTML could contain malicious JS
- **Impact**: XSS/RCE if evals run in privileged environment

## Updated Node Attributes

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty |
|-------------|------------|--------|--------|-------------|-----------------------|
| 1.4         | Medium     | High   | Medium | High        | Very High             |
| 2.3         | Low        | Medium | High   | High        | Medium                |
| 4.4         | Medium     | High   | Medium | Medium      | Low                   |
| 5.4         | High       | High   | Low    | Medium      | Medium                |

## Critical Updates to Mitigation Strategies

1. **Visual Input Sanitization**:
```python
# Add to image_processing/utils.py
from PIL import Image
import pytesseract

def sanitize_image_text(image_path):
    text = pytesseract.image_to_string(Image.open(image_path))
    return text.replace('<', '&lt;').replace('>', '&gt;')
```

2. **SSRF Protection in Screenshot API**:
```python
# Add to routes/screenshot.py
from urllib.parse import urlparse

def validate_url(target_url: str):
    parsed = urlparse(target_url)
    if parsed.hostname in ['localhost', '127.0.0.1']:
        raise ValueError("Internal URL blocked")
    if parsed.port in [22, 3306, 5432]:
        raise ValueError("Dangerous port blocked")
```

3. **Eval Sandboxing**:
```python
# Update routes/evals.py
import js2py

def safe_eval(html_content: str):
    context = js2py.EvalJs({'window': None})
    return context.eval(html_content)
```

## New High-Risk Paths

### 1. Visual Prompt Injection (1.4)
- **Impact**: Stealthy code injection via AI misinterpretation
- **Example**: Hidden "<!-- <script>" text in screenshot leading to XSS
- **Mitigation**: Implement OCR-based input sanitization

### 2. Evaluation Sandbox Escape (5.4)
- **Impact**: Privilege escalation through test execution
- **Example**: Malicious `eval()` in generated test code
- **Mitigation**: Strict sandboxing with Docker-based eval containers

## Updated Questions & Assumptions

**New Assumptions**:
- Video processing uses unpatched moviepy version
- Evaluation HTML runs in same context as backend
- WebSocket authentication relies on frontend session cookies

**New Questions**:
1. Is there input validation for visual text extraction?
2. Are evaluation environments containerized?
3. How often are moviepy/PIL dependencies scanned?
