Here's the updated attack tree analysis incorporating findings from the new project files:

# Threat Modeling Analysis for screenshot-to-code Using Attack Trees (Updated)

## Updated Attack Tree Visualization

```
Root Goal: Compromise systems using screenshot-to-code by exploiting project weaknesses [OR]
+-- 1. Inject malicious code via AI-generated output [OR]
|   +-- 1.1 Exploit prompt injection in image metadata [AND]
|   |   +-- 1.1.1 Embed hidden prompts in input images
|   |   +-- 1.1.2 Bypass AI model safeguards
|   +-- 1.2 Manipulate training data in evaluation dataset
|   +-- 1.3 Exploit imported code processing [AND]
|   |   +-- 1.3.1 Inject malicious code in user-provided HTML
|   |   +-- 1.3.2 Bypass code sanitization in assemble_imported_code_prompt
|
+-- 2. Compromise API key handling [OR]
|   +-- 2.1 Steal keys from insecure storage [OR]
|   |   +-- 2.1.1 Exploit .env file exposure
|   |   +-- 2.1.2 Access keys through client-side settings
|   +-- 2.2 Intercept keys in insecure communications [AND]
|   |   +-- 2.2.1 MITM attack on unencrypted API calls
|   |   +-- 2.2.2 Exploit VITE_WS_BACKEND_URL misconfiguration
|
+-- 3. Exploit media processing vulnerabilities [OR]
|   +-- 3.1 Upload malicious media files [OR]
|   |   +-- 3.1.1 Crafted PNG with embedded payload
|   |   +-- 3.1.2 Video with malformed headers
|   +-- 3.2 Abuse video processing utilities [AND]
|   |   +-- 3.2.1 Exploit moviepy vulnerabilities
|   |   +-- 3.2.2 Bypass frame extraction limits
|
+-- 4. Compromise dependency chain [OR]
|   +-- 4.1 Poison CDN resources [AND]
|   |   +-- 4.1.1 Hijack cdn.tailwindcss.com
|   |   +-- 4.1.2 Modify jQuery scripts
|   +-- 4.2 Exploit vulnerable Python packages [AND]
|   |   +-- 4.2.1 Attack outdated FastAPI/uvicorn
|   |   +-- 4.2.2 Exploit poetry package installation
|   +-- 4.3 Compromise third-party API endpoints [OR]
|       +-- 4.3.1 Attack screenshotone.com API
|       +-- 4.3.2 Poison placehold.co image service
|
+-- 5. Abuse WebSocket interface [OR]
|   +-- 5.1 Exploit code generation stream [AND]
|   |   +-- 5.1.1 Inject malicious payload in history param
|   |   +-- 5.1.2 Bypass input validation in extract_params
|   +-- 5.2 Attack model selection logic [AND]
|       +-- 5.2.1 Force vulnerable model selection
|       +-- 5.2.2 Exploit mixed model vulnerabilities
|
+-- 6. Exploit evaluation system [OR]
    +-- 6.1 Path traversal in eval processing [AND]
    |   +-- 6.1.1 Manipulate base_name parameter
    |   +-- 6.1.2 Access arbitrary files via folder param
    +-- 6.2 Poison evaluation datasets [AND]
        +-- 6.2.1 Modify HTML files in evals directory
        +-- 6.2.2 Alter golden reference outputs
```

## Key Additions from New Files Analysis

### 1. Imported Code Processing Risks (Node 1.3)
- System processes user-provided code through `assemble_imported_code_prompt`
- No apparent sanitization of imported HTML content
- Risk of persistent XSS through malicious code in user-provided HTML

### 2. Video Processing Vulnerabilities (Node 3.2)
- Uses `moviepy` for video frame extraction
- Potential for malformed video file exploits
- Frame extraction logic could be abused to bypass security controls

### 3. WebSocket Interface Risks (Node 5)
- Complex input handling in `stream_code` endpoint
- Model selection logic could be manipulated to choose less secure AI models
- History parameter injection in update generations

### 4. Evaluation System Risks (Node 6)
- File path handling in `get_evals` and `get_pairwise_evals`
- Potential path traversal via folder/base_name parameters
- Golden dataset poisoning attack surface

## Updated Risk Analysis

| Attack Path                  | Likelihood | Impact | Effort | Skill | Detection |
|------------------------------|------------|--------|--------|-------|------------|
| 1.3.1 Malicious imported code| High       | High   | Low    | Medium| Medium     |
| 4.3.1 Screenshot API abuse   | Medium     | Medium | Medium| High  | Hard       |
| 5.1.1 WS history injection   | Low        | High   | High  | High  | Hard       |
| 6.1.1 Path traversal         | Medium     | High   | Medium| Medium| Medium     |

## Critical Updates to Mitigation Strategies

1. **Imported Code Sanitization**
   - Add HTML sanitization layer in `assemble_imported_code_prompt`
   - Implement CSP recommendations in generated code

2. **WebSocket Security**
   - Add strict input validation in `extract_params`
   - Implement model selection whitelisting

3. **Evaluation System Hardening**
   - Add path sanitization for folder/base_name parameters
   - Implement read-only access for eval directories

4. **Video Processing**
   - Add file signature verification for video uploads
   - Implement frame processing limits

## New Questions & Assumptions

**Questions:**
1. How are user-imported HTML files sanitized?
2. What validation exists for WebSocket message parameters?
3. Are eval directory paths properly sandboxed?
4. How are third-party CDN resources verified?

**Assumptions:**
1. No HTML sanitization occurs on imported code
2. WebSocket message parameters are trusted
3. Eval file paths are user-controllable
4. Third-party CDN resources are implicitly trusted

## Recommended Priority Actions

1. Implement HTML sanitization for user-imported code
2. Add path sanitization in eval file handling
3. Introduce CSP headers in generated code
4. Add signature verification for video files
5. Implement WebSocket input validation schema
