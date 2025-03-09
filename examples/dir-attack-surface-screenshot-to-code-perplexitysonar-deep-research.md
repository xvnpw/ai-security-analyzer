# Attack Surface Analysis for screenshot-to-code Application

## Insecure Cross-Origin Resource Sharing (CORS) Configuration
**Description:** Backend API endpoints allow requests from any origin (`allow_origins=["*"]`)
**Project Contribution:** Explicit CORS middleware configuration in `main.py` enables wide-open access
**Example Impact:** Malicious website could make unauthorized API requests to generate code using stolen API credentials
**Risk Severity:** High
**Current Mitigations:** None implemented in current configuration
**Missing Mitigations:** Restrict origins to frontend domains only using environment variables

## Third-Party API Key Exposure Risk
**Description:** Sensitive API keys (OpenAI/Anthropic) stored in frontend client-side settings
**Project Contribution:** Frontend settings dialog allows key input that persists in browser storage
**Example Impact:** XSS vulnerability could exfiltrate keys, enabling unauthorized LLM usage at project's expense
**Risk Severity:** Critical
**Current Mitigations:** Keys only stored in browser memory (not localStorage)
**Missing Mitigations:** Implement backend proxy for API calls with rate limiting and key rotation

## Unsafe User Content Processing
**Description:** Image/video upload functionality without proper sanitization
**Project Contribution:** Direct processing of base64-encoded user uploads in `video/utils.py` and `image_processing/utils.py`
**Example Impact:** Maliciously crafted image files could exploit vulnerabilities in Pillow/moviepy dependencies
**Risk Severity:** High
**Current Mitigations:** Basic image resizing/compression for Claude compatibility
**Missing Mitigations:** Sandboxed processing environment, file type whitelisting, malware scanning

## WebSocket Endpoint Vulnerabilities
**Description:** `/generate-code` WebSocket lacks authentication and payload validation
**Project Contribution:** Direct exposure of code generation endpoint without session management
**Example Impact:** Unauthenticated attackers could exhaust API quotas through automated requests
**Risk Severity:** Medium
**Current Mitigations:** API key requirement for generation endpoints
**Missing Mitigations:** Implement WebSocket authentication tokens and request rate limiting

## Insecure Client-Side Code Execution
**Description:** Generated HTML outputs include untrusted third-party scripts by default
**Project Contribution:** Template system automatically includes CDN-hosted scripts (Tailwind, FontAwesome)
**Example Impact:** Compromised CDN could lead to DOM-based XSS in generated outputs
**Risk Severity:** Medium
**Current Mitigations:** None in current implementation
**Missing Mitigations:** Content Security Policy headers, subresource integrity checks

## Containerization Risks
**Description:** Docker configuration runs services as root user
**Project Contribution:** Both `backend/Dockerfile` and `frontend/Dockerfile` lack USER directives
**Example Impact:** Container breakout could lead to host system compromise
**Risk Severity:** Medium
**Current Mitigations:** None implemented
**Missing Mitigations:** Create non-root users in Dockerfiles, implement read-only filesystems

## Video Processing Attack Surface
**Description:** `moviepy` dependency used for frame extraction from user-uploaded videos
**Project Contribution:** Direct processing of arbitrary video formats in `video/utils.py`
**Example Impact:** Malformed video files could trigger memory corruption vulnerabilities
**Risk Severity:** High
**Current Mitigations:** Temporary file cleanup after processing
**Missing Mitigations:** Input file type validation, ffmpeg hardening with seccomp profiles

## Dependency Chain Risks
**Description:** Multiple high-risk dependencies (OpenCV, FFmpeg, PIL) in processing pipeline
**Project Contribution:** Direct use of image/video processing libraries with complex parsing logic
**Example Impact:** Known vulnerabilities in `pillow` or `moviepy` dependencies could be exploited
**Risk Severity:** Medium
**Current Mitigations:** Poetry dependency management with pinned versions
**Missing Mitigations:** Regular vulnerability scanning, minimal base images

## Prompt Injection Vulnerabilities
**Description:** User-controlled input passed directly to LLM system prompts
**Project Contribution:** `prompts/assemble_prompt` handles unescaped user content
**Example Impact:** Crafted prompts could bypass output restrictions or exfiltrate system data
**Risk Severity:** Medium
**Current Mitigations:** Basic prompt templating
**Missing Mitigations:** Input sanitization, LLM output validation layer

## Build Pipeline Vulnerabilities
**Description:** Frontend build process includes development dependencies in production
**Project Contribution:** Single-stage Docker builds including dev tools like Vite
**Example Impact:** Increased attack surface from unnecessary build components
**Risk Severity:** Low
**Current Mitigations:** Separate dev/prod Docker configurations
**Missing Mitigations:** Multi-stage builds with production-only artifacts

## Conclusion
The analysis reveals critical risks around third-party API key management and high-severity vulnerabilities in media processing pipelines. Immediate priorities should include implementing proper CORS restrictions, sandboxing user content processing, and securing API key storage. The containerization strategy requires hardening to follow least-privilege principles. Future mitigations should focus on input validation layers and dependency vulnerability management.
