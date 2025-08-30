# Threat Modeling Analysis for Screenshot-to-Code Using Attack Trees

## 1. Understand the Project

### Overview

Screenshot-to-Code is an AI-powered web application that converts screenshots, mockups, and Figma designs into functional code. It uses AI models (Claude, GPT-4, Gemini) to analyze visual inputs and generate HTML/CSS/JavaScript code in various frameworks. The system consists of a FastAPI backend (Python) and React/Vite frontend.

### Key Components and Features

- **Backend (FastAPI/Python)**:
  - WebSocket-based code generation pipeline
  - Integration with multiple AI providers (OpenAI, Anthropic, Gemini)
  - Image generation capabilities (DALL-E 3, Flux via Replicate)
  - Video-to-code conversion
  - Screenshot capture functionality
  - Evaluation system for testing model performance

- **Frontend (React/Vite)**:
  - WebSocket client for real-time communication
  - Multi-variant code generation (parallel generation of multiple versions)
  - Code editing and update capabilities
  - Settings management for API keys

- **Core Functionality**:
  - Accepts images/videos/text as input
  - Generates code in multiple stacks (HTML/Tailwind, React, Vue, Bootstrap, etc.)
  - Supports multiple AI model providers
  - Allows iterative code updates based on user feedback
  - Generates placeholder images using AI

### Dependencies

- **AI Service Providers**: OpenAI, Anthropic, Google (Gemini), Replicate
- **External Services**: Screenshot API (screenshotone.com)
- **Python Libraries**: FastAPI, Pydantic, httpx, Pillow, BeautifulSoup4, moviepy
- **Frontend Libraries**: React, Vite, Tailwind CSS, Zustand

## 2. Define the Root Goal of the Attack Tree

**Attacker's Ultimate Objective:**

To compromise systems that use Screenshot-to-Code by exploiting vulnerabilities in the application itself, enabling unauthorized access, data theft, code injection, service disruption, or supply chain attacks on downstream users.

## 3. Identify High-Level Attack Paths (Sub-Goals)

The main attack strategies include:

1. **Exploiting AI Integration Vulnerabilities**
2. **WebSocket Communication Attacks**
3. **Supply Chain Poisoning**
4. **API Key and Secrets Exploitation**
5. **Code Injection Through Generated Output**
6. **Resource Exhaustion and DoS Attacks**
7. **Video Processing Exploitation** (NEW based on test files)

## 4. Expand Each Attack Path with Detailed Steps

### 1. Exploiting AI Integration Vulnerabilities

- 1.1 Prompt Injection Attacks
  - 1.1.1 Malicious Image Content
    - Embed instructions in screenshot metadata
    - Use optical character recognition confusion
    - Leverage model hallucinations
  - 1.1.2 History Manipulation
    - Inject malicious content through update history
    - Exploit multi-turn conversation context
    - Manipulate imported code flow system prompts
  - 1.1.3 Video Frame Poisoning
    - Insert malicious frames in video input
    - Exploit temporal processing vulnerabilities
    - Abuse frame extraction logic in `split_video_into_screenshots()`

- 1.2 Model Response Manipulation
  - 1.2.1 Force Generation of Malicious Code
    - XSS payloads in generated HTML
    - Command injection in generated scripts
  - 1.2.2 Information Disclosure
    - Extract training data through prompts
    - Reveal system prompts and configurations

### 2. WebSocket Communication Attacks

- 2.1 Message Injection
  - 2.1.1 Parameter Tampering
    - Modify `generationType` to bypass validations
    - Inject malicious `prompt` content
    - Manipulate `variantIndex` for race conditions
    - Exploit custom close code `APP_ERROR_WEB_SOCKET_CODE = 4332`
  - 2.1.2 Protocol Exploitation
    - Send malformed WebSocket frames
    - Exploit message ordering vulnerabilities

- 2.2 Session Hijacking
  - 2.2.1 WebSocket Connection Takeover
    - Lack of authentication on WebSocket endpoints
    - Missing rate limiting
  - 2.2.2 Cross-Origin WebSocket Hijacking
    - Exploit missing origin validation
    - CSRF-style attacks on WebSocket

### 3. Supply Chain Poisoning

- 3.1 Dependency Vulnerabilities
  - 3.1.1 Vulnerable Python Packages
    - Exploit known CVEs in dependencies
    - Poetry lock file manipulation
    - Target moviepy library vulnerabilities
  - 3.1.2 Frontend Package Exploitation
    - npm/yarn dependency confusion
    - Malicious package injection

- 3.2 Generated Code Distribution
  - 3.2.1 Malicious Code Templates
    - Backdoors in generated code
    - Hidden cryptocurrency miners
  - 3.2.2 Persistent XSS in Output
    - Self-replicating malicious patterns
    - Time-delayed payloads

### 4. API Key and Secrets Exploitation

- 4.1 Key Extraction
  - 4.1.1 Frontend Key Exposure
    - Extract keys from browser storage
    - Network traffic interception
  - 4.1.2 Backend Key Leakage
    - Error message disclosure
    - Debug endpoint exposure
    - Extract from test/debug configurations

- 4.2 Key Abuse
  - 4.2.1 Unauthorized API Usage
    - Consume victim's API credits
    - Access restricted models
  - 4.2.2 Data Exfiltration
    - Use stolen keys to access AI services
    - Extract proprietary prompts

### 5. Code Injection Through Generated Output

- 5.1 Client-Side Attacks
  - 5.1.1 XSS in Generated HTML
    - Bypass sanitization in `extract_html_content()`
    - Exploit BeautifulSoup parsing vulnerabilities
    - Leverage `extract_tag_content()` function weaknesses
  - 5.1.2 JavaScript Execution
    - Malicious event handlers
    - DOM manipulation attacks

- 5.2 Server-Side Attacks
  - 5.2.1 Template Injection
    - Exploit prompt assembly logic
    - Path traversal in file operations
  - 5.2.2 Command Injection
    - Through image processing pipeline
    - Via external service calls

### 6. Resource Exhaustion and DoS Attacks

- 6.1 Computational DoS
  - 6.1.1 Parallel Variant Overload
    - Request maximum variants repeatedly
    - Trigger expensive AI operations
  - 6.1.2 Image Generation Abuse
    - Request large numbers of images
    - Exploit Replicate/DALL-E rate limits

- 6.2 Memory Exhaustion
  - 6.2.1 Large Input Processing
    - Upload massive images/videos
    - Exploit image resizing logic
  - 6.2.2 WebSocket Connection Flooding
    - Open multiple connections
    - Send continuous streaming data

### 7. Video Processing Exploitation (NEW)

- 7.1 Video File Attacks
  - 7.1.1 Malformed Video Upload
    - Upload corrupted video files to crash moviepy
    - Exploit tempfile handling in video processing
    - Trigger memory exhaustion via large video files
  - 7.1.2 Frame Extraction Manipulation
    - Manipulate `TARGET_NUM_SCREENSHOTS` limits
    - Force extraction of excessive frames
    - Exploit frame skip calculation logic

- 7.2 Screenshot URL Exploitation
  - 7.2.1 URL Normalization Bypass
    - Exploit `normalize_url()` function
    - SSRF via screenshot API
    - Protocol confusion attacks
  - 7.2.2 External Service Abuse
    - Target screenshotone.com API
    - Rate limit exhaustion
    - Cost inflation attacks

## 5. Visualize the Attack Tree

```
Root Goal: Compromise systems using Screenshot-to-Code by exploiting application vulnerabilities

[OR]
+-- 1. Exploiting AI Integration Vulnerabilities
    [OR]
    +-- 1.1 Prompt Injection Attacks
        [OR]
        +-- 1.1.1 Malicious Image Content
            [AND]
            +-- Craft poisoned screenshot
            +-- Bypass image validation
            +-- Trigger code generation
        +-- 1.1.2 History Manipulation
            [AND]
            +-- Inject via update history
            +-- Maintain context persistence
            +-- Exploit imported code flow
        +-- 1.1.3 Video Frame Poisoning
            [AND]
            +-- Insert malicious frames
            +-- Exploit Claude video processing
            +-- Abuse frame extraction
    +-- 1.2 Model Response Manipulation
        [OR]
        +-- 1.2.1 Force Malicious Code Generation
        +-- 1.2.2 Information Disclosure

+-- 2. WebSocket Communication Attacks
    [OR]
    +-- 2.1 Message Injection
        [OR]
        +-- 2.1.1 Parameter Tampering
            [AND]
            +-- Intercept WebSocket message
            +-- Modify parameters
            +-- Replay modified message
        +-- 2.1.2 Protocol Exploitation
    +-- 2.2 Session Hijacking
        [OR]
        +-- 2.2.1 WebSocket Connection Takeover
        +-- 2.2.2 Cross-Origin WebSocket Hijacking

+-- 3. Supply Chain Poisoning
    [OR]
    +-- 3.1 Dependency Vulnerabilities
        [OR]
        +-- 3.1.1 Vulnerable Python Packages
        +-- 3.1.2 Frontend Package Exploitation
    +-- 3.2 Generated Code Distribution
        [OR]
        +-- 3.2.1 Malicious Code Templates
        +-- 3.2.2 Persistent XSS in Output

+-- 4. API Key and Secrets Exploitation
    [OR]
    +-- 4.1 Key Extraction
        [OR]
        +-- 4.1.1 Frontend Key Exposure
        +-- 4.1.2 Backend Key Leakage
    +-- 4.2 Key Abuse
        [AND]
        +-- Obtain valid API keys
        +-- Use for malicious purposes

+-- 5. Code Injection Through Generated Output
    [OR]
    +-- 5.1 Client-Side Attacks
        [OR]
        +-- 5.1.1 XSS in Generated HTML
        +-- 5.1.2 JavaScript Execution
    +-- 5.2 Server-Side Attacks
        [OR]
        +-- 5.2.1 Template Injection
        +-- 5.2.2 Command Injection

+-- 6. Resource Exhaustion and DoS
    [OR]
    +-- 6.1 Computational DoS
        [OR]
        +-- 6.1.1 Parallel Variant Overload
        +-- 6.1.2 Image Generation Abuse
    +-- 6.2 Memory Exhaustion
        [OR]
        +-- 6.2.1 Large Input Processing
        +-- 6.2.2 WebSocket Connection Flooding

+-- 7. Video Processing Exploitation
    [OR]
    +-- 7.1 Video File Attacks
        [OR]
        +-- 7.1.1 Malformed Video Upload
            [AND]
            +-- Create corrupted video file
            +-- Bypass file validation
            +-- Trigger moviepy crash
        +-- 7.1.2 Frame Extraction Manipulation
    +-- 7.2 Screenshot URL Exploitation
        [OR]
        +-- 7.2.1 URL Normalization Bypass
        +-- 7.2.2 External Service Abuse
```

## 6. Assign Attributes to Each Node

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty |
|---|---|---|---|---|---|
| **1. AI Integration Vulnerabilities** | High | High | Medium | Medium | High |
| - 1.1.1 Malicious Image Content | High | High | Low | Low | High |
| - 1.1.2 History Manipulation | Medium | High | Medium | Medium | Medium |
| - 1.1.3 Video Frame Poisoning | Medium | High | High | High | High |
| - 1.2.1 Force Malicious Code | High | Critical | Low | Medium | High |
| - 1.2.2 Information Disclosure | Medium | Medium | Low | Low | Medium |
| **2. WebSocket Attacks** | High | High | Low | Low | Medium |
| - 2.1.1 Parameter Tampering | High | High | Low | Low | Low |
| - 2.1.2 Protocol Exploitation | Medium | Medium | Medium | Medium | Medium |
| - 2.2.1 Connection Takeover | High | High | Low | Low | Low |
| - 2.2.2 CSWSH | Medium | High | Medium | Medium | High |
| **3. Supply Chain Poisoning** | Medium | Critical | High | High | High |
| - 3.1.1 Python Package Vulns | Medium | High | Medium | Medium | Medium |
| - 3.1.2 Frontend Package Exploit | Medium | High | Medium | Medium | Medium |
| - 3.2.1 Malicious Templates | Low | Critical | High | High | High |
| - 3.2.2 Persistent XSS | Medium | High | Medium | Medium | High |
| **4. API Key Exploitation** | High | High | Low | Low | Medium |
| - 4.1.1 Frontend Key Exposure | High | High | Low | Low | Low |
| - 4.1.2 Backend Key Leakage | Medium | High | Medium | Medium | Medium |
| - 4.2 Key Abuse | High | High | Low | Low | Medium |
| **5. Code Injection** | High | Critical | Medium | Medium | Medium |
| - 5.1.1 XSS in Generated HTML | High | High | Low | Low | Medium |
| - 5.1.2 JavaScript Execution | High | High | Low | Low | Medium |
| - 5.2.1 Template Injection | Medium | Critical | Medium | High | High |
| - 5.2.2 Command Injection | Low | Critical | High | High | Medium |
| **6. Resource Exhaustion** | High | Medium | Low | Low | Low |
| - 6.1.1 Variant Overload | High | Medium | Low | Low | Low |
| - 6.1.2 Image Generation Abuse | Medium | Medium | Low | Low | Low |
| - 6.2.1 Large Input Processing | High | Medium | Low | Low | Low |
| - 6.2.2 WebSocket Flooding | High | Medium | Low | Low | Low |
| **7. Video Processing Exploitation** | Medium | High | Medium | Medium | Medium |
| - 7.1.1 Malformed Video Upload | Medium | High | Medium | Medium | Low |
| - 7.1.2 Frame Extraction Manipulation | Low | Medium | Medium | Medium | Medium |
| - 7.2.1 URL Normalization Bypass | Medium | High | Low | Medium | Medium |
| - 7.2.2 External Service Abuse | Medium | Medium | Low | Low | Low |

## 7. Analyze and Prioritize Attack Paths

### High-Risk Paths

1. **Prompt Injection → Malicious Code Generation** (Critical Risk)
   - **Justification**: AI models can be manipulated to generate harmful code through carefully crafted inputs. The application lacks strict output validation and the test files show complex prompt assembly with images and history manipulation capabilities.

2. **WebSocket Parameter Tampering** (High Risk)
   - **Justification**: No authentication on WebSocket endpoints and minimal input validation make this trivially exploitable. Custom error codes suggest WebSocket handling complexity.

3. **Video Processing Attacks** (High Risk)
   - **Justification**: Video processing uses tempfiles and moviepy library which can be exploited. The frame extraction logic with hardcoded limits (`TARGET_NUM_SCREENSHOTS = 20`) and debug mode saving frames to disk presents attack surface.

4. **URL Normalization Bypass for SSRF** (High Risk)
   - **Justification**: The `normalize_url()` function accepts various URL formats and protocols, potentially enabling SSRF attacks via the screenshot functionality.

### Critical Nodes

- **WebSocket endpoint `/generate-code`**: Gateway to all generation functionality
- **AI response processing pipeline**: Lacks proper sanitization
- **Video processing pipeline**: Uses temporary files and external library (moviepy)
- **URL normalization function**: Entry point for screenshot capture attacks
- **API key management**: Weak isolation between frontend and backend

## 8. Develop Mitigation Strategies

### For Prompt Injection Attacks
- Implement strict input validation and sanitization
- Add output filtering for dangerous patterns
- Use sandboxed execution environments for generated code
- Implement content security policies
- Validate image metadata and strip unnecessary data

### For WebSocket Vulnerabilities
- Add authentication and authorization to WebSocket endpoints
- Implement rate limiting per connection
- Validate message structure and parameters
- Add origin validation for CSWSH prevention
- Implement proper error handling without revealing system details

### For Video Processing Security
- Validate video file formats and sizes before processing
- Implement resource limits for video processing
- Sanitize temporary file handling
- Add timeout mechanisms for video processing operations
- Validate frame count limits strictly
- Disable debug mode in production (remove `save_images_to_tmp()`)

### For URL Security
- Implement strict URL validation in `normalize_url()`
- Whitelist allowed protocols (only http/https)
- Add SSRF protection with internal network blocking
- Implement URL reputation checking
- Add rate limiting for screenshot requests

### For API Key Security
- Move all API keys to backend-only storage
- Implement proxy endpoints for AI services
- Add API key rotation mechanisms
- Use short-lived tokens for frontend
- Remove API keys from test configurations

### For Code Injection
- Enhance HTML extraction and sanitization
- Improve `extract_tag_content()` function security
- Implement CSP headers for generated content
- Use iframe sandboxing for preview
- Add malicious pattern detection

### For Resource Exhaustion
- Implement request throttling
- Add resource quotas per user/session
- Optimize parallel processing limits
- Add circuit breakers for external services
- Implement video file size limits
- Add frame extraction limits

## 9. Summarize Findings

### Key Risks Identified

1. **Unprotected WebSocket endpoints** enable unauthorized code generation
2. **Prompt injection vulnerabilities** allow malicious code generation through history and image manipulation
3. **Video processing vulnerabilities** via moviepy and tempfile handling
4. **URL normalization weaknesses** enable SSRF attacks
5. **API key exposure** risks financial and data security
6. **Lack of output sanitization** enables XSS attacks
7. **Missing rate limiting** allows resource exhaustion
8. **Debug mode features** expose sensitive information in production

### Recommended Actions

**Immediate (Critical)**:
- Implement WebSocket authentication
- Add rate limiting to all endpoints
- Sanitize AI-generated output
- Move API keys to backend-only
- Disable debug mode features in production
- Add video file size and processing limits

**Short-term (High)**:
- Add input validation for all parameters
- Implement CSP for generated content
- Add monitoring and alerting
- Implement request signing
- Improve URL validation and SSRF protection
- Add timeout mechanisms for video processing

**Long-term (Medium)**:
- Develop sandboxed execution environment
- Implement zero-trust architecture
- Add behavioral analysis for abuse detection
- Create security testing framework
- Implement comprehensive logging for video processing
- Add content validation for extracted frames

## 10. Questions & Assumptions

### Questions
1. Are there any existing authentication mechanisms planned?
2. What is the expected deployment environment (cloud/on-premise)?
3. Are there compliance requirements (GDPR, SOC2)?
4. What is the intended user base (public/private)?
5. Is the debug mode (`DEBUG = True`) disabled in production?
6. What are the file size limits for video uploads?
7. Are there any rate limits on external service APIs (screenshotone.com)?

### Assumptions
1. Application is publicly accessible without authentication
2. Users can provide their own API keys
3. Generated code is executed in user environments
4. No current rate limiting or abuse prevention
5. Default configuration is used in production
6. Debug features may be enabled in production
7. Video processing has no file size restrictions
8. Temporary files are not properly cleaned up after processing
