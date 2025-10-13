# Threat Modeling Analysis for screenshot-to-code Using Attack Trees

## 1. Understand the Project

### Project Name: screenshot-to-code

### Overview

Screenshot-to-code is a web application that converts screenshots, mockups, and Figma designs into functional code using AI models. The system consists of:
- **Frontend**: React/Vite application that provides the user interface
- **Backend**: FastAPI Python application that handles AI model interactions and code generation
- **AI Integration**: Supports multiple AI providers (OpenAI GPT-4, Anthropic Claude, Google Gemini)
- **Image Generation**: Optional image generation via DALL-E 3 or Replicate's Flux

The application accepts visual inputs (screenshots, videos, or text descriptions) and generates working code in various frameworks (HTML/Tailwind, React, Vue, Bootstrap, etc.).

### Key Components and Features

**Frontend:**
- React-based UI for uploading images/videos or entering text prompts
- Real-time WebSocket communication for streaming AI responses
- Support for multiple code variants (NUM_VARIANTS = 4)
- Code preview and editing capabilities
- Settings dialog for API key configuration

**Backend:**
- FastAPI WebSocket server for real-time code generation
- Multi-provider AI integration (OpenAI, Anthropic, Gemini)
- Prompt engineering system with different templates per stack
- Image processing and generation pipeline
- Evaluation and testing infrastructure
- Mock response system for testing
- Video processing capabilities (extracting frames from videos)
- URL screenshot capture via ScreenshotOne API

**Key Workflows:**
1. User uploads screenshot/video or enters text prompt
2. Backend assembles prompts using stack-specific templates
3. AI models generate code variants in parallel
4. Optional image generation for placeholders
5. Real-time streaming of generated code to frontend
6. User can iterate with updates and refinements

**New Testing Infrastructure:**
- Comprehensive test suite for prompt assembly
- Support for images in conversation history during updates
- Test utilities for prompt summary visualization
- URL normalization testing

### Dependencies

**Backend:**
- FastAPI, uvicorn (web framework)
- OpenAI Python SDK
- Anthropic Python SDK
- Google Gemini SDK
- aiohttp, httpx (HTTP clients)
- Pillow (image processing)
- BeautifulSoup (HTML parsing)
- moviepy (video processing)
- pytest (testing framework)

**Frontend:**
- React 18, Vite
- WebSocket for real-time communication
- Various UI libraries

**External Services:**
- OpenAI API (GPT-4 models)
- Anthropic API (Claude models)
- Google Gemini API
- Replicate API (Flux image generation)
- ScreenshotOne API (URL screenshot capture)

## 2. Define the Root Goal of the Attack Tree

**Attacker's Ultimate Objective:**

Compromise systems and data of users running screenshot-to-code by exploiting weaknesses in the application's design, implementation, or dependencies.

## 3. Identify High-Level Attack Paths (Sub-Goals)

1. **Exploit AI Model Integration Weaknesses**
   - Manipulate AI responses to inject malicious code
   - Abuse API key handling
   - Exploit prompt injection vulnerabilities

2. **Exploit WebSocket Communication**
   - Hijack or manipulate WebSocket connections
   - Bypass authentication/authorization
   - Inject malicious payloads via WebSocket messages

3. **Exploit Image/Video Processing Pipeline**
   - Upload malicious images/videos
   - Exploit image processing libraries
   - Abuse external image generation services

4. **Exploit Code Generation and Execution**
   - Generate malicious code via crafted inputs
   - Exploit code preview/execution mechanisms
   - Abuse eval() or similar dynamic code execution

5. **Compromise API Keys and Secrets**
   - Extract API keys from environment or configuration
   - Steal keys via client-side storage
   - Abuse shared/exposed API keys

6. **Exploit External Service Dependencies**
   - Abuse screenshot capture service
   - Man-in-the-middle attacks on external API calls
   - Exploit vulnerabilities in external SDKs

7. **Exploit Testing and Debug Infrastructure**
   - Abuse debug utilities in production
   - Exploit test mocking capabilities
   - Information disclosure through verbose error messages

## 4. Expand Each Attack Path with Detailed Steps

### 1. Exploit AI Model Integration Weaknesses

#### 1.1 Prompt Injection Attacks
- **1.1.1 Inject Malicious Instructions in Screenshots**
  - [AND]
    - Craft screenshot containing text that appears as system instructions
    - Upload screenshot to application
    - AI model interprets visual text as commands
    - Generated code contains malicious payloads (XSS, malicious scripts)
  
- **1.1.2 Manipulate History/Update Context**
  - [AND]
    - Send update request with crafted history
    - Include prompt injection in "user" messages
    - AI generates code with embedded attacks
    - Bypass system prompt restrictions

- **1.1.3 Exploit Video Mode Multi-Pass Processing**
  - [AND]
    - Submit video with adversarial frames
    - First pass generates benign code
    - Second pass introduces malicious modifications
    - Final code contains hidden malicious functionality

- **1.1.4 Inject via History Images**
  - [AND]
    - Submit update with images array in history
    - Include malicious visual prompts in referenced images
    - AI model processes images as additional context
    - Generated code includes injected malicious patterns
    - Bypass text-only sanitization

#### 1.2 Abuse Mock Response Mode
- **1.2.1 Enable MOCK Mode in Production**
  - [AND]
    - Set MOCK=true environment variable
    - Application serves hardcoded malicious responses
    - Users receive pre-crafted attack code
    - Bypass AI safety mechanisms

#### 1.3 Model Selection Manipulation
- **1.3.1 Force Use of Vulnerable/Cheaper Models**
  - [AND]
    - Manipulate generationType parameter
    - Force use of models with weaker safety guardrails
    - Generate code with reduced security checks
    - Exploit model-specific vulnerabilities

### 2. Exploit WebSocket Communication

#### 2.1 WebSocket Message Injection
- **2.1.1 Inject Malicious Messages**
  - [OR]
    - Send crafted "chunk" messages with malicious code
    - Inject "setCode" messages overwriting legitimate code
    - Manipulate "variantIndex" to target specific variants
  
#### 2.2 WebSocket Hijacking
- **2.2.1 No Authentication on WebSocket**
  - [AND]
    - WebSocket endpoint has no authentication
    - Attacker connects directly to /generate-code
    - Send malicious generation requests
    - Consume victim's API credits

- **2.2.2 WebSocket Error Code Exploitation**
  - [AND]
    - Trigger custom close code (APP_ERROR_WEB_SOCKET_CODE = 4332)
    - Application reveals error details in close frame
    - Information disclosure about internal state
    - Use disclosed info for targeted attacks

#### 2.3 Race Conditions in Parallel Variants
- **2.3.1 Exploit Variant Processing Race**
  - [AND]
    - Send concurrent malicious requests
    - Exploit non-atomic variant completion handling
    - Cause inconsistent state in variant_completions dict
    - Mix malicious and legitimate code

### 3. Exploit Image/Video Processing Pipeline

#### 3.1 Malicious Image Upload
- **3.1.1 Upload Image with Embedded Exploits**
  - [AND]
    - Craft image exploiting Pillow vulnerabilities
    - Upload via screenshot input
    - Trigger buffer overflow or arbitrary code execution
    - Compromise backend server

- **3.1.2 XXE via SVG Upload**
  - [AND]
    - Create SVG with XML External Entity
    - Upload as screenshot
    - BeautifulSoup or image processor parses SVG
    - Read sensitive files from server

#### 3.2 Video Processing Exploitation
- **3.2.1 Exploit moviepy Vulnerabilities**
  - [AND]
    - Upload malicious video file
    - moviepy processes video frames
    - Trigger vulnerability in video codec handling
    - Execute arbitrary code on server

- **3.2.2 Video Frame Extraction DoS**
  - [AND]
    - Upload video with excessive frames
    - Target exceeds TARGET_NUM_SCREENSHOTS (20)
    - Frame extraction consumes excessive resources
    - Causes server resource exhaustion (DoS)

- **3.2.3 Temporary File Exploitation**
  - [AND]
    - Upload video triggering frame extraction
    - Exploit race condition in temp file handling
    - Access saved screenshots in /tmp/screenshots_*
    - Read sensitive data from other users' sessions

#### 3.3 Image Generation Service Abuse
- **3.3.1 Inject Malicious Prompts into Image Generation**
  - [AND]
    - Generate code with crafted alt text
    - Alt text contains prompt injection for DALL-E/Flux
    - Image generation creates inappropriate/malicious images
    - Embed malicious content in generated code

### 4. Exploit Code Generation and Execution

#### 4.1 Generate XSS Payloads
- **4.1.1 Craft Input Generating XSS Code**
  - [AND]
    - Upload screenshot with XSS vectors in text
    - AI generates code including unsanitized input
    - User previews code in browser
    - XSS executes stealing credentials/session tokens

#### 4.2 Generate Code with Backdoors
- **4.2.1 Social Engineer AI to Include Malicious Logic**
  - [AND]
    - Craft screenshot with hidden malicious requirements
    - AI generates code with data exfiltration
    - User deploys generated code to production
    - Attacker gains access to user's application data

#### 4.3 Exploit HTML Extraction Weaknesses
- **4.3.1 Bypass HTML Content Extraction**
  - [AND]
    - AI response includes malicious code outside <html> tags
    - extract_html_content() fails to properly sanitize
    - Malicious JavaScript/CSS included in output
    - Code execution in user's browser

#### 4.4 Exploit Tag Content Extraction
- **4.4.1 Abuse extract_tag_content Function**
  - [AND]
    - AI generates code with nested or malformed tags
    - extract_tag_content() extracts unexpected content
    - Tag boundaries incorrectly identified
    - Malicious content leaks into extracted output

### 5. Compromise API Keys and Secrets

#### 5.1 Extract Keys from Frontend
- **5.1.1 Keys Stored in Browser Storage**
  - [AND]
    - User enters API keys in settings dialog
    - Keys stored in localStorage/sessionStorage
    - XSS or malicious extension reads storage
    - Attacker steals API keys

- **5.1.2 Keys Transmitted in WebSocket**
  - [AND]
    - API keys sent via WebSocket params
    - No TLS/encryption on WebSocket
    - Network sniffing captures keys
    - Attacker reuses stolen keys

#### 5.2 Server-Side Key Exposure
- **5.2.1 .env File Exposed**
  - [AND]
    - Misconfigured deployment exposes .env file
    - Attacker accesses /.env endpoint
    - All API keys leaked (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
    - Attacker uses keys for their own purposes

- **5.2.2 Keys in Debug Logs**
  - [AND]
    - IS_DEBUG_ENABLED=true in production
    - Debug logs written to publicly accessible directory
    - Logs contain API keys or sensitive data
    - Attacker retrieves keys from log files

#### 5.3 Abuse Shared API Keys
- **5.3.1 Hosted Version Key Reuse**
  - [AND]
    - IS_PROD=true using shared backend keys
    - No rate limiting per user
    - Attacker sends massive requests
    - Exhaust API quota causing DoS

### 6. Exploit External Service Dependencies

#### 6.1 Screenshot Capture Service Abuse
- **6.1.1 SSRF via ScreenshotOne**
  - [AND]
    - User provides URL for screenshot
    - normalize_url() validation is insufficient
    - ScreenshotOne API screenshots internal services
    - Attacker scans internal network

- **6.1.2 Capture Sensitive Screenshots**
  - [AND]
    - Provide URL to authenticated page
    - Service captures screenshot with user data
    - Screenshot sent back to attacker
    - Leak sensitive information

- **6.1.3 Protocol Confusion Attack**
  - [AND]
    - Exploit normalize_url() whitelist bypass
    - Craft URL with alternative protocol encoding
    - Bypass http/https validation
    - Access file:// or other dangerous protocols

#### 6.2 External API Poisoning
- **6.2.1 Man-in-the-Middle on API Calls**
  - [AND]
    - Attacker intercepts requests to OpenAI/Anthropic
    - Modify responses to inject malicious code
    - Application trusts modified responses
    - Malicious code delivered to user

#### 6.3 SDK Vulnerabilities
- **6.3.1 Exploit OpenAI SDK Vulnerability**
  - [AND]
    - Known vulnerability in openai Python package
    - Application uses vulnerable version
    - Craft API response triggering vulnerability
    - Remote code execution on backend

### 7. Exploit Testing and Debug Infrastructure

#### 7.1 Abuse Test Utilities in Production
- **7.1.1 Access Test Endpoints**
  - [AND]
    - Test routes not disabled in production
    - Discover test endpoints via enumeration
    - Access debug functionality (print_prompt_summary, format_prompt_summary)
    - Leak sensitive prompt data or system information

- **7.1.2 Trigger Debug Output**
  - [AND]
    - DEBUG flag set to True in production
    - Video processing saves frames to /tmp
    - Access saved screenshots via predictable UUID paths
    - Retrieve other users' sensitive image data

#### 7.2 Information Disclosure via Verbose Errors
- **7.2.1 Extract System Information from Errors**
  - [AND]
    - Trigger errors in image/video processing
    - Application returns detailed stack traces
    - Leak file paths, library versions, configuration
    - Use information for targeted exploitation

#### 7.3 Exploit Test Mock Functionality
- **7.3.1 Abuse assert_structure_match**
  - [AND]
    - Test utilities exposed or accessible
    - Craft malicious test patterns with <ANY>, <CONTAINS:>
    - Bypass validation logic in production code
    - Inject unexpected data structures

## 5. Visualize the Attack Tree

```
Root Goal: Compromise applications and users via screenshot-to-code weaknesses

[OR]
+-- 1. Exploit AI Model Integration Weaknesses
    [OR]
    +-- 1.1 Prompt Injection Attacks
        [OR]
        +-- 1.1.1 Inject Malicious Instructions in Screenshots
            [AND]
            +-- Craft screenshot with text as system instructions
            +-- Upload to application
            +-- AI interprets as commands
            +-- Generate code with malicious payloads
        +-- 1.1.2 Manipulate History/Update Context
            [AND]
            +-- Send update with crafted history
            +-- Include prompt injection in messages
            +-- AI generates malicious code
            +-- Bypass system prompt restrictions
        +-- 1.1.3 Exploit Video Multi-Pass Processing
            [AND]
            +-- Submit video with adversarial frames
            +-- First pass benign, second malicious
            +-- Final code contains hidden attacks
        +-- 1.1.4 Inject via History Images
            [AND]
            +-- Submit update with images in history
            +-- Include malicious visual prompts
            +-- AI processes as additional context
            +-- Bypass text-only sanitization
    +-- 1.2 Abuse Mock Response Mode
        [AND]
        +-- Set MOCK=true in environment
        +-- Serve hardcoded malicious responses
        +-- Bypass AI safety mechanisms
    +-- 1.3 Model Selection Manipulation
        [AND]
        +-- Manipulate generationType parameter
        +-- Force weaker safety model
        +-- Generate less secure code

+-- 2. Exploit WebSocket Communication
    [OR]
    +-- 2.1 WebSocket Message Injection
        [OR]
        +-- Send crafted "chunk" messages
        +-- Inject "setCode" overwriting code
        +-- Manipulate "variantIndex"
    +-- 2.2 WebSocket Hijacking
        [OR]
        +-- 2.2.1 No Authentication
            [AND]
            +-- No authentication on endpoint
            +-- Connect to /generate-code
            +-- Send malicious requests
            +-- Consume victim's API credits
        +-- 2.2.2 Error Code Exploitation
            [AND]
            +-- Trigger custom close code 4332
            +-- Extract error details
            +-- Information disclosure
            +-- Targeted attacks
    +-- 2.3 Race Conditions in Variants
        [AND]
        +-- Send concurrent requests
        +-- Exploit non-atomic completion
        +-- Mix malicious/legitimate code

+-- 3. Exploit Image/Video Processing
    [OR]
    +-- 3.1 Malicious Image Upload
        [OR]
        +-- 3.1.1 Exploit Pillow Vulnerabilities
            [AND]
            +-- Craft malicious image
            +-- Upload via screenshot
            +-- Trigger code execution
            +-- Compromise backend
        +-- 3.1.2 XXE via SVG Upload
            [AND]
            +-- Create SVG with XXE
            +-- Parser processes SVG
            +-- Read sensitive files
    +-- 3.2 Video Processing Exploitation
        [OR]
        +-- 3.2.1 Moviepy Vulnerabilities
            [AND]
            +-- Upload malicious video
            +-- moviepy processes frames
            +-- Trigger codec vulnerability
            +-- Execute arbitrary code
        +-- 3.2.2 Frame Extraction DoS
            [AND]
            +-- Upload excessive-frame video
            +-- Exceed TARGET_NUM_SCREENSHOTS
            +-- Resource exhaustion
            +-- Server DoS
        +-- 3.2.3 Temporary File Exploitation
            [AND]
            +-- Upload video
            +-- Race condition in temp files
            +-- Access /tmp/screenshots_*
            +-- Read other users' data
    +-- 3.3 Image Generation Abuse
        [AND]
        +-- Generate code with crafted alt text
        +-- Inject prompts into DALL-E/Flux
        +-- Create malicious images
        +-- Embed in generated code

+-- 4. Exploit Code Generation
    [OR]
    +-- 4.1 Generate XSS Payloads
        [AND]
        +-- Screenshot with XSS vectors
        +-- AI generates unsanitized code
        +-- User previews in browser
        +-- XSS steals credentials
    +-- 4.2 Generate Code with Backdoors
        [AND]
        +-- Screenshot with hidden requirements
        +-- AI includes data exfiltration
        +-- User deploys to production
        +-- Attacker gains data access
    +-- 4.3 Bypass HTML Extraction
        [AND]
        +-- AI response outside <html> tags
        +-- extract_html_content() fails
        +-- Malicious script included
        +-- Execute in browser
    +-- 4.4 Abuse Tag Content Extraction
        [AND]
        +-- Malformed/nested tags
        +-- extract_tag_content() misidentifies boundaries
        +-- Malicious content leaks
        +-- Execution in output

+-- 5. Compromise API Keys
    [OR]
    +-- 5.1 Extract from Frontend
        [OR]
        +-- 5.1.1 Keys in Browser Storage
            [AND]
            +-- Keys stored in localStorage
            +-- XSS reads storage
            +-- Steal API keys
        +-- 5.1.2 Keys in WebSocket
            [AND]
            +-- Keys sent via WebSocket
            +-- No TLS encryption
            +-- Network sniffing
            +-- Steal keys
    +-- 5.2 Server-Side Exposure
        [OR]
        +-- 5.2.1 .env File Exposed
            [AND]
            +-- Misconfigured deployment
            +-- Access /.env endpoint
            +-- Leak all API keys
        +-- 5.2.2 Keys in Debug Logs
            [AND]
            +-- IS_DEBUG_ENABLED in prod
            +-- Logs publicly accessible
            +-- Keys in log files
    +-- 5.3 Abuse Shared Keys
        [AND]
        +-- Hosted version shared keys
        +-- No rate limiting
        +-- Massive requests
        +-- Exhaust quota (DoS)

+-- 6. Exploit External Services
    [OR]
    +-- 6.1 Screenshot Service Abuse
        [OR]
        +-- 6.1.1 SSRF via ScreenshotOne
            [AND]
            +-- Provide internal URL
            +-- Insufficient normalize_url() validation
            +-- Screenshot internal services
            +-- Scan internal network
        +-- 6.1.2 Capture Sensitive Data
            [AND]
            +-- URL to authenticated page
            +-- Service captures data
            +-- Screenshot to attacker
        +-- 6.1.3 Protocol Confusion
            [AND]
            +-- Alternative protocol encoding
            +-- Bypass http/https validation
            +-- Access dangerous protocols
    +-- 6.2 API Poisoning
        [AND]
        +-- MITM on API calls
        +-- Modify responses
        +-- Inject malicious code
    +-- 6.3 SDK Vulnerabilities
        [AND]
        +-- Vulnerable SDK version
        +-- Craft malicious response
        +-- Trigger SDK vulnerability
        +-- Remote code execution

+-- 7. Exploit Testing/Debug Infrastructure
    [OR]
    +-- 7.1 Abuse Test Utilities
        [OR]
        +-- 7.1.1 Access Test Endpoints
            [AND]
            +-- Test routes in production
            +-- Discover via enumeration
            +-- Access debug functionality
            +-- Leak prompt data
        +-- 7.1.2 Trigger Debug Output
            [AND]
            +-- DEBUG=True in production
            +-- Frames saved to /tmp
            +-- Predictable UUID paths
            +-- Retrieve users' images
    +-- 7.2 Verbose Error Information
        [AND]
        +-- Trigger processing errors
        +-- Detailed stack traces
        +-- Leak system information
        +-- Targeted exploitation
    +-- 7.3 Mock Functionality Abuse
        [AND]
        +-- Test utilities exposed
        +-- Craft malicious patterns
        +-- Bypass validation
        +-- Inject unexpected data
```

## 6. Assign Attributes to Each Node

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty |
|-------------|-----------|--------|--------|-------------|---------------------|
| **1. Exploit AI Model Integration** | High | High | Low | Medium | High |
| - 1.1 Prompt Injection Attacks | High | High | Low | Low | High |
| -- 1.1.1 Inject via Screenshots | High | High | Low | Low | High |
| -- 1.1.2 Manipulate History/Context | Medium | High | Medium | Medium | High |
| -- 1.1.3 Video Multi-Pass | Low | High | High | High | Very High |
| -- 1.1.4 Inject via History Images | High | High | Low | Low | Very High |
| - 1.2 Abuse Mock Mode | Low | High | Low | Low | Low |
| - 1.3 Model Selection Manipulation | Medium | Medium | Low | Low | Medium |
| **2. Exploit WebSocket** | Medium | High | Medium | Medium | Medium |
| - 2.1 Message Injection | Medium | High | Medium | Medium | Medium |
| - 2.2 WebSocket Hijacking | High | High | Low | Low | Low |
| -- 2.2.1 No Authentication | High | High | Low | Low | Low |
| -- 2.2.2 Error Code Exploitation | Low | Low | Medium | Medium | High |
| - 2.3 Race Conditions | Low | Medium | High | High | High |
| **3. Exploit Image/Video Processing** | Medium | Critical | Medium | High | Medium |
| - 3.1 Malicious Image Upload | Medium | Critical | Medium | High | Medium |
| -- 3.1.1 Pillow Exploits | Medium | Critical | Medium | High | Medium |
| -- 3.1.2 XXE via SVG | Low | High | Medium | Medium | High |
| - 3.2 Video Processing | Medium | Critical | Medium | High | Medium |
| -- 3.2.1 Moviepy Vulnerabilities | Low | Critical | High | High | Medium |
| -- 3.2.2 Frame Extraction DoS | High | Medium | Low | Low | Low |
| -- 3.2.3 Temp File Exploitation | Medium | High | Medium | Medium | High |
| - 3.3 Image Generation Abuse | Medium | Medium | Low | Low | High |
| **4. Exploit Code Generation** | High | High | Low | Low | High |
| - 4.1 Generate XSS | High | High | Low | Low | High |
| - 4.2 Backdoors in Code | Medium | Critical | Medium | Medium | Very High |
| - 4.3 Bypass HTML Extraction | Low | High | Medium | Medium | Medium |
| - 4.4 Tag Content Extraction | Low | Medium | Low | Low | High |
| **5. Compromise API Keys** | Medium | Critical | Medium | Low | Low |
| - 5.1 Extract from Frontend | High | Critical | Low | Low | Low |
| -- 5.1.1 Browser Storage | High | Critical | Low | Low | Low |
| -- 5.1.2 WebSocket Sniffing | Medium | Critical | Medium | Medium | Medium |
| - 5.2 Server-Side Exposure | Low | Critical | Low | Low | Low |
| -- 5.2.1 .env File Exposed | Low | Critical | Low | Low | Low |
| -- 5.2.2 Keys in Debug Logs | Low | Critical | Low | Low | Low |
| - 5.3 Abuse Shared Keys | Medium | High | Low | Low | Medium |
| **6. Exploit External Services** | Medium | Medium | Medium | Medium | Medium |
| - 6.1 Screenshot Service Abuse | Medium | Medium | Low | Medium | Medium |
| -- 6.1.1 SSRF | Medium | Medium | Low | Medium | Medium |
| -- 6.1.2 Capture Sensitive Data | Low | High | Low | Low | High |
| -- 6.1.3 Protocol Confusion | Medium | High | Medium | High | High |
| - 6.2 API Poisoning | Low | Critical | High | High | High |
| - 6.3 SDK Vulnerabilities | Low | Critical | Low | Medium | Low |
| **7. Exploit Testing/Debug** | Medium | Medium | Low | Low | Low |
| - 7.1 Test Utilities Abuse | Low | Medium | Low | Low | Low |
| -- 7.1.1 Test Endpoints | Low | Medium | Low | Low | Low |
| -- 7.1.2 Debug Output | Medium | High | Low | Low | Low |
| - 7.2 Verbose Errors | Medium | Low | Low | Low | Medium |
| - 7.3 Mock Functionality | Low | Low | Medium | Medium | High |

## 7. Analyze and Prioritize Attack Paths

### High-Risk Paths

#### 1. Prompt Injection via Screenshots and History Images (1.1.1, 1.1.4)
**Justification:** The new test files reveal that the application now supports images in conversation history during updates. This significantly expands the attack surface for prompt injection:
- **High Likelihood:** Attackers can inject malicious visual prompts not just in initial screenshots, but throughout the entire conversation history
- **High Impact:** Generated code directly affects users, and visual prompts are harder to sanitize than text
- **Low Effort:** Simply craft images with embedded instructions
- **Very High Detection Difficulty:** Malicious visual prompts in history blend with legitimate update flows and are difficult to distinguish from benign reference images

The test cases (`test_image_mode_update_with_single_image_in_history`, `test_image_mode_update_with_multiple_images_in_history`) show that user messages can contain multiple images, each potentially carrying malicious visual instructions that compound the attack.

#### 2. Video Frame Extraction DoS (3.2.2)
**Justification:** The video processing code explicitly limits extraction to `TARGET_NUM_SCREENSHOTS = 20`, but the validation happens after extraction begins:
- **High Likelihood:** Easy to craft videos exceeding limits
- **Medium Impact:** Resource exhaustion on backend server
- **Low Effort:** Generate video with excessive frames
- **Low Detection Difficulty:** Resource monitoring can catch this
The code raises `ValueError` for >20 frames but only after processing, creating a window for DoS.

#### 3. Temporary File Information Disclosure (3.2.3, 7.1.2)
**Justification:** The `save_images_to_tmp()` function in video processing uses predictable UUIDs and DEBUG mode is explicitly enabled:
```python
DEBUG = True
unique_dir_name = f"screenshots_{uuid.uuid4()}"
tmp_screenshots_dir = os.path.join(tempfile.gettempdir(), unique_dir_name)
```
- **Medium Likelihood:** DEBUG=True suggests this runs in production
- **High Impact:** Access to other users' screenshot data
- **Low Effort:** Enumerate UUID-based paths
- **Low Detection Difficulty:** File access logs would show this
The function explicitly prints paths, potentially logging sensitive information.

#### 4. Protocol Confusion in URL Normalization (6.1.3)
**Justification:** The test file `test_screenshot.py` reveals the URL normalization function:
- Only validates against `ftp://` and `file://` protocols explicitly
- Defaults to adding `https://` for URLs without protocol
- **Medium Likelihood:** Alternative protocol encodings may bypass validation
- **High Impact:** SSRF to dangerous protocols
- **Medium Effort:** Requires crafting bypass payloads
- **High Detection Difficulty:** Depends on logging of URL processing

### Critical Nodes

#### 1. History Processing in Prompt Assembly
The new testing infrastructure reveals that conversation history is a critical node:
- Images can be included in any update message
- Multiple images per message are supported
- Both text and images flow through history
- Test shows imported code also supports images in updates

**Mitigations needed:**
- Sanitize all images in history, not just initial prompts
- Limit number of images per message and total in history
- Implement visual content analysis for prompt injection patterns
- Add warnings when images are included in updates

#### 2. Video Processing Pipeline
The video utilities expose multiple attack vectors:
- Frame extraction with resource consumption
- Temporary file storage with DEBUG logging
- Base64 decoding and file handling
- moviepy integration with potential codec vulnerabilities

**Mitigations needed:**
- Validate video properties before processing
- Disable DEBUG mode in production
- Secure temporary file permissions and cleanup
- Sandbox video processing

#### 3. WebSocket Error Handling
The custom WebSocket error code (4332) could leak information:
- Application-specific error codes reveal internal state
- Error messages in close frames may contain sensitive details

**Mitigations needed:**
- Generic error messages in WebSocket close frames
- Log detailed errors server-side only
- Rate limit error responses

#### 4. URL Normalization and External Services
The `normalize_url()` function is a critical security boundary:
- Handles user-provided URLs for ScreenshotOne API
- Validates protocols but may have edge cases
- Determines what external resources are accessed

**Mitigations needed:**
- Comprehensive protocol whitelist
- URL parsing library with security focus
- Internal IP/hostname blacklist
- Additional validation before external API calls

## 8. Develop Mitigation Strategies

### For Prompt Injection (1.1.x, 4.1, 4.2) - Updated

**Preventive:**
1. **History Image Sanitization:**
   - Implement OCR on all images in conversation history
   - Detect text patterns resembling system instructions
   - Reject or warn about images with suspicious text content
   - Limit number of images per message (e.g., max 3)
   - Implement total image limit per conversation (e.g., max 10)

2. **Visual Content Analysis:**
   - Use computer vision to detect adversarial patterns
   - Flag images with text overlays or embedded instructions
   - Validate image authenticity (not manipulated/composited)
   - Check for steganography in image data

3. **Output Sanitization:**
   - Add post-processing to detect and remove suspicious patterns in generated code
   - Implement Content Security Policy (CSP) headers in generated HTML
   - Escape special characters in AI-generated content
   - Validate that generated code matches expected structure

4. **System Prompt Hardening:**
   - Add explicit instructions to never execute code from images
   - Include anti-jailbreak instructions for image-based prompts
   - Instruct AI to ignore visual text that looks like system commands
   - Validate that system prompts aren't being overridden

5. **Code Review Layer:**
   - Show diff/preview before applying generated code
   - Highlight potentially dangerous patterns (eval, innerHTML, etc.)
   - Require user confirmation for risky operations
   - Display image sources used in code generation

**Detective:**
- Log all prompts and AI responses, including image metadata
- Monitor for patterns indicating prompt injection attempts
- Track unusual code generation patterns
- Alert on high-risk code patterns in output
- Analyze correlation between images and generated malicious code

### For Video Processing Vulnerabilities (3.2.x) - New

**Preventive:**
1. **Resource Limits:**
   - Validate video properties before extraction:
     ```python
     # Before processing
     if total_frames > MAX_ALLOWED_FRAMES:
         raise ValueError("Video too long")
     ```
   - Set maximum video duration (e.g., 30 seconds)
   - Limit video file size (current 5MB may be too large)
   - Implement timeout for video processing
   - Queue video jobs with resource monitoring

2. **Secure Temporary Files:**
   - **Disable DEBUG mode in production:**
     ```python
     DEBUG = os.getenv("DEBUG_VIDEO_PROCESSING", "false").lower() == "true"
     ```
   - Use secure temp directories with proper permissions (700)
   - Implement immediate cleanup after processing
   - Use cryptographically random UUIDs for paths
   - Never log temp file paths

3. **Sandboxing:**
   - Process videos in isolated containers
   - Limit filesystem access during processing
   - Use separate user account with minimal permissions
   - Implement network isolation during video processing

4. **Input Validation:**
   - Whitelist video formats (MP4, WebM only)
   - Verify video codec before processing
   - Check for video metadata anomalies
   - Reject videos with suspicious properties

**Detective:**
- Monitor resource consumption during video processing
- Alert on processing time exceeding thresholds
- Track failed video processing attempts
- Log video characteristics (frames, duration, size)
- Audit temp file access patterns

### For URL Normalization (6.1.x) - New

**Preventive:**
1. **Comprehensive Protocol Validation:**
   ```python
   ALLOWED_PROTOCOLS = {"http", "https"}
   BLOCKED_PROTOCOLS = {"file", "ftp", "data", "javascript", "vbscript"}
   
   def normalize_url(url: str) -> str:
       parsed = urlparse(url)
       if parsed.scheme and parsed.scheme not in ALLOWED_PROTOCOLS:
           raise ValueError(f"Protocol not allowed: {parsed.scheme}")
       # ... rest of validation
   ```

2. **Internal IP/Hostname Blocking:**
   - Block RFC 1918 private IP ranges
   - Block loopback addresses (127.0.0.0/8, ::1)
   - Block link-local addresses (169.254.0.0/16)
   - Block cloud metadata endpoints (169.254.169.254)
   - Block internal hostnames

3. **DNS Rebinding Protection:**
   - Resolve hostname before making request
   - Validate resolved IP is not internal
   - Re-validate after DNS resolution
   - Use DNS pinning for external services

4. **Additional Validation:**
   - Maximum URL length (e.g., 2048 chars)
   - Validate URL structure beyond protocol
   - Check for URL encoding bypasses
   - Validate query parameters don't contain injections

**Detective:**
- Log all URL screenshot requests
- Monitor for internal IP access attempts
- Alert on blocked protocol attempts
- Track patterns of malicious URL submissions

### For Testing/Debug Infrastructure (7.x) - New

**Preventive:**
1. **Environment-Based Feature Flags:**
   - Never enable DEBUG in production:
     ```python
     DEBUG = os.getenv("ENVIRONMENT") == "development"
     TARGET_NUM_SCREENSHOTS = 5 if DEBUG else 20  # Less in dev
     ```
   - Separate test endpoints from production code
   - Use environment variables to control debug features
   - Implement feature flags with production defaults

2. **Test Endpoint Protection:**
   - Remove test routes from production builds
   - Require authentication for debug endpoints
   - Use separate ports for admin/debug interfaces
   - Implement IP whitelisting for debug access

3. **Secure Logging:**
   - Never log sensitive data (API keys, user content)
   - Redact sensitive information in logs
   - Implement structured logging with security levels
   - Separate debug logs from production logs
   - Use log aggregation with access controls

4. **Error Handling:**
   - Generic error messages for users
   - Detailed errors only in server logs
   - No stack traces in API responses
   - Error codes instead of detailed messages

**Detective:**
- Monitor for access to debug endpoints
- Alert on DEBUG flag changes
- Track error rates and types
- Audit log access patterns

### For WebSocket Security (2.x) - Enhanced

**Preventive:**
1. **Authentication:** (as before)
   - Implement token-based auth for WebSocket connections
   - Validate tokens on every message
   - Use session management

2. **Rate Limiting:** (as before)
   - Limit requests per user/IP
   - Implement backoff strategies
   - Queue management to prevent resource exhaustion

3. **Error Information Control:**
   - Use generic close codes for client errors
   - Log detailed errors server-side only
   - Never include sensitive data in close messages:
     ```python
     # Instead of revealing details
     await websocket.close(code=APP_ERROR_WEB_SOCKET_CODE, reason="Generic error")
     # Log details server-side
     logger.error(f"WebSocket error: {detailed_error}")
     ```

4. **Input Validation:** (as before)
   - Validate all WebSocket message parameters
   - Enforce message schema
   - Reject malformed messages

**Detective:**
- Monitor WebSocket connection patterns
- Alert on unusual message volumes
- Track error rates and types
- Log all WebSocket activity with sanitized data

### For API Key Protection (5.x) - Same as before

[Previous mitigations remain unchanged]

### For Image/Video Processing (3.x) - Enhanced

[Previous mitigations plus video-specific ones above]

### For External Service Security (6.x) - Enhanced

[Previous mitigations plus URL normalization ones above]

### For Code Execution (4.x) - Enhanced with Tag Extraction

**Preventive:**
1. **Tag Content Validation:**
   - Validate tag structure before extraction
   - Implement maximum nesting depth
   - Sanitize extracted content
   - Use proper HTML parser instead of string manipulation

2. **Code Preview Security:** (as before)
   - Use sandboxed iframe for preview
   - Implement strict CSP
   - Disable dangerous APIs
   - Sanitize HTML before preview

3. **Code Generation Guardrails:** (as before)
   - Scan generated code for dangerous patterns
   - Block obvious backdoors
   - Validate against expected code structure
   - Use static analysis tools

**Detective:**
- Analyze generated code patterns
- Alert on suspicious code features
- Track user deployments (if applicable)
- Monitor user feedback on quality/security

## 9. Summarize Findings

### Key Risks Identified

1. **Images in Conversation History (NEW - CRITICAL)**
   - Multiple images can be included in update messages throughout conversation
   - Visual prompt injection can occur at any point, not just initial screenshot
   - Harder to detect than text-based injection
   - Test infrastructure confirms this is intentionally supported

2. **Video Processing Resource Exhaustion (NEW - HIGH)**
   - DEBUG mode explicitly enabled in code
   - Frame extraction validates limits after processing begins
   - Temporary files saved with predictable paths
   - No resource limits enforced before processing

3. **Temporary File Information Disclosure (NEW - HIGH)**
   - DEBUG flag set to True suggests production use
   - UUID-based paths are predictable
   - Screenshots saved to /tmp with print statements
   - No immediate cleanup visible
   - Potential cross-user data leakage

4. **URL Normalization Weaknesses (NEW - MEDIUM)**
   - Limited protocol validation (only blocks ftp, file)
   - No internal IP blocking visible
   - Potential for protocol confusion attacks
   - SSRF risks to internal services

5. **WebSocket Error Information Leakage (NEW - LOW)**
   - Custom error code (4332) may reveal application state
   - Error details in close frames
   - Potential information disclosure

6. **Prompt Injection Vulnerability (CRITICAL - Enhanced)**
   - AI models can be manipulated via crafted screenshots AND history images
   - No effective filtering of visual prompt injection attempts
   - Generated code directly affects users without validation
   - Multiple injection points throughout conversation flow

7. **Unauthenticated WebSocket Endpoint (HIGH)**
   - `/generate-code` WebSocket has no authentication
   - Enables API credit theft and abuse
   - Allows direct code injection

8. **Client-Side API Key Storage (CRITICAL)**
   - API keys likely stored in browser storage
   - Vulnerable to XSS and malicious extensions
   - Exposes expensive third-party API access

9. **XSS in Generated Code (HIGH)**
   - No sanitization of AI-generated HTML/JavaScript
   - Preview functionality may execute malicious code
   - Users may deploy vulnerable code to production

10. **Image Processing Vulnerabilities (MEDIUM)**
    - Pillow and moviepy may have exploitable vulnerabilities
    - SVG files could enable XXE attacks
    - Malicious files could compromise backend

### Recommended Actions

**Immediate (Critical Priority):**

1. **Implement Image Sanitization in Conversation History (NEW)**
   - Add OCR analysis to all images in history messages
   - Detect and reject images with system instruction patterns
   - Limit number of images per message (max 3)
   - Implement total conversation image limit (max 10)
   - Add visual content analysis for adversarial patterns
   - Log all images used in code generation with metadata

2. **Disable DEBUG Mode and Secure Video Processing (NEW)**
   - Set `DEBUG = False` or use environment-based flag
   - Move DEBUG check to environment variable:
     ```python
     DEBUG = os.getenv("ENVIRONMENT") == "development"
     ```
   - Implement pre-processing video validation
   - Add resource limits before extraction begins
   - Secure temporary file permissions (chmod 700)
   - Use cryptographically random paths
   - Implement immediate cleanup after processing
   - Never log temp file paths

3. **Harden URL Normalization (NEW)**
   - Implement comprehensive protocol whitelist (http, https only)
   - Add internal IP/hostname blocking (RFC 1918, loopback, etc.)
   - Implement DNS rebinding protection
   - Add maximum URL length validation
   - Check for encoding bypasses
   - Validate resolved IPs before making requests

4. **Implement Server-Side API Key Management**
   - Remove all client-side API key storage
   - Implement backend proxy for AI API calls
   - Encrypt keys with proper key management
   - Add per-user rate limiting

5. **Add WebSocket Authentication**
   - Implement token-based authentication
   - Validate on connection and per-message
   - Add rate limiting per user
   - Implement session management
   - Use generic error codes (don't reveal APP_ERROR_WEB_SOCKET_CODE details)

6. **Implement Output Sanitization**
   - Scan AI-generated code for malicious patterns
   - Add CSP headers to generated HTML
   - Validate code structure before delivery
   - Implement code preview security (sandboxed iframe)
   - Add tag content extraction validation

**Short-term (High Priority):**

7. **Secure Test and Debug Infrastructure (NEW)**
   - Remove test endpoints from production
   - Implement environment-based feature flags
   - Separate debug logs from production
   - Never log sensitive data (API keys, temp paths)
   - Generic error messages only
   - Implement proper error handling without stack traces

8. **Harden Prompt System**
   - Add anti-injection instructions for visual prompts
   - Implement input scanning for suspicious patterns in images
   - Add user warnings for detected risks in images
   - Log prompt injection attempts
   - Implement image provenance tracking

9. **Secure Image Processing**
   - Update all image processing libraries
   - Implement file validation and size limits
   - Disable XXE in XML parsers
   - Add sandboxing for file processing
   - Validate video properties before processing
   - Implement processing timeouts

10. **Fix SSRF Vulnerability**
    - Implement allowlist for screenshot URLs
    - Block internal/private IP ranges comprehensively
    - Add URL validation beyond normalize_url()
    - Consider removing screenshot-from-URL feature
    - Implement DNS rebinding protection

**Medium-term (Medium Priority):**

11. **Implement Security Monitoring**
    - Add logging for all security-relevant events
    - Implement anomaly detection for video processing
    - Set up alerts for suspicious patterns
    - Create incident response procedures
    - Monitor temp file access patterns
    - Track image usage in conversations

12. **Dependency Management**
    - Set up automated vulnerability scanning
    - Pin SDK versions
    - Monitor CVE databases
    - Establish update procedures
    - Special attention to moviepy and Pillow

13. **User Security Education**
    - Warn about risks of deploying generated code
    - Provide security review guidelines
    - Document secure usage patterns
    - Add security warnings in UI
    - Explain risks of providing sensitive screenshots

## 10. Questions & Assumptions

### Questions:

1. **Image History Storage:** Are images in conversation history stored server-side or only referenced by URL? How long are they retained?

2. **Video Processing Environment:** Is video processing done synchronously during WebSocket connection? Is there a separate job queue?

3. **DEBUG Mode Usage:** Is the DEBUG flag in video processing actually used in production, or is this test/development code?

4. **Temporary File Cleanup:** What is the cleanup mechanism for temporary video frames? Is there a cron job or manual cleanup?

5. **Test Utilities Exposure:** Are the test utilities (`print_prompt_summary`, `format_prompt_summary`, `assert_structure_match`) accessible in any way from production code or endpoints?

6. **URL Screenshot Rate Limiting:** Are there rate limits on screenshot-from-URL functionality to prevent abuse?

7. **Image Limits:** What are the actual limits on image count per message and total in conversation? Are they enforced?

8. **WebSocket Error Handling:** What information is actually sent in WebSocket close frames when APP_ERROR_WEB_SOCKET_CODE (4332) is used?

9. **Video Format Support:** What video formats are actually supported beyond the mime type detection?

10. **Prompt Summary Logging:** Is the prompt summary functionality used in production logging? Does it log sensitive user images?

### Assumptions:

1. **History Image Support:** Assuming the test cases reflect actual production functionality where images can be included in any update message

2. **DEBUG Flag:** Assuming `DEBUG = True` in video utils suggests this may run in production or is overlooked

3. **Temporary File Persistence:** Assuming temp files persist beyond video processing completion based on explicit save and print

4. **No Image Validation:** Assuming no OCR or visual content analysis on images in history based on lack of such code in tests

5. **Test Infrastructure:** Assuming test utilities are not exposed in production, but confirming this is important

6. **URL Validation:** Assuming `normalize_url()` function shown in tests is the actual production implementation

7. **WebSocket Error Details:** Assuming error details may be sent in close frames based on custom error code definition

8. **Resource Limits:** Assuming no pre-processing resource validation for videos based on code structure

9. **Client-Side Storage:** (Same as before) Assuming API keys entered via settings dialog are stored client-side

10. **No Additional Security Layers:** (Same as before) Assuming no WAF or additional security infrastructure

**New Assumptions from Test Files:**

11. **Multiple Images Per Message:** Assuming production supports multiple images per user message as shown in tests

12. **No Image Count Limits:** Assuming no hard limits on image count based on test patterns

13. **History Images Processed Same as Initial:** Assuming all images in history are processed with same detail level ("high")

14. **Imported Code Supports Images:** Assuming imported code flow also supports image references in updates

15. **Prompt Summary Not in Production:** Assuming `print_prompt_summary` and related functions are development/testing only