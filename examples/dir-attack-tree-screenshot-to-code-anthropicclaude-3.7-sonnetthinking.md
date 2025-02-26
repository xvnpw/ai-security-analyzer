# Threat Modeling Analysis for Screenshot-to-Code Using Attack Trees

## 1. Understand the Project

### Overview
Screenshot-to-code is a tool that converts screenshots, mockups, and Figma designs into functional code using AI. It supports multiple frontend frameworks and integrates with various AI models including Claude Sonnet 3.5, GPT-4o, DALL-E 3, and Flux Schnell. The project consists of a React/Vite frontend and a FastAPI backend.

### Key Components and Features
- Frontend: React/Vite web application
- Backend: FastAPI Python server
- AI Integration: OpenAI (GPT-4o), Anthropic (Claude), Google (Gemini)
- Image Generation: DALL-E 3, Flux Schnell
- Code Generation: Multiple frameworks (HTML+Tailwind, React, Vue, Bootstrap, etc.)
- Video-to-code functionality: Converting screen recordings to functional code
- Evaluation system: Comparing outputs from different AI models

### Dependencies
- Python libraries: FastAPI, uvicorn, websockets, openai, anthropic, PIL, moviepy
- Frontend: React, TailwindCSS, various web frameworks

## 2. Define the Root Goal of the Attack Tree

**Attacker's Ultimate Objective:** Compromise systems using the screenshot-to-code application by exploiting weaknesses in the project.

## 3. High-Level Attack Paths

1. API Key Theft and Abuse
2. Input Manipulation Attacks
3. Malicious Generated Code Delivery
4. Backend Server Exploitation
5. Data Exfiltration
6. Path Traversal and File System Access

## 4. Expanded Attack Tree

```
Root Goal: Compromise systems using Screenshot-to-Code by exploiting weaknesses in the project

[OR]
+-- 1. API Key Theft and Abuse
    [OR]
    +-- 1.1 Extract API Keys
        [OR]
        +-- 1.1.1 Access client-side stored API keys
        +-- 1.1.2 Intercept API keys during transmission
        +-- 1.1.3 Exploit insecure environment variable handling
    +-- 1.2 Abuse API access
        [OR]
        +-- 1.2.1 Make unauthorized AI service calls
        +-- 1.2.2 Exploit billing resources
        +-- 1.2.3 Access sensitive data from previous AI interactions

+-- 2. Input Manipulation Attacks
    [OR]
    +-- 2.1 Prompt Injection
        [OR]
        +-- 2.1.1 Craft screenshots with hidden malicious prompts
        +-- 2.1.2 Create images that induce the AI to generate vulnerable code
    +-- 2.2 File Upload Exploitation
        [OR]
        +-- 2.2.1 Upload malicious images targeting processing libraries
        +-- 2.2.2 Perform path traversal via upload filenames
        +-- 2.2.3 Upload oversized files causing DoS
    +-- 2.3 Video Processing Exploitation
        [OR]
        +-- 2.3.1 Upload crafted video files exploiting moviepy vulnerabilities
        +-- 2.3.2 Cause resource exhaustion with complex video processing

+-- 3. Malicious Generated Code Delivery
    [OR]
    +-- 3.1 Generate code with embedded vulnerabilities
        [OR]
        +-- 3.1.1 Generate code with XSS payloads
        +-- 3.1.2 Generate code with remote script inclusions
        +-- 3.1.3 Generate code with malicious redirects
    +-- 3.2 Social engineer users to deploy generated code
        [AND]
        +-- 3.2.1 Generate convincing yet vulnerable code
        +-- 3.2.2 Trick users into deploying it on production systems

+-- 4. Backend Server Exploitation
    [OR]
    +-- 4.1 Exploit CORS misconfiguration
        [AND]
        +-- 4.1.1 Identify CORS vulnerability (allow_origins="*")
        +-- 4.1.2 Perform cross-origin attacks with credentials
    +-- 4.2 Exploit dependency vulnerabilities
        [OR]
        +-- 4.2.1 Target vulnerable image processing libraries (PIL/Pillow)
        +-- 4.2.2 Exploit outdated Python packages
        +-- 4.2.3 Target vulnerabilities in moviepy during video processing
    +-- 4.3 Server-Side Request Forgery
        [AND]
        +-- 4.3.1 Manipulate OPENAI_BASE_URL setting
        +-- 4.3.2 Force server to connect to attacker-controlled endpoint
    +-- 4.4 Path Traversal in Evaluation Routes
        [OR]
        +-- 4.4.1 Submit folder paths with directory traversal characters
        +-- 4.4.2 Access unauthorized files through path manipulation

+-- 5. Data Exfiltration
    [OR]
    +-- 5.1 Extract sensitive information from logs/debug output
        [OR]
        +-- 5.1.1 Access debug logs containing API keys or sensitive prompts
        +-- 5.1.2 Extract data from error messages
    +-- 5.2 Extract design IP from submitted screenshots
        [AND]
        +-- 5.2.1 Gain access to image storage
        +-- 5.2.2 Harvest proprietary designs
    +-- 5.3 Access saved files in evaluation system
        [OR]
        +-- 5.3.1 Access HTML files containing sensitive information
        +-- 5.3.2 Extract design patterns from saved screenshots
```

## 5. Attack Tree Node Attributes

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty | Justification |
|---|---|---|---|---|---|---|
| 1. API Key Theft and Abuse | High | High | Medium | Medium | Medium | API keys provide direct access to paid AI services |
| 1.1 Extract API Keys | High | High | Medium | Medium | Medium | Keys appear to be stored client-side |
| 1.1.1 Access client-side stored API keys | High | High | Low | Low | Medium | README mentions keys are stored in browser |
| 1.1.2 Intercept API keys during transmission | Medium | High | Medium | Medium | Medium | Depends on transport security implementation |
| 1.1.3 Exploit insecure environment variable handling | Low | High | High | High | High | Requires server access |
| 1.2 Abuse API access | High | High | Low | Low | High | Once keys are obtained, abuse is straightforward |
| 1.2.1 Make unauthorized AI service calls | High | High | Low | Low | High | APIs can be used directly with the key |
| 1.2.2 Exploit billing resources | High | High | Low | Low | Medium | AI API calls can be expensive |
| 2. Input Manipulation Attacks | High | High | Medium | Medium | High | AI systems are vulnerable to specially crafted inputs |
| 2.1 Prompt Injection | High | High | Medium | Medium | High | LLMs can be manipulated with crafted inputs |
| 2.1.1 Craft screenshots with hidden malicious prompts | High | High | Medium | Medium | High | LLMs process image content including text |
| 2.1.2 Create images that induce the AI to generate vulnerable code | High | High | Medium | High | High | Requires understanding of AI biases |
| 2.3 Video Processing Exploitation | Medium | High | Medium | High | High | Video processing involves complex libraries with potential vulnerabilities |
| 2.3.1 Upload crafted video files exploiting moviepy vulnerabilities | Medium | High | High | High | High | Requires knowledge of specific moviepy vulnerabilities |
| 2.3.2 Cause resource exhaustion with complex video processing | High | Medium | Low | Medium | Medium | The code doesn't limit video size or complexity |
| 3. Malicious Generated Code Delivery | High | Critical | Medium | High | High | Generated code could contain backdoors |
| 3.1 Generate code with embedded vulnerabilities | High | Critical | Medium | High | High | AI might not recognize subtle vulnerabilities |
| 3.1.1 Generate code with XSS payloads | High | High | Medium | Medium | Medium | No explicit security checks for generated code |
| 3.1.2 Generate code with remote script inclusions | High | High | Medium | Medium | Medium | Users might not audit every script reference |
| 4. Backend Server Exploitation | Medium | High | High | High | Medium | Server has multiple security issues |
| 4.1 Exploit CORS misconfiguration | High | Medium | Low | Medium | Low | CORS is configured with allow_origins=["*"] |
| 4.3 Server-Side Request Forgery | High | High | Medium | High | High | OPENAI_BASE_URL can be configured via UI in non-prod environments |
| 4.4 Path Traversal in Evaluation Routes | High | High | Medium | Medium | Medium | Evaluation routes use user-provided folder paths without proper sanitization |
| 4.4.1 Submit folder paths with directory traversal characters | High | High | Low | Medium | Medium | No validation to prevent "../" in folder paths |
| 5.3 Access saved files in evaluation system | High | Medium | Medium | Medium | Medium | Evaluation system provides direct access to files |

## 6. Critical Attack Paths and Mitigation Strategies

### High-Risk Path 1: API Key Theft and Abuse
**Risk:** Client-side storage of API keys makes them vulnerable to theft, enabling attackers to abuse AI services at the user's expense.

**Mitigation:**
- Use a server-side proxy for AI API calls to avoid exposing keys to clients
- Implement key usage limitations and monitoring
- Consider using short-lived tokens or OAuth flows instead of long-lived API keys
- Add rate limiting on backend to prevent abuse

### High-Risk Path 2: Prompt Injection Attacks
**Risk:** Specially crafted screenshots could manipulate the AI to generate vulnerable or malicious code.

**Mitigation:**
- Implement content filtering for AI inputs and outputs
- Add security guardrails to the prompts to instruct the AI to avoid generating unsafe code
- Scan generated code for known vulnerability patterns before presenting to users
- Consider implementing a human-in-the-loop review for certain high-risk generation patterns

### High-Risk Path 3: Malicious Generated Code Delivery
**Risk:** Generated code could contain vulnerabilities that compromise systems where it's deployed.

**Mitigation:**
- Add security scanning for generated code
- Provide clear warnings about reviewing generated code before production use
- Sanitize any user-generated inputs used in code generation
- Add configurable security levels for code generation to allow users to balance creativity/functionality with security

### High-Risk Path 4: Server-Side Request Forgery via OPENAI_BASE_URL
**Risk:** Users can configure custom OpenAI base URL in non-production environments, which could be manipulated for SSRF attacks.

**Mitigation:**
- Validate and sanitize the OPENAI_BASE_URL parameter
- Implement URL allowlisting for acceptable endpoints
- Consider removing this feature or limiting it to trusted environments

### High-Risk Path 5: Path Traversal in Evaluation Routes
**Risk:** Evaluation routes use user-provided folder paths without proper validation, potentially allowing access to unauthorized files.

**Mitigation:**
- Sanitize all user-provided paths to prevent directory traversal
- Use a whitelist approach for allowed directories
- Implement proper access controls for file operations
- Consider using a dedicated file storage service instead of direct filesystem access

### High-Risk Path 6: Video Processing Exploitation
**Risk:** Video processing functionality lacks proper validation and uses complex libraries that could be exploited.

**Mitigation:**
- Implement strict validation for video files (size, format, duration)
- Add resource usage limits for video processing
- Keep video processing libraries updated
- Consider running video processing in a sandboxed environment

## 7. Summary of Findings

Screenshot-to-code has several significant security concerns:

1. **Client-side API key storage** creates risk of theft and unauthorized usage of expensive AI services
2. **Insecure handling of user input** could lead to prompt injection and malicious code generation
3. **CORS misconfiguration** increases the risk of cross-origin attacks
4. **Lack of input validation** for configuration parameters like OPENAI_BASE_URL enables server-side request forgery
5. **Path traversal vulnerabilities** in evaluation routes could allow unauthorized file access
6. **Video processing vulnerabilities** could be exploited to cause resource exhaustion or leverage vulnerabilities in dependencies
7. **No security scanning of generated code** means vulnerabilities could be introduced into downstream systems

The most critical risks involve API key security, prompt injection, path traversal in file operations, and server-side request forgery. These should be addressed first, followed by implementing proper input validation and security scanning for generated code.

## 8. Questions & Assumptions

- Does the application currently implement any form of code scanning or sanitization?
- Is there API usage monitoring or rate limiting in place?
- Are there any authentication mechanisms not visible in the provided files?
- Are there controls to prevent the generation of malicious code?
- How are temporary files managed and cleaned up?
- Is there a secure mechanism for storing and accessing evaluation data?
- For this threat model, I've assumed the application is running in a production environment with real user data and API keys.
