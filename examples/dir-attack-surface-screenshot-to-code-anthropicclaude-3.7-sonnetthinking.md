# Attack Surface Analysis for Screenshot-to-Code

## Key Attack Surfaces

### 1. API Key Exposure

- **Description**: API keys for OpenAI, Anthropic, Google Gemini, Replicate, and Screenshotone could be exposed through insecure storage, logging, or client-side exposure.

- **How screenshot-to-code contributes**: The application stores API keys in `.env` files, allows users to set API keys through the frontend UI, and uses these keys in API calls to external services including AI providers and screenshot services.

- **Example**: If API keys are accidentally committed to a public GitHub repository or logged in error messages, attackers could extract and use these keys.

- **Impact**: Unauthorized access to AI and screenshot services, potentially significant financial impact (billing for unauthorized API usage), and possible data access.

- **Risk Severity**: High

- **Current Mitigations**: The application advises users to keep keys secret in documentation. The code also allows setting keys via environment variables rather than hardcoding them. The application also stores API keys locally in the user's browser when set through the UI (rather than on the server).

- **Missing Mitigations**: Implement encryption for stored API keys, create a key rotation mechanism, add rate limiting and usage monitoring to detect abuse, implement a secure vault for API key storage, and add alerts for unusual API usage patterns.

### 2. Cross-Site Scripting (XSS) through Generated Code

- **Description**: The application generates HTML, CSS, and JavaScript code based on AI models' output, which could potentially contain malicious scripts.

- **How screenshot-to-code contributes**: The application generates code based on AI model outputs, displays this code in the browser, and allows users to execute the generated code for preview.

- **Example**: An attacker could design a screenshot or video with components that trick the AI into generating JavaScript code containing XSS payloads, which would then be executed when previewed.

- **Impact**: Client-side attacks, session hijacking, data theft from users viewing or executing the generated code.

- **Risk Severity**: High

- **Current Mitigations**: AI models are instructed to generate functional, clean code (though not explicitly for security). The generated code is mainly presentational, with limited functionality.

- **Missing Mitigations**: Implement sanitization of generated code before execution, add a Content Security Policy (CSP) for the preview environment, provide clear warnings to users about executing generated code, and implement a sandboxed preview environment.

### 3. Path Traversal in Evaluation Routes

- **Description**: The evaluation routes accept user-provided folder paths and file names which could potentially be exploited for path traversal attacks.

- **How screenshot-to-code contributes**: In `routes/evals.py`, the application accepts folder paths as parameters, verifies their existence, and performs file operations on them without comprehensive path sanitization.

- **Example**: An attacker might use path traversal sequences like `../../../etc/passwd` to access sensitive files outside the intended directory.

- **Impact**: Unauthorized access to sensitive files on the server, information disclosure, and potential system compromise.

- **Risk Severity**: High

- **Current Mitigations**: Some basic validation is performed (checking if folders exist), but comprehensive path validation is missing.

- **Missing Mitigations**: Implement strict path validation and sanitization, use absolute paths with proper restrictions, avoid directly using user input for file paths, and implement a secure sandbox for file operations.

### 4. Insecure External API Integration

- **Description**: The application integrates with multiple external APIs (OpenAI, Anthropic, Google, Replicate, Screenshotone) which could introduce vulnerabilities if not properly secured.

- **How screenshot-to-code contributes**: The app sends user content (images, text, videos) to third-party AI services, processes responses from these services, allows configuration of custom API base URLs, and uses an external screenshot service.

- **Example**: The application allows setting a custom OpenAI base URL through the `OPENAI_BASE_URL` environment variable, which could potentially be exploited for Server-Side Request Forgery (SSRF) if not properly validated.

- **Impact**: Data leakage to third parties, potential for SSRF attacks, and exposure to vulnerabilities in third-party services.

- **Risk Severity**: Medium

- **Current Mitigations**: The application provides options to use proxies for API access and includes documentation on how to properly configure API endpoints.

- **Missing Mitigations**: Implement input validation for custom API base URLs, add sandboxing of external API interactions, establish a process for handling third-party API security incidents, and implement data minimization practices when sending data to external APIs.

### 5. Server-Side Request Forgery (SSRF) via Screenshot Service

- **Description**: The screenshot API accepts a user-provided URL which could be used to forge requests to internal services or resources.

- **How screenshot-to-code contributes**: The application provides a `/api/screenshot` endpoint that accepts a target URL and forwards it to an external screenshot service without comprehensive validation.

- **Example**: An attacker could provide a URL pointing to an internal service (e.g., `http://localhost:8080/admin`) which would cause the screenshot service to attempt connecting to that internal resource.

- **Impact**: Access to internal services, network scanning, and potential exploitation of internal vulnerabilities.

- **Risk Severity**: Medium

- **Current Mitigations**: The application uses an external screenshot service (screenshotone.com) rather than implementing the screenshot functionality locally, which provides some isolation.

- **Missing Mitigations**: Implement URL validation to restrict targets to legitimate public websites, establish a whitelist of allowed domains, and monitor screenshot requests for suspicious patterns.

### 6. Video Processing Vulnerabilities

- **Description**: The application processes video files to extract frames for AI analysis, which could expose vulnerabilities in video processing libraries.

- **How screenshot-to-code contributes**: The application uses third-party libraries (moviepy, PIL) to process and extract frames from user-provided videos.

- **Example**: A specially crafted malicious video file could potentially exploit vulnerabilities in the moviepy or PIL libraries, leading to buffer overflows or arbitrary code execution.

- **Impact**: Potential server compromise, data theft, or denial of service.

- **Risk Severity**: Medium

- **Current Mitigations**: The application uses established libraries for video processing and limits the number of frames extracted (20 maximum).

- **Missing Mitigations**: Implement strict validation of video file formats and sizes, regularly update video processing libraries, limit resources allocated to video processing, and potentially use sandboxing for video processing operations.

### 7. Insecure WebSocket Communication

- **Description**: The application uses WebSockets for communication between frontend and backend, which could be vulnerable to various attacks.

- **How screenshot-to-code contributes**: The app implements a WebSocket server in the backend (specifically for code generation), establishes client-side WebSocket connections, and exchanges potentially sensitive data over these connections.

- **Example**: Without proper authentication and encryption, WebSocket communications could be intercepted or hijacked, allowing attackers to access sensitive information or inject malicious content.

- **Impact**: Data interception, unauthorized access to application functionality, and potential for injecting malicious payloads.

- **Risk Severity**: Medium

- **Current Mitigations**: The application uses standard WebSocket implementation, limits the scope of what can be done via WebSockets, and defines custom error codes for more secure communication.

- **Missing Mitigations**: Implement authentication for WebSocket connections, add TLS encryption for WebSocket traffic, validate WebSocket message formats, and implement rate limiting for WebSocket connections.
