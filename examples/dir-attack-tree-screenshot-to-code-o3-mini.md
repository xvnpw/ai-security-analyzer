Below is an attack‐tree analysis that focuses on weaknesses intrinsic to the “screenshot‐to‐code” project (as evidenced by the repository’s files) and on ways an attacker might exploit them to compromise a system that uses the project. In this analysis we concentrate on vulnerabilities that stem from how the application assembles and processes inputs, its handling of file and network parameters, and its integration with large‐language model (LLM) APIs. (Note that we explicitly omit “general” threats such as audit, backup issues, etc.)

---

## 1. Project Overview

**Purpose and Functionality:**
“screenshot‐to‐code” is an open–source tool that uses AI (via models like GPT‐4 Vision, Claude Sonnet, Gemini, etc.) to convert screenshots, mockups, and design snapshots into clean, functional code (HTML/CSS, React, Vue, etc.). Its architecture features a React/Vite frontend and a FastAPI backend. The project includes multiple evaluation and testing scripts, Dockerfiles for both backend and frontend deployments, and extensive prompt–assembly logic for commanding different LLMs. It also integrates with third–party APIs for taking screenshots and even processing videos to extract frames for further input to the code generator.

**Key Components:**

- **Backend API Endpoints:**
  – `/generate-code` (via WebSocket) which accepts parameters (including image URLs, API keys, generation history) and streams code completions obtained from providers (OpenAI, Anthropic, Gemini).
  – `/api/screenshot` that accepts a URL and API key and calls an external screenshot API.
  – Evaluation routes (e.g. `/evals`, `/pairwise-evals`, `/best-of-n-evals`) that list local HTML files and images from a designated eval folder.

- **Prompt Assembly and LLM Integration:**
  Files under “prompts” and “llm.py” show that the project constructs composite messages (with image URL parts and text prompts) to instruct the models. There is also functionality to handle “imported code” as part of an update.

- **Utilities and Logging:**
  Utility modules (e.g. for extracting HTML from an LLM’s output, image processing, logging) that perform minimal sanitization and version tracking.

- **Deployment and Development:**
  Dockerfiles, Poetry configuration, and environment variable usage for API keys.

---

## 2. Root Goal of the Attack Tree

**Attacker’s Ultimate Objective:**
*“Compromise target systems that use ‘screenshot‐to‐code’ by exploiting weaknesses in the project’s code‐assembly, file–handling, API integration, and prompt processing mechanisms.”*

---

## 3. High–Level Attack Paths & Expansion (Attack Tree)

Below is a text–based visualization of the attack tree. The top–level node splits (with logical [OR] branches) into several distinct strategies an attacker might use.

```
Root Goal: Compromise systems using weaknesses in the screenshot-to-code project
[OR]
+-- 1. Exploit Eval Endpoints for Arbitrary File Access and Disclosure
|     [OR]
|     +-- 1.1 Manipulate the "folder" query parameter in the /evals endpoint
|           to traverse directories and list/return arbitrary files.
|     +-- 1.2 Abuse folder parameters in /pairwise-evals and /best-of-n-evals
|           to force the server to open files from sensitive directories.
|
+-- 2. Exploit the Code Generation Endpoint (/generate-code)
|     [OR]
|     +-- 2.1 Perform Prompt Injection Attacks:
|           - Supply specially crafted image URLs or history entries
|             that cause the downstream LLM (via unsanitized prompt messages)
|             to output malicious code (e.g. code that creates hidden iframes or
|             executes unexpected JavaScript).
|     +-- 2.2 Inject Malicious Code Payloads:
|           - Manipulate inputs so that the resulting HTML includes XSS or
|             client-side malicious scripts which can compromise a user’s browser.
|
+-- 3. Exploit SSRF via the /api/screenshot Endpoint
|     [AND]
|     +-- Supply a malicious "url" parameter that forces the server's HTTP
|         client to initiate requests against internal networks or unintended targets.
|
+-- 4. Abuse LLM Integration Vulnerabilities in Prompt Processing
|     [OR]
|     +-- 4.1 Manipulate the composite prompt messages (both system and user parts)
|           to force the LLM to reveal sensitive internal logic or output harmful code.
|     +-- 4.2 Interfere with the streaming callback mechanism to disrupt or poison
|           the code generation process.
|
+-- 5. Denial-of-Service (DoS) via WebSocket Flooding
|     [AND]
|     +-- Flood the /generate-code WebSocket with rapid/malicious input requests,
|         leading to resource exhaustion on the backend.
|
+-- 6. Exploit Debug and Log Handling for Information Disclosure
      [AND]
      +-- Poison or read the log files (written by fs_logging) to leak sensitive
          prompt, key, or model–related information.
```

---

## 4. Node Attributes Summary

Below is a summary table with rough risk–attributes for each node. (These ratings are estimative and meant to guide prioritization.)

| Attack Step                                               | Likelihood | Impact   | Effort    | Skill Level  | Detection Difficulty |
|-----------------------------------------------------------|------------|----------|-----------|--------------|----------------------|
| **1. Exploit Eval Endpoints**                             | Medium     | High     | Low–Med   | Low          | Low                  |
| &nbsp;&nbsp;1.1 Manipulate folder parameter in /evals      | Medium     | High     | Low       | Low          | Low                  |
| &nbsp;&nbsp;1.2 Abuse folder parameters in pairwise evals    | Medium     | High     | Low       | Low          | Low                  |
| **2. Exploit /generate-code Endpoint**                    | Medium     | High     | Medium    | Medium       | Medium               |
| &nbsp;&nbsp;2.1 Prompt Injection Attack                    | Medium     | High     | Medium    | Medium       | Medium               |
| &nbsp;&nbsp;2.2 Malicious Code Payload Injection (XSS)     | Low–Med    | High     | Medium    | Medium       | Medium               |
| **3. Exploit SSRF in /api/screenshot Endpoint**           | Low–Med    | Medium   | Low       | Medium       | Medium               |
| **4. Abuse LLM Integration Vulnerabilities**              | Medium     | High     | Medium    | High         | High                 |
| &nbsp;&nbsp;4.1 Force LLM to reveal sensitive data/code      | Medium     | High     | Medium    | High         | High                 |
| &nbsp;&nbsp;4.2 Disrupt streaming callback processing       | Medium     | High     | Medium    | High         | High                 |
| **5. Denial-of-Service (DoS) via WebSocket Flooding**       | Medium     | Medium   | Low       | Low          | Medium               |
| **6. Exploit Logging Mechanism for Info Disclosure**      | Low        | Medium   | Low       | Low          | High                 |

---

## 5. Mitigation Strategies (Actionable Insights)

For each identified attack path, consider the following countermeasures (tailored to the project’s context):

- **For Eval Endpoints (Node 1):**
  • Validate and sanitize folder and file–related parameters.
  • Restrict file system access to only the designated eval directories.

- **For the Code Generation Endpoint (Node 2):**
  • Rigorously sanitize all inputs that become part of the prompt.
  • Enforce strict output validation on generated HTML before rendering it in clients.
  • Consider “whitelisting” acceptable structures or post–processing generated code.

- **For SSRF in /api/screenshot (Node 3):**
  • Validate the “url” parameter against a list of allowed domains or patterns.
  • Use timeouts and safe defaults when making outbound HTTP calls.

- **For LLM Integration (Node 4):**
  • Harden the prompt–assembly routines (for both system and user parts) so that input data cannot alter critical instructions.
  • Monitor and limit the content of streaming callbacks to detect anomalies.

- **For WebSocket Flooding (Node 5):**
  • Implement rate–limiting on the WebSocket endpoint and enforce quotas per client.

- **For Log–Based Information Leakage (Node 6):**
  • Sanitize logged data and restrict access to log directories.
  • Avoid logging sensitive API keys or detailed prompt contents in production.

---

## 6. Summary of Findings

The “screenshot–to–code” project—though a powerful tool for converting visual designs into deployable code—contains several areas where an attacker could exploit weaknesses intrinsic to its prompt processing, file access logic, and network–based endpoints. In particular:

- Unsanitized query parameters in eval endpoints may allow arbitrary file disclosure.
- The code generation WebSocket endpoint (which handles dynamic prompt assembly for LLMs) is potentially vulnerable to prompt injection and even DoS if flooded.
- The integration with third–party APIs (both for screenshots and LLMs) may be subject to remote request forgery or injection attacks if inputs are not properly validated.
- Finally, any leakage or misuse of logs (or unsanitized generated code) could expose sensitive configuration details or lead to client–side exploits.

Given these risks—and their relatively moderate to high impact—it is critical to add proper validation, sanitization, and rate limiting when deploying this project in environments that are publicly accessible.

---

## 7. Assumptions & Questions

- **Assumptions:**
  • The project is deployed as provided, with minimal additional hardening on the backend endpoints.
  • API keys are expected to be provided by users via settings; however, the project itself does not re–validate these keys once received.
  • The project’s integration with LLM APIs trusts the structure of generated outputs without thorough sanitization.

- **Questions:**
  • Is the evaluation endpoint intended to be accessible by end–users, or only by trusted administrators?
  • What measures (if any) are already in place on deployed instances (e.g. behind authentication or in a private network) that might mitigate some of these file system or WebSocket–based attacks?

---

This attack tree should guide defenders in prioritizing fixes on input validation (both for file system paths and API parameters), prompt integrity in LLM integration, and protections against flooding and log leakage.
