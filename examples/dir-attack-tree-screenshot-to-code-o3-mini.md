Below is the detailed threat modeling analysis—organized as an attack tree—for the “screenshot‐to‐code” project. This project is an open source tool that converts screenshots, mockups, Figma designs and even video recordings into web application code. It uses a modern stack including a React/Vite front end, a FastAPI backend running under Python with Poetry/Docker support, and integrates several AI models (from OpenAI, Anthropic, Gemini, and even image generation via Replicate) to dynamically generate code.

The analysis below shows how an attacker might compromise systems that use this project by abusing input channels, misconfigurations, insecure credential/key handling, container and API weaknesses, or by inducing harmful behavior through the automated prompt and code generation chain.

────────────────────────────
1. ROOT GOAL

“Compromise systems using the screenshot‐to‐code project by exploiting its weaknesses so as to inject malicious code, exfiltrate sensitive data, or disrupt intended operations.”

────────────────────────────
2. HIGH‐LEVEL ATTACK PATHS

[OR]
+-- A. Prompt Injection and Malicious Code Generation
+-- B. API Key and Credential Exposure
+-- C. WebSocket and Communication Channel Exploitation
+-- D. Docker Deployment and Container Misconfiguration Exploitation
+-- E. SSRF and Malicious URL Injection via the Screenshot API
+-- F. Video-to-App / Image Processing Abuse
+-- G. Evaluation/ File Access Exploitation

────────────────────────────
3. EXPANSION OF ATTACK PATHS

A. Prompt Injection / Malicious Code Generation
   [AND]
   +-- A1. Attacker controls user-supplied inputs (e.g. the “image”, “history” or settings values) submitted from the front end.
   +-- A2. The prompt assembly function (which combines a hard–coded “system” message with a user “image_url” and a text prompt) is manipulated so that malicious payloads are included.
   +-- A3. The chosen LLM (via OpenAI or Anthropic) returns generated code that contains back–doors, script injections, or other malicious modifications which are then served to clients or deployed in production.

B. API Key and Credential Exposure
   [OR]
   +-- B1. API keys (for OpenAI, Anthropic, Gemini, etc.) are provided via environment variables or UI settings; these may be intercepted if transmitted insecurely.
   +-- B2. Excessive “allow_origins” (CORS * in FastAPI) and loose endpoint access may let an attacker read or abuse API keys stored on the server or in browser–local settings.

C. WebSocket Communication Exploitation
   [OR]
   +-- C1. The generated code is streamed via a WebSocket connection that is accepted from any origin—this can be abused by flooding the channel (DoS) or tampering with messages.
   +-- C2. Weak error handling (with custom close codes) may allow injection of malicious “chunk” messages to alter the final delivered code.

D. Docker Deployment / Container Exploitation
   [AND]
   +-- D1. Dockerfiles and docker-compose configurations (which expose ports such as 7001 and 5173 without strong restriction) may be misconfigured.
   +-- D2. The containerized environment (running Python libraries, uvicorn and Node–based tooling) might be exploitable via privilege escalation or container breakout if images or dependencies have unpatched vulnerabilities.

E. SSRF and Malicious URL Injection via Screenshot API
   [AND]
   +-- E1. The /api/screenshot endpoint accepts arbitrary URLs and calls an external screenshot service; an attacker may supply an internal URL or specially crafted URL.
   +-- E2. This can trigger a server–side request forgery (SSRF) attack and lead to sensitive internal resource discovery or unintended API calls.

F. Video-to-App / Image Processing Abuse
   [AND]
   +-- F1. The video-to-code module decodes videos (using moviepy, PIL) without heavy validation; a crafted video file may exhaust CPU/memory (DoS) or cause image library errors (buffer overflow/logic bugs).
   +-- F2. Malformed image data could be injected so that when re–encoded to JPEG the altered payload might lead to further exploitation if downstream consumers execute the generated HTML/JS blindly.

G. Evaluation / File Access Exploitation
   [AND]
   +-- G1. The eval endpoints (e.g. /evals, /pairwise-evals) take folder paths or filenames from parameters; if not fully sanitized, an attacker may force unintended file access (path traversal) or leak sensitive files.
   +-- G2. This also covers manipulation of file–naming schemes in the eval outputs to cause confusion or expose backend logs.

────────────────────────────
4. VISUALIZATION OF THE ATTACK TREE

Root Goal: Compromise systems using screenshot‐to‐code project vulnerabilities
   [OR]
   +-- A. Prompt Injection / Malicious Code Generation
         [AND]
         +-- A1. Control of user input (image URL, history messages, “settings” dialog)
         +-- A2. Manipulation of prompt assembly (unsanitized concatenation of system and user messages)
         +-- A3. Malicious LLM output (backdoor code injection)
   +-- B. API Key and Credential Exposure
         [OR]
         +-- B1. Interception of API keys via insecure transmission or weak browser storage
         +-- B2. Exploitation of open CORS and environment misconfiguration
   +-- C. WebSocket Communication Exploitation
         [OR]
         +-- C1. WebSocket flooding/DoS via uncontrolled connections
         +-- C2. Injection/tampering in streaming messages
   +-- D. Docker Deployment / Container Exploitation
         [AND]
         +-- D1. Misconfigured container/network settings exposing ports and services
         +-- D2. Container escape via vulnerable dependencies or privileged execution
   +-- E. SSRF via Screenshot API Endpoint
         [AND]
         +-- E1. Malicious URL input to /api/screenshot
         +-- E2. SSRF to internal services
   +-- F. Video-to-App / Image Processing Abuse
         [AND]
         +-- F1. Malicious video input causing resource exhaustion or errors
         +-- F2. Exploitation of PIL image processing vulnerabilities
   +-- G. Evaluation / File Access Exploitation
         [AND]
         +-- G1. Manipulation of eval folder/filename parameters for unauthorized file reads
         +-- G2. Exploitation of eval API to access sensitive logs or historical responses

────────────────────────────
5. RISK ATTRIBUTE ASSIGNMENT (per high–level node)

                                Likelihood    Impact    Effort    Skill Level    Detection Difficulty
A. Prompt Injection                Medium      High      Medium       Medium             Medium
B. API Key Exposure                Medium      High      Low          Low                Medium
C. WebSocket Exploitation          Low         Medium    Medium       Medium             Medium
D. Docker Exploitation             Medium      High      Medium       High               High
E. SSRF via Screenshot            Low-Medium   High      Low          Medium             Medium
F. Video-to-App Abuse              Low         Medium    High         High               High
G. Eval/File Access Exploitation   Low         Medium    Low          Low                Low

────────────────────────────
6. MITIGATION STRATEGIES

For each class of threat, the following countermeasures are recommended:

• For Prompt Injection (Path A):
  – Sanitize and validate all user–supplied input (image URLs, “history” messages, settings values).
  – Enforce strict formatting rules when building prompt messages for the LLM.
  – Consider using a whitelist and static templates rather than free–form concatenation.
  – Add logging and anomaly detection on unexpected prompt contents or LLM output.

• For API Key Exposure (Path B):
  – Ensure all API key transmissions occur only over HTTPS/TLS.
  – Do not store sensitive API keys in browser–accessible storage; use secure vaults or server–side abstractions.
  – Limit CORS origins to trusted domains only.
  – Rotate keys periodically and conduct security audits of environment variable exposures.

• For WebSocket Exploitation (Path C):
  – Rate–limit connections and data frames on the WebSocket endpoint.
  – Implement robust error handling and authentication of WebSocket clients.
  – Monitor anomalous behavior in streaming communications.

• For Docker/Container Hardening (Path D):
  – Follow best practices for container security including running as non–root and minimizing exposed ports.
  – Regularly scan container images for vulnerabilities.
  – Use network segmentation and firewall rules to limit external access.

• For SSRF in Screenshot API (Path E):
  – Validate and filter URLs submitted to the screenshot endpoint.
  – Enforce network isolation so that requests cannot reach internal resources.
  – Limit responses and add timeouts on external API calls.

• For Video and Image Processing Abuse (Path F):
  – Impose resource limits (CPU, memory, processing time) on video processing operations.
  – Validate video and image formats and sizes before processing.
  – Use well–maintained libraries and keep them updated.

• For Evaluation/File Access (Path G):
  – Sanitize any folder or file name inputs provided by users.
  – Use secure coding practices (such as avoiding directory traversal) when reading files.
  – Restrict access only to known safe directories.

────────────────────────────
7. SUMMARY OF FINDINGS

Key risks include the potential for an attacker to manipulate the prompt–generation process (Path A) to produce malicious code; exposure or interception of API keys and credentials (Path B) via lax CORS and insecure client–server key handling; and the possibility of container and network misconfiguration (Path D) that could be leveraged for privilege escalation. In addition, endpoints such as the screenshot API (Path E) and video–to–app conversion process (Path F) provide channels by which an attacker might induce unintended behavior or force a denial of service.

The recommended countermeasures focus on careful sanitization and validation of inputs, tightening of API key protection and network policies, hardening of the container deployment, rate limiting and monitoring of streaming communications, and overall adherence to secure coding practices throughout the project.

Addressing the critical nodes—especially in the prompt assembly and API key management—is paramount to reducing the risk that attackers can compromise systems that use the “screenshot-to-code” project.

By applying these mitigations, project maintainers and implementers can significantly lower the attack surface and help ensure that the automated code–generation process is not subverted for malicious ends.

────────────────────────────
End of Threat Modeling Analysis.
