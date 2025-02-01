# Attack Surface Analysis for screenshot-to-code

This document focuses on the digital attack surfaces of screenshot-to-code – an application that converts screenshots, designs, mockups, and videos into functional code via AI models. The system comprises a FastAPI backend (with WebSocket and HTTP endpoints), a React/Vite frontend, Docker/deployment configurations, and integrations with multiple third‑party APIs (OpenAI, Anthropic, Gemini, and Replicate).

---

## Attack Surface Identification

•  **APIs & Endpoints**
 – Backend HTTP endpoints including:
  • /api/screenshot – Accepts external URLs and API keys to capture screenshots (see backend/routes/screenshot.py)
  • /evals, /pairwise-evals, /best-of-n-evals – Endpoints for evaluation and comparison of generated code (see backend/routes/evals.py)
  • /generate-code – A WebSocket endpoint for streaming code generation responses (see backend/routes/generate_code.py)
  • / (home) – A simple status endpoint (see backend/routes/home.py)

•  **WebSocket Channels**
 – /generate-code is used to stream code generation chunks from interactions with integrated LLMs.
 – Custom close codes are defined (e.g., APP_ERROR_WEB_SOCKET_CODE in backend/ws/constants.py)

•  **External Integrations & Third‑Party Services**
 – Multiple LLM integrations via third‑party APIs:
  • OpenAI (GPT-4 variants, GPT‑4O)
  • Anthropic (Claude models)
  • Gemini (via google-genai)
  • Replicate for image generation (“flux-schnell”)
 – These are invoked from modules such as backend/llm.py and backend/image_generation/ (e.g., replicate.py)

•  **Configuration & Secrets**
 – Environment variables defined in .env files and in Docker configurations (docker-compose.yml, backend/pyproject.toml, backend/config.py) carry sensitive API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, REPLICATE_API_KEY)
 – The frontend allows users to input API keys via a settings dialog; keys are then used for comparison between models

•  **Frontend Application**
 – React/Vite based frontend (see frontend/README.md and Dockerfile) that communicates with the backend using HTTP/WebSocket protocols
 – User settings for API keys and backend URL configurations (e.g., VITE_WS_BACKEND_URL), which may affect both functionality and security

•  **Container & Deployment Setup**
 – Dockerfiles for backend and frontend are provided. The use of public base images (e.g., python:3.12.3-slim-bullseye and node:22-bullseye-slim) increases the risk of vulnerabilities if not kept updated

•  **Inter-process Communication & Logging**
 – Communication with external LLM services is performed asynchronously. Logging is implemented (see fs_logging/core.py) to capture request/response data (may include sensitive information if not protected)
 – CORS is configured with "allow_origins=[*]" (in backend/main.py), exposing the API to any origin

---

## Threat Enumeration

Using an approach similar to STRIDE, we identify and outline the following potential threats:

1. **Spoofing**
 – An attacker might impersonate legitimate clients due to the lack of authentication (e.g., no API user authentication on backend endpoints).
  • Entry Points: WebSocket (/generate-code) and HTTP endpoints (/evals, /api/screenshot).
  • Details: Attackers could send forged requests to trigger expensive LLM queries or induce unauthorized code generation.

2. **Tampering**
 – Malicious modification of requests or responses within the system.
  • Entry Points:
   – Manipulated HTTP request data (e.g., supplying crafted URL parameters to /api/screenshot)
   – Altered WebSocket payloads to inject unexpected input into code generation flows.
  • Details: Injection attacks, parameter tampering, or malicious payloads could adversely affect LLM input or output integrity.

3. **Repudiation**
 – Insufficient logging or audit trails may allow clients to deny actions.
  • Entry Points: Logging mechanisms (fs_logging/core.py) and API request records.
  • Details: Lack of robust authentication and request identification complicates non‑repudiation.

4. **Information Disclosure**
 – Exposure of sensitive data such as API keys or generated source code.
  • Entry Points:
   – Environment configurations (e.g., .env variables, settings transmitted from frontend to backend)
   – Overly permissive CORS configuration.
  • Details: Insecure transport or logging practices may inadvertently reveal API keys or internal code, risking financial and operational data.

5. **Denial of Service (DoS)**
 – Exhaustion of system resources or abuse of expensive external APIs from unauthenticated, high‑rate requests.
  • Entry Points:  – Publicly exposed endpoints (/generate-code, /evals, /api/screenshot).
  • Details: An attacker can flood the system with requests causing service degradation, high costs (from third‑party API calls), and potential unavailability.

6. **Elevation of Privilege**
 – Exploitation of backend or container vulnerabilities could result in unauthorized access to system resources or broader network compromise.
  • Entry Points:
   – Docker containers and underlying host OS (if base images or third‑party libraries are exploited).
  • Details: A successful container breakout could lead to complete system compromise.

---

## Impact Assessment

1. **Spoofing**
 – *Confidentiality:* Medium to High – If attackers misuse API keys or impersonate legitimate users, sensitive operations may be initiated.
 – *Integrity:* Medium – Unauthorized code generation may inject malicious code.
 – *Availability:* Medium – Attackers can overload the system.
 • **Severity:** High due to potential financial and operational consequences.

2. **Tampering**
 – *Confidentiality:* Medium – Tampered messages might leak sensitive internal state.
 – *Integrity:* High – Incorrect or malicious code outputs may be generated, affecting system behavior.
 – *Availability:* Medium – Manipulated payloads could crash services.
 • **Severity:** High when it affects the core functionality.

3. **Repudiation**
 – *Confidentiality:* Low – Doesn’t directly expose data.
 – *Integrity:* Medium – Lack of audit trails affects accountability.
 – *Availability:* Low – Limited impact on service uptime.
 • **Severity:** Medium, particularly in forensic investigations.

4. **Information Disclosure**
 – *Confidentiality:* Critical – Exposure of API keys and internal code can lead to further attacks or financial loss (e.g., excessive billing on LLM services).
 – *Integrity:* Medium – Leaked data might be used to craft more sophisticated attacks.
 – *Availability:* Low to Medium – Indirectly, through misuse of credentials leading to abuse.
 • **Severity:** Critical.

5. **Denial of Service (DoS)**
 – *Confidentiality:* Low – Not directly affecting data secrecy.
 – *Integrity:* Low – Service content remains unchanged, though availability is compromised.
 – *Availability:* Critical – Disrupts service, leading to potential financial loss and user dissatisfaction.
 • **Severity:** Critical.

6. **Elevation of Privilege**
 – *Confidentiality:* Critical – Full system compromise could expose all data.
 – *Integrity:* Critical – Unauthorized modifications to system components.
 – *Availability:* Critical – Complete shutdown or misuse of system resources.
 • **Severity:** Critical.

---

## Threat Ranking

1. **Critical Threats:**
 – **Information Disclosure:** Misconfigured environment variables, permissive CORS, and insecure logging can expose API keys and sensitive operational details.
 – **Denial of Service (DoS):** Unauthenticated endpoints can be flooded, causing service outages and high operational costs.
 – **Elevation of Privilege:** Exploitable vulnerabilities in underlying containers or dependencies could result in complete system compromise.

2. **High Threats:**
 – **Spoofing:** Lack of authentication can allow attackers to impersonate users and abuse the system.
 – **Tampering:** Manipulated requests can corrupt code generation outputs and undermine system integrity.

3. **Medium Threats:**
 – **Repudiation:** Although important for audit trails, its impact is less immediate on system availability or integrity compared to other threats.

---

## Mitigation Recommendations

1. **Authentication & Access Control:**
 – Implement robust authentication on API endpoints and WebSocket connections. Use tokens or API keys for client verification before processing requests.
 – Apply role‑based access controls (RBAC) to restrict access to sensitive operations.

2. **Input Validation & Sanitization:**
 – Rigorously validate and sanitize all user‑provided inputs (URLs, settings) to prevent injection and tampering attacks.
 – Use schema validation for incoming JSON and sanitize text-based inputs before processing.

3. **CORS & Communication Security:**
 – Replace the overly permissive CORS policy (allow_origins=["*"]) with a whitelist of trusted domains.
 – Ensure all communications occur over TLS/HTTPS to protect data in transit.

4. **Rate Limiting & Throttling:**
 – Introduce rate-limiting mechanisms on public endpoints (HTTP and WebSocket) to mitigate DoS attacks and resource exhaustion.
 – Monitor request patterns and throttle abnormal client behavior.

5. **Secrets Management:**
 – Secure storage of API keys and environment variables (e.g., using secret management tools).
 – Avoid exposing sensitive keys in frontend code; consider server‑side key management and proxying of requests.

6. **Logging, Monitoring & Audit Trails:**
 – Strengthen logging mechanisms to capture robust audit logs while ensuring that sensitive data is redacted.
 – Integrate real‑time monitoring and alerting for abnormal activities (e.g., spikes in API requests, unusual error rates).

7. **Container & Dependency Security:**
 – Regularly update base images and software dependencies to patch known vulnerabilities.
 – Use container hardening techniques (minimal privileges, read‑only filesystems) and perform security scans on Docker images.

8. **Third‑Party API Integration Safeguards:**
 – Validate responses from external APIs and implement fallbacks if responses deviate from expected schemas.
 – Enforce authentication with third‑party services and monitor API usage closely to detect abuse.

---

## QUESTIONS & ASSUMPTIONS

•  **Questions:**
 – Are communications between the frontend and backend always secured via TLS/HTTPS in production?
 – Is there an existing plan for authenticating API requests, or is the system intended mainly for internal use?
 – How are sensitive logs managed and stored to ensure that API keys and secret tokens are not leaked?
 – What is the current process for monitoring external API usage to mitigate potential financial abuse?

•  **Assumptions:**
 – The system is assumed to be deployed in an environment where HTTPS is enforced in production, even though the code defaults to permissive CORS.
 – User inputs and settings (such as API keys) provided via the frontend are assumed to be transmitted securely even if not currently authenticated.
 – Docker/container security configurations follow best practices in production deployments, but the current public base images require regular audits.
 – The primary focus of the threat model is on digital vectors; human and physical security aspects are out‑of‑scope.

---

By addressing these threats with appropriate technical controls, the screenshot-to-code project can significantly reduce its digital attack surface while delivering its innovative code-generation capabilities securely.
