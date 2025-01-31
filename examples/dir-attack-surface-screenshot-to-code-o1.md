# Attack Surface Analysis for "screenshot-to-code"

This threat model focuses exclusively on software and network-facing (digital) risks. It excludes human and physical attack vectors.

---

## Attack Surface Identification

Below are the main digital assets, components, and entry points observed in "screenshot-to-code" based on the PROJECT FILES:

1. Front-End (React/Vite)
   - Serves the client user interface on port 5173 (by default).
   - Exposes a React-based web application that communicates with the backend over HTTP and WebSocket.
   - Potential user inputs enabling advanced code generation, screenshot requests, and AI parameter configuration.
   - Implementation references:
     - "frontend/Dockerfile" (build definitions)
     - "frontend/.env.local" (optional environment variables controlling API endpoints)

2. Back-End (FastAPI)
   - Accessible on port 7001 (by default) or via Docker Compose.
   - Contains multiple endpoints and routes, including:
     - /generate-code (WebSocket) for streaming AI code generation results
     - /api/screenshot (POST) for capturing screenshots of user-supplied URLs
     - /evals for evaluating AI outputs internally
     - Additional routes for image generation, logging, and debugging
   - Implementation references:
     - "backend/main.py" (app initialization)
     - "backend/routes/*.py" (endpoints for screenshot, code generation, etc.)
     - "docker-compose.yml" (exposes the service on port 7001)

3. WebSocket Communication & HTTP APIs
   - WebSocket at /generate-code for real-time streaming of code generation results.
   - Regular HTTP routes (e.g., GET/POST) to capture screenshots, run model evaluations, fetch logs, etc.
   - Implementation references:
     - "backend/routes/generate_code.py" (WebSocket code generation)
     - "backend/routes/screenshot.py" (screenshot capturing API)

4. External AI Integrations
   - OpenAI API (GPT-4 / GPT-4o, etc.)
   - Anthropic API (Claude 3 variants)
   - Replicate API (Flux Schnell for image generation)
   - Google Gemini (optional)
   - Keys and endpoints are stored in environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, REPLICATE_API_KEY, GEMINI_API_KEY).
   - Implementation references:
     - "backend/config.py" (environment variable usage)
     - "backend/llm.py" and "mock_llm.py" (LLM streaming logic / fallback mock)
     - "backend/image_generation/*.py" (integration with replicate or DALL·E)

5. Containerization & Deployment
   - Dockerfiles for both backend (Python) and frontend (Node).
   - docker-compose.yml binding ports to the host system. Potential surface for misconfigurations or unprotected local deployments.
   - Implementation references:
     - "backend/Dockerfile"
     - "frontend/Dockerfile"
     - "docker-compose.yml"

6. Environment & Configuration Files
   - .env files in both root and subdirectories storing or referencing secrets (OpenAI, Anthropic keys, etc.).
   - Potential for secrets leakage if environment files or logs are inadvertently exposed.
   - Implementation references:
     - ".env" (root)
     - "backend/.env" usage
     - "frontend/.env.local"

7. Screenshot Feature & Video-to-Code Processing
   - Accepts user-supplied URLs and video data for generating screenshots or converting videos into code prototypes.
   - Possible risk of SSRF or malicious payload if not properly validated.
   - Implementation references:
     - "backend/routes/screenshot.py" (external calls to screenshot services)
     - "backend/video_to_app.py" / "video/utils.py" (video frame extraction and AI prompt generation)

### Potential Vulnerabilities or Insecure Configurations

- Handling untrusted user input (URLs, text prompts, code generation instructions) without sufficient validation.
- SSRF possibilities in the screenshot capturing route.
- Misuse or exposure of environment variables (API keys) if logs or .env files are not protected.
- Threats of injection into AI prompts or malicious payload injection via code generation.
- WebSocket endpoints lacking robust authentication or rate-limiting.
- Potential Docker misconfigurations exposing ports to the internet by default.

---

## Threat Enumeration

Using a STRIDE-like model, below are a subset of possible threats:

1. Spoofing (S)
   - Attackers might impersonate authorized users or the front-end client to call the backend WebSocket or screenshot endpoints.
   - Attackers could supply forged or malicious data to AI endpoints under a spoofed identity.

2. Tampering (T)
   - Tampering with AI prompts or request bodies to produce unauthorized code or manipulate screenshot results.
   - Tampering with environment variables in container deployments if the Docker or .env scope is insecure.

3. Repudiation (R)
   - Lack of authentication or robust logging may hinder forensic analysis or allow threat actors to deny actions (e.g., generating malicious code or conducting unauthorized screenshots).
   - Logging is partially present but might be insufficient if not integrated with an audit trail.

4. Information Disclosure (I)
   - Potential environment variable leakage, particularly if error logs or debug endpoints inadvertently expose secrets.
   - The screenshot route or additional external calls could leak internal IP addresses or system info (SSRF scenario).
   - The mocking features or debug logs might inadvertently reveal sensitive dev/test data.

5. Denial of Service (D)
   - Attackers can spam /generate-code or /screenshot routes with large or complex tasks (high concurrency, large media files, etc.), draining system or API usage limits.
   - Overuse of external AI calls can exhaust monthly cost or rate limits, effectively causing partial service denial.

6. Elevation of Privilege (E)
   - If the container or processes run as root or with elevated privileges, a container breakout could lead to broader system compromise.
   - Insecure code generation or injection vulnerabilities might allow an attacker to run arbitrary commands if the code is subsequently executed in a trusting environment.

Mapping Each Threat to Components:

- SSRF / URL-based threats: (Screenshot Route, "backend/routes/screenshot.py").
- AI prompt injection / Malicious code generation: (WebSocket route /generate-code, "backend/routes/generate_code.py").
- Secrets leakage: (Docker Compose, environment files, logging in "backend/fs_logging" or "debugFileWriter").
- DDoS or resource exhaustion: (All external endpoints / WebSocket / Docker environment).
- Unauthorized container or host-level compromise: (Docker, host system if run as root).

---

## Impact Assessment

Potential impacts focus on Confidentiality, Integrity, and Availability:

1. Confidentiality
   - Unsecured environment variables or logs can lead to exposure of privileged API keys for OpenAI, Anthropic, replicate, etc.
   - SSRF or manipulated screenshot requests could reveal internal network details.

2. Integrity
   - Attackers tampering with AI prompts could produce harmful or malicious code, which would degrade user trust or inject vulnerabilities.
   - Malicious use of environment variables or Docker misconfiguration can lead to unauthorized code or container modifications.

3. Availability
   - High-volume abuse of the screenshot or code-generation features could exhaust API rate limits or cause resource exhaustion, leading to partial or total service disruption.
   - If the container or host is forced to process large unvalidated payloads, it can degrade performance or crash.

Severity (High, Medium, Low):

- High-impact threats:
  - Leakage of environment secrets (keys) enabling attacker to run indefinite AI requests or impersonate system.
  - SSRF enabling broader internal compromise or scanning.
  - Container breakout or malicious code inject leading to system-wide compromise.

- Medium-impact threats:
  - DOS through repeated code generation or screenshot tasks.
  - Insecure WebSocket usage leading to spam or partial service disruption.

- Low-impact threats:
  - Minor usage of AI credits or config spoofs without broad system compromise.
  - Superficial repudiation issues if partial logs exist but do not hamper overall security.

---

## Threat Ranking

Below is a high-level prioritization (from highest priority to lower) based on likelihood and impact:

1. SSRF / Malicious External Request (High)
   - Likely feasible if the screenshot endpoint does not sanitize or validate URLs.
   - Potentially severe, enabling attackers to pivot into the internal network or leak data.

2. Secrets Leakage & Key Misuse (High)
   - Direct compromise or accidental leaks in logs / .env.
   - Adversary can run up charges or impersonate the service to external AI providers.

3. Injection in AI Prompts / Code Gen (Medium)
   - Could produce harmful or obfuscated code, degrade user trust, or facilitate further attacks.
   - Severity depends on how the code is consumed (if automatically executed or only stored).

4. DoS via Excessive AI or Screenshot Calls (Medium)
   - Repeated calls can lead to cost blowouts, rate-limit exhaustion, or high server CPU usage.

5. Unauthenticated or Weakly Authenticated Endpoints (Medium)
   - Allows unauthorized parties to invoke screenshot or generation APIs.
   - Could enable repeated malicious usage or degrade system performance.

6. Container Misconfigurations (Low-Medium)
   - If Docker runs as root or insecure volumes are mapped, can escalate attack to the host.
   - Typically less likely if Docker best practices are followed.

---

## Mitigation Recommendations

1. URL Validation & SSRF Protections (Addresses SSRF Threat)
   - Strictly validate or whitelist domains for screenshots.
   - Add timeouts, domain filtering, or SSRF proxy with restricted egress.

2. Secure Secrets Management (Addresses Key Leakage Threat)
   - Store keys and .env securely (e.g., AWS SSM, Vault, or Docker secrets).
   - Avoid checking .env into Git repositories or logs.
   - Restrict who can read environment variables at runtime.

3. Require Strong Authentication & Rate Limiting (Addresses DoS & Unauthorized Access)
   - Token-based or session-based auth for WebSocket endpoints and screenshot routes.
   - Enforce rate limits to block high-frequency calls or large malicious payloads.

4. Input Sanitization & Prompt Injection Controls (Addresses AI Prompt Injection)
   - Sanitize user-supplied text that feeds into AI to reduce injection surprises.
   - Possibly restrict certain token sequences or embed safe wrappers in prompts.

5. Logging & Monitoring (Addresses Repudiation, Forensics, and Unusual Activity)
   - Log critical actions, especially screenshot calls and code-generation usage.
   - Monitor usage metrics for anomaly detection (sudden spikes in usage or suspicious requests).
   - Keep logs secure and sanitized (no secrets).

6. Docker Hardening (Addresses Container Attack Surface)
   - Run containers with a non-root user.
   - Limit container privileges (using read-only file systems, restricting volume mounts, etc.).
   - Avoid exposing ports externally unless strictly needed.

7. Implement Quotas / Billing Alerts (Addresses AI Cost and Potential DoS)
   - Configure the external AI providers (OpenAI, Anthropic, replicate) with usage limits or billing alerts.
   - Display a user-friendly error if daily/weekly usage is exceeded.

8. WebSocket Security Best Practices (Addresses Spoofing, DoS)
   - Validate client authentication or tokens before establishing a streaming session.
   - Implement graceful disconnection and error handling under load or suspicious patterns.

---

## QUESTIONS & ASSUMPTIONS

1. Authentication & Authorization:
   - Assumption: Currently minimal or no authentication is enforced between frontend and backend. Are additional user-level authentication or gating mechanisms planned?

2. Production vs. Development Mode:
   - Which environment is used in production, and are debug flags (MOCK, IS_DEBUG_ENABLED) safely disabled or not publicly accessible?

3. Domain Restrictions for AI Endpoints:
   - Are only official OpenAI / Anthropic / replicate domains used? Or do we rely on user-supplied base URLs?

4. Payment / Billing Controls for AI Access:
   - Are usage spikes or unlimited usage possible? Should the system perform usage counting or capping?

5. Logging & PII:
   - Does any user input potentially contain PII or sensitive data? Are there data protection obligations?

Assumptions are that the system is not automatically executing the code returned by AI. If that changes, the severity of injection threats would rise substantially.

---

End of Threat Model.
