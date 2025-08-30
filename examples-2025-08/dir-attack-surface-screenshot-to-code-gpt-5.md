# Attack Surface Analysis for screenshot-to-code

Below are the key medium, high, and critical attack surfaces that arise from the application’s implementation and configuration observed in the provided project files.

1) Unauthenticated code-generation backend can be abused as a paid-API proxy
- Description:
  - The backend exposes WebSocket and HTTP endpoints without any authentication. If server-side API keys for OpenAI/Anthropic/Replicate are present in the environment, requests from any origin can trigger expensive LLM or image-generation calls.
- How screenshot-to-code contributes:
  - WebSocket /generate-code pipeline uses environment keys when the client does not supply keys (ParameterExtractionStage → _get_from_settings_dialog_or_env). Endpoints exposed publicly, with permissive CORS/WS policy.
  - Image generation also consults REPLICATE_API_KEY if present.
- Example:
  - An attacker connects to /generate-code without providing openAiApiKey or anthropicApiKey. The server uses its OPENAI_API_KEY/ANTHROPIC_API_KEY to satisfy the request, streaming completions to the attacker.
- Impact:
  - Direct financial loss via server-owned paid API usage; resource exhaustion; potential service degradation.
- Risk severity: Critical
- Current mitigations:
  - None for authentication/authorization. The code supports client-provided keys but falls back to server env keys if present.
- Missing mitigations:
  - Require authentication and authorization on all endpoints (JWT/session/API tokens).
  - In hosted/multi-tenant mode, refuse to use server-owned LLM keys for user-triggered generations (enforce “bring your own key” only).
  - Add per-IP and per-account rate limiting/quotas; enforce concurrency limits per connection.
  - Disable image generation in hosted mode unless the caller supplies their own key for Replicate/OpenAI images.

2) OpenAI base URL override enables SSRF and credential exfiltration if misconfigured
- Description:
  - The backend allows clients to set an arbitrary OpenAI base URL when not in production. If the server uses its env OpenAI key (because the client omitted a key) this will send Authorization: Bearer <server key> to attacker-controlled endpoints.
- How screenshot-to-code contributes:
  - ParameterExtractionStage allows openAiBaseURL from client when IS_PROD is false; AsyncOpenAI is instantiated with base_url for both chat and image generation. IS_PROD is parsed incorrectly (string truthiness).
- Example:
  - Attacker sets openAiBaseURL to https://evil.example.com/v1 and omits openAiApiKey; the server uses its env OPENAI_API_KEY, sending requests (with the Authorization header) to the attacker’s server, leaking the key. SSRF to internal addresses (e.g., 169.254.169.254) is also possible if not blocked at the network layer.
- Impact:
  - Credential exfiltration (server OpenAI key); SSRF into internal networks/metadata services; full proxying of model traffic through attacker infrastructure.
- Risk severity: Critical
- Current mitigations:
  - Attempted gating by IS_PROD; however, config uses os.environ.get("IS_PROD", False) without normalization, making any non-empty string truthy and easy to misconfigure across environments. No allowlist of domains.
- Missing mitigations:
  - Parse booleans safely (e.g., strtobool) and default to production-safe behavior.
  - Never accept client-controlled base URLs; if proxying is supported, use a strict server-side allowlist (e.g., only api.openai.com) and block link-local/private IPs.
  - If any server-owned key is in use, forbid base URL override unconditionally.
  - Network egress controls (FW/egress proxy) to block access to metadata endpoints and private address ranges.

3) Overly permissive CORS and WebSocket origin policy facilitate cross-origin abuse
- Description:
  - The backend accepts requests from any origin with credentials allowed, increasing the ease of cross-site abuse and drive-by usage of the backend.
- How screenshot-to-code contributes:
  - CORSMiddleware is configured with allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]. WebSockets are exposed without origin checks.
- Example:
  - A malicious website embeds front-end code that triggers generations against the backend. If the backend uses server env keys (see item 1), the victim’s browser can cause the backend to burn credits without user awareness.
- Impact:
  - Simplifies exploitation of the unauthenticated backend (credit burn, DoS).
- Risk severity: High
- Current mitigations:
  - None; configuration is wide open.
- Missing mitigations:
  - Restrict allowed origins to a known set. Enforce Origin checks on WebSocket handshakes.
  - If credentials are used, set Access-Control-Allow-Origin to explicit domains; disable allow_credentials when using “*”.
  - Consider CSRF tokens if cookies/session auth are introduced.

4) Arbitrary folder read via evals endpoints (exfiltration of .html files)
- Description:
  - Multiple eval endpoints accept arbitrary folder paths and return contents of .html files found in those folders.
- How screenshot-to-code contributes:
  - GET /evals?folder=... opens and returns HTML from any provided directory; /pairwise-evals and /best-of-n-evals accept folder paths too.
- Example:
  - Attacker calls /evals?folder=/var/www to enumerate and read all .html files in that directory; responses include full file contents.
- Impact:
  - Disclosure of arbitrary HTML content on the server filesystem (internal eval results, admin UIs, secrets accidentally stored in .html).
- Risk severity: Medium
- Current mitigations:
  - None (no path restriction or auth on these endpoints).
- Missing mitigations:
  - Restrict to a fixed, server-configured base directory; reject absolute and parent-paths.
  - Require admin authentication/authorization for all eval endpoints or disable them in production.
  - Return only metadata or sampled content; avoid raw file reads.

5) Resource exhaustion via unbounded inputs and parallel model runs
- Description:
  - The service performs computationally expensive tasks (LLM calls, image generation, video frame extraction) without strict input size or concurrency controls.
- How screenshot-to-code contributes:
  - NUM_VARIANTS=4 generates multiple variants in parallel; video mode extracts many frames; image processing accepts large base64 images; no explicit request-size or CPU/memory caps in app layer.
- Example:
  - An attacker repeatedly sends large base64 videos/images and requests 4 variants, causing CPU/memory spikes and external API charges; the server becomes unresponsive.
- Impact:
  - Denial of service; unexpected spend on paid APIs.
- Risk severity: High
- Current mitigations:
  - None evident in the code (no payload size checks, no throttling).
- Missing mitigations:
  - Enforce maximum request body sizes and validate media dimensions/lengths; reject oversize inputs early.
  - Bound concurrency per user/IP; set timeouts and circuit breakers per stage.
  - Queue long-running jobs; isolate heavy work into workers with resource limits.

6) Data leakage from debug artifacts and video frame dumps
- Description:
  - The system writes user data (HTML outputs, “thinking”, extracted video frames) to disk in temp or debug directories.
- How screenshot-to-code contributes:
  - video.utils has DEBUG=True, saving extracted frames to tmp by default; DebugFileWriter writes complete artifacts when IS_DEBUG_ENABLED is set (and parsing IS_DEBUG_ENABLED is also string-truthy).
- Example:
  - Hosted instance processes a user’s screen recording; frames are written to /tmp and remain accessible to operators or other containers sharing the host.
- Impact:
  - Leakage of potentially sensitive user content; increased compliance exposure.
- Risk severity: Medium
- Current mitigations:
  - None (DEBUG=True in code; debug writes gated only by env var presence, which is easy to mis-set).
- Missing mitigations:
  - Set DEBUG=False for video frames; guard all debug/trace writes with robust boolean parsing and default-off.
  - Add retention and secure deletion for temp/debug data; ensure temp paths are not exposed via static serving or volume mounts.
  - Provide a configuration to completely disable disk writes of user artifacts in production.

7) Prompt/completion logging may store sensitive content
- Description:
  - Logs include the full prompt messages and generated HTML, which may embed user-provided base64 images or proprietary content.
- How screenshot-to-code contributes:
  - fs_logging.core.write_logs writes JSON with prompt and completion into run_logs under LOGS_PATH or CWD, without redaction.
- Example:
  - A user uploads a screenshot of internal systems; the base64 image and code are stored on disk. If logs are shipped off-box or mounted to shared volumes, data is exposed.
- Impact:
  - Unauthorized retention and exposure of user data; compliance issues.
- Risk severity: Medium
- Current mitigations:
  - None (always logs first valid completion if any).
- Missing mitigations:
  - Add a production flag to disable logging by default; or implement redaction/sampling/anonymization.
  - Separate debug logs from production; restrict file permissions and destinations.
  - Provide user/tenant-level opt-outs and retention policies.

8) Input parsing bugs allow request-level DoS in update flows
- Description:
  - The update history image cache builder and image replacement assume certain attributes exist and may raise exceptions on malformed inputs from the client.
- How screenshot-to-code contributes:
  - create_alt_url_mapping uses image["src"] and image["alt"] without presence checks; generate_images later dereferences mapping[img.get("alt")] with a non-guarded key. A crafted history payload can trigger exceptions that fail the request or crash a variant post-processing path.
- Example:
  - Client sends history[-2]["text"] with <img> tags lacking alt/src in update mode; backend raises KeyError while assembling prompts or during image generation for variants.
- Impact:
  - Request-level Denial of Service for affected generations; degraded reliability under hostile inputs.
- Risk severity: Medium
- Current mitigations:
  - Some later code paths use .get() defensively, but not all (mapping creation is not defensive).
- Missing mitigations:
  - Harden HTML parsing: always use .get() and validate attributes before access; skip or sanitize malformed tags.
  - Wrap mapping and replacement in try/except with clear error signaling instead of crashing the pipeline.

9) Dev server shipped in Docker Compose (frontend) and open ports encourage unsafe deployments
- Description:
  - The provided Docker setup runs Vite’s dev server (yarn dev --host 0.0.0.0) which is not suitable for production and is exposed on 0.0.0.0:5173; backend also exposed without auth.
- How screenshot-to-code contributes:
  - docker-compose.yml builds and runs this dev setup; no reverse proxy, TLS, or auth are included; invites accidental exposure on public hosts.
- Example:
  - Team deploys docker-compose to a cloud VM as-is; the dev server and backend become internet-accessible with all the risks above.
- Impact:
  - Easy exploitation of items 1–5; information leakage via source maps, hot-reload, etc.
- Risk severity: Medium
- Current mitigations:
  - README cautions that Docker setup isn’t for development rebuilds; no explicit production guidance.
- Missing mitigations:
  - Provide a production Dockerfile/docker-compose with a static build (vite build) behind an HTTP server and locked-down backend; document required envs, TLS, and auth.
  - Default to binding to localhost unless explicitly overridden.

10) Evals orchestration can read and serve arbitrary HTML when given arbitrary folder paths (multiple endpoints)
- Description:
  - Beyond /evals, the /pairwise-evals and /best-of-n-evals endpoints accept folder paths and return HTML outputs from those directories, enabling browsing of server file trees containing .html files.
- How screenshot-to-code contributes:
  - These endpoints enumerate and read .html and serve them in API responses without auth.
- Example:
  - Attacker queries /best-of-n-evals?folder1=/var/www/html&folder2=/home/ubuntu to collect content from both directories.
- Impact:
  - Disclosure of sensitive operational data stored as .html anywhere on the host/container.
- Risk severity: Medium
- Current mitigations:
  - None.
- Missing mitigations:
  - Same as item 4: restrict to a known base path; enforce auth; disable endpoints in production.

Notes on risk interplay
- Items 1, 2, and 3 combine into a particularly dangerous exploitation path: a public, cross-origin-accessible backend that will (a) accept attacker-driven generations; (b) potentially use server-held API keys; and (c) allow attacker-set base URLs in non-production or misconfigured environments, enabling SSRF and key exfiltration.

Recommended prioritization
- P0: Lock down authentication/authorization; remove server-owned LLM keys from request paths for untrusted users; restrict CORS/WS origins; disable base URL override and parse IS_PROD safely.
- P1: Add size/concurrency limits; harden HTML parsing; disable debug/frame dumps; control logging; remove or secure eval endpoints.
- P2: Provide production-grade deployment artifacts; document safe configurations and defaults.
