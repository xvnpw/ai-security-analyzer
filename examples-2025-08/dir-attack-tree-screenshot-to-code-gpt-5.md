# Threat Modeling Analysis for screenshot-to-code Using Attack Trees

## 1. Understand the Project

Project Name: screenshot-to-code

Overview
- A React/Vite frontend + FastAPI backend tool that converts screenshots, mockups, and Figma designs (and experimental video) to functional code using AI (OpenAI, Anthropic, Gemini). It can generate multiple variants in parallel and optionally generate images via OpenAI DALL·E 3 or Replicate Flux.
- Users can run a local/deployed backend and a local frontend or a hosted version. Users may provide API keys through environment variables or via the frontend UI (sent to backend over WebSocket).

Key Components and Features
- Backend (FastAPI):
  - WebSocket endpoint /generate-code: orchestrates prompt assembly, model selection, parallel code generation (variants), optional image generation, streaming results to client.
  - HTTP API endpoints for evals (/evals, /pairwise-evals, /best-of-n-evals, /output_folders), screenshot capture proxy (/api/screenshot).
  - Logging prompts/completions to disk (fs_logging).
  - Video processing pipeline that splits video frames and builds prompt data for Claude.
  - CORS middleware configured with allow_origins ["*"], allow_credentials True, allow_methods ["*"], allow_headers ["*"].
- Frontend (React/Vite):
  - WebSocket client that sends params: generatedCodeConfig, inputMode, keys (optional), generationType, prompt, history, etc.
  - Variants UI with non-blocking completion flow.

Dependencies
- FastAPI, uvicorn, websockets, openai, anthropic, google-genai, aiohttp/httpx, BeautifulSoup, Pillow, moviepy, etc.
- Optional: Replicate API for Flux Schnell.

## 2. Define the Root Goal of the Attack Tree

Attacker’s Ultimate Objective:
Compromise systems that run screenshot-to-code by exploiting weaknesses in its code and configuration to exfiltrate provider API keys, abuse paid resources, or exfiltrate local files.

## 3. Identify High-Level Attack Paths (Sub-Goals)

- A. Exfiltrate API keys or redirect model traffic (SSRF/key theft) via client-controlled OpenAI base URL and unauthenticated WebSocket.
- B. Abuse unauthenticated generation endpoints to burn API credits and degrade service (cost DoS/compute DoS).
- C. Read arbitrary server files (that match .html) via evals endpoints’ unbounded folder path parameters.
- D. Cross-site WebSocket/CORS exposure enabling remote pages to drive local backends and consume secrets/resources.
- E. Sensitive prompt/image leakage to local disk through logging/debug paths that may later be exposed or mishandled.

## 4. Expand Each Attack Path with Detailed Steps

A. Exfiltrate API keys via client-controlled base URL (OpenAI) and unauthenticated WS
- A1. Connect to ws://<host>:7001/generate-code (no auth).
- A2. Send params omitting openAiApiKey so backend uses env OPENAI_API_KEY (ParameterExtractionStage._get_from_settings_dialog_or_env).
- A3. Provide openAiBaseURL in params (allowed when IS_PROD is falsey or mis-set), e.g., attacker-controlled https://evil.tld/v1.
- A4. ModelSelection selects OpenAI model; AsyncOpenAI uses base_url and Authorization: Bearer <server OPENAI_API_KEY>.
- A5. Attacker’s server receives the request and captures the key (or traffic).

B. Abuse generation to burn credits / DoS
- B1. Direct abuse: Repeatedly connect to /generate-code and request large/parallel generations (NUM_VARIANTS=4, image generation enabled, long prompts, multiple models).
- B2. Cross-site driving: Host a web page that initiates WebSocket connections from victims’ browsers to their local backend (if running) and drives generations with their env or UI-provided keys.
- B3. Video payload DoS: Send very large data:video/* base64 to trigger heavy processing via moviepy/ffmpeg, frame extraction (TARGET_NUM_SCREENSHOTS up to 20), CPU and disk pressure.

C. Arbitrary .html file read via evals endpoints
- C1. Call GET /evals?folder=/absolute/path (no auth, no path restriction).
- C2. Server lists *.html in that folder and returns file contents as outputs.
- C3. Similar with /pairwise-evals (folder1, folder2) and /best-of-n-evals (folderN) to exfiltrate multiple folders’ .html files.

D. Cross-site exposure due to permissive CORS and missing WS origin checks
- D1. CORS configured as allow_origins ["*"], allow_credentials True (insecure combination).
- D2. WebSocket does not validate Origin. Remote web pages can connect to a user’s local backend and operate it (CSWSH).
- D3. If local backend holds env keys or UI-stored keys, attacker can trigger generations and costs; they also receive streamed content in the page context.

E. Sensitive prompt/image leakage to disk
- E1. PostProcessing writes prompt_messages and first completion to run_logs (write_logs), containing base64 images and user inputs.
- E2. When IS_DEBUG_ENABLED is set (truthy by any value) DebugFileWriter writes “thinking” and HTML artifacts to DEBUG_DIR/<uuid>.
- E3. If logs are stored in exposed volumes or later served, sensitive data may be disclosed. If combined with any future file-reading bug targeting those paths, leakage increases.

## 5. Visualize the Attack Tree

Root Goal: Compromise systems using screenshot-to-code (exfiltrate secrets, abuse paid APIs, or exfiltrate local files)

[OR]
+-- A. Exfiltrate API keys via base URL injection and unauth WS
    [AND]
    +-- A1. Connect to /generate-code WebSocket (no auth)
    +-- A2. Omit openAiApiKey to force env key usage
    +-- A3. Provide attacker-controlled openAiBaseURL (allowed in non-prod)
    +-- A4. Trigger OpenAI model path so server sends Authorization to attacker URL
    +-- A5. Capture key on attacker server

+-- B. Abuse generation to burn credits / DoS
    [OR]
    +-- B1. Direct unauth WS spam to /generate-code
    +-- B2. Cross-site WS from victim browser to local backend
    +-- B3. Send oversized video data URL to force CPU/memory/disk work

+-- C. Arbitrary .html file read via evals APIs
    [AND]
    +-- C1. Call /evals or /pairwise-evals with arbitrary folder paths
    +-- C2. Server reads *.html and returns content
    +-- C3. Receive file contents (potentially sensitive HTML)

+-- D. Cross-site exposure via permissive CORS/WS
    [AND]
    +-- D1. CORS allow_origins ["*"], allow_credentials True
    +-- D2. WS lacks Origin validation
    +-- D3. Remote page drives local backend with user’s keys/resources

+-- E. Sensitive data written to disk
    [OR]
    +-- E1. write_logs stores prompts/completions with base64 images
    +-- E2. DebugFileWriter writes artifacts when IS_DEBUG_ENABLED truthy
    +-- E3. Later exposure of those files (ops/process error or future bug)

## 6. Assign Attributes to Each Node

Scales: Likelihood (Low/Med/High), Impact (Low/Med/High/Critical), Effort (Low/Med/High), Skill (Low/Med/High), Detection Difficulty (Low/Med/High)

- A. Exfiltrate API keys
  - Likelihood: High (default dev allows base URL; no auth)
  - Impact: Critical (long-lived API key theft)
  - Effort: Low-Med (basic WS client + listener server)
  - Skill: Med
  - Detection: High (looks like normal traffic unless base URL logged)

  - A1–A5 combined are required [AND]. Each individual step: Likelihood High; Effort Low.

- B. Abuse generation / DoS
  - B1 Direct WS spam: Likelihood High; Impact High; Effort Low; Skill Low; Detection Med
  - B2 Cross-site WS: Likelihood Med-High; Impact High; Effort Low; Skill Med; Detection Med
  - B3 Video payload DoS: Likelihood Med; Impact High; Effort Med; Skill Med; Detection Med-High

- C. Arbitrary .html file read
  - Likelihood: Med (requires .html present in target dirs)
  - Impact: Med (HTML-only; could expose reports, admin UIs, secrets if embedded)
  - Effort: Low
  - Skill: Low
  - Detection: Low-Med (just a GET with path string)

- D. Cross-site exposure (CORS/WS)
  - Likelihood: High (permissive defaults)
  - Impact: High (enables B2 and remote operation)
  - Effort: Low
  - Skill: Low
  - Detection: Med

- E. Sensitive data to disk
  - Likelihood: Med-High (logging enabled by default; debug gate is lax)
  - Impact: Med-High (PII/images/prompts)
  - Effort: Low
  - Skill: Low
  - Detection: Low (local side effect)

## 7. Analyze and Prioritize Attack Paths

High-Risk, High-Impact (Top Priorities)
- A. API key exfiltration via openAiBaseURL over unauth WS (Justification: straightforward to execute in default dev configuration; yields direct credential theft with critical blast radius).
- B1/B2. Unauthenticated WS abuse and cross-site WS driving (Justification: trivial exploitation; direct monetary/resource impact; can be mounted at scale).
- D. Permissive CORS/WS origin policy enabling cross-site control (Justification: multiplies remote attack surface; enables B2).

Medium Risk
- C. Arbitrary .html file read (constrained to .html; still data leakage).
- B3. Video payload DoS (resource drains; situational).
- E. Sensitive log/debug artifacts (impact depends on where logs end up).

Critical Nodes Mitigating Multiple Paths
- WS authentication and origin validation (cuts A, B1, B2, D).
- Removing/strictly allowlisting client-supplied openAiBaseURL (cuts A).
- Path restriction/allowlist for evals folder parameters (cuts C).
- Boolean env parsing correctness for IS_PROD/IS_DEBUG_ENABLED/MOCK (reduces unexpected exposures).

## 8. Develop Mitigation Strategies (Project-Specific)

Address A: API key exfiltration via openAiBaseURL
- Remove openAiBaseURL from client-controlled params, or:
  - Only allow known-safe domains via strict allowlist (e.g., https://api.openai.com).
  - If a custom base URL must be supported, require explicit server-side config (env/allowlist), never client-provided over WS.
- Ensure the server never uses env OPENAI_API_KEY when a client also provides a custom base URL; require both to originate from the same trusted configuration source (server-side).
- Fix IS_PROD parsing to strict boolean: IS_PROD = os.getenv("IS_PROD", "false").lower() == "true" and do the same for MOCK/IS_DEBUG_ENABLED (note TODO already in config).
- Add per-request guardrails to reject non-HTTPS base URLs and private address ranges (block 127.0.0.0/8, 169.254.0.0/16, RFC1918, link-local).

Address B/D: WS abuse and cross-site control
- Require an auth token for all WS and HTTP endpoints (e.g., server-side configured API key/bearer token checked in the first WS message).
- Validate WebSocket Origin header and optionally the Host header; deny if not in an allowed list.
- Bind backend to localhost by default for dev; make explicit opt-in to bind 0.0.0.0.
- Introduce server-side rate limiting / connection caps per IP for WS and a max concurrent generations guard; short-circuit abusive sessions.
- Enforce hard caps:
  - Max NUM_VARIANTS per request (and on server side, not just config).
  - Max prompt/history size (bytes), max streaming duration, max image generation count.
  - Disable should_generate_images by default unless explicitly enabled on the server.

Address C: Arbitrary folder reads via evals endpoints
- Restrict folder inputs to subpaths of a known root (e.g., EVALS_DIR/results) with strict path normalization and checks (no absolute paths, no “..”).
- Alternatively, replace free-form folder parameters with server-enumerated IDs returned by /output_folders.

Address E: Sensitive data persistence
- Default write_logs off unless LOGS_PATH is explicitly set to a safe, non-public path; add a server config guard to disable logging in production.
- Redact/strip base64 images from logs or store pointers only.
- Debug artifacts behind IS_DEBUG_ENABLED should default false; fix boolean parsing to avoid truthy misconfigurations. Consider adding a runtime banner when enabled.

Other focused hardening in code paths
- Video mode: enforce a maximum video data URL byte-size before decoding; reject with a clear error. Consider disabling in multi-tenant environments by default.
- CORS: Do not use allow_origins ["*"] with allow_credentials True. Set explicit origins and set allow_credentials appropriately.

## 9. Summarize Findings

Key Risks Identified
- Critical: API key exfiltration via client-controlled OpenAI base URL parameter and unauthenticated WebSocket.
- High: Unauthenticated WebSocket enabling cost DoS and remote control, compounded by permissive CORS and missing WS Origin checks.
- Medium: Arbitrary .html file reads via evals folder parameters.
- Medium: Sensitive prompt/image logging and debug artifacts written to disk.
- Medium: Resource DoS via oversized video inputs.

Recommended Actions (most to least urgent)
- Enforce WS authentication and Origin checks; bind to localhost by default in dev.
- Remove or strictly allowlist openAiBaseURL; fix boolean env parsing for IS_PROD/MOCK/IS_DEBUG_ENABLED.
- Add hard caps and rate limits for generations (NUM_VARIANTS, prompt sizes, durations) and disable image generation by default.
- Restrict evals folder parameters to a fixed root with path validation or server-enumerated choices.
- Redact or disable prompt/completion logging by default; make debug artifacts opt-in and obvious.

## 10. Questions & Assumptions

Questions
- Is openAiBaseURL truly required for end-users, or can it be removed and replaced with server-only configuration?
- Should the project provide a built-in lightweight auth (static token) for dev to reduce accidental exposure?
- Are evals endpoints intended for unauthenticated public environments, or only for local usage?
- What is the intended default binding (0.0.0.0 vs localhost) for backend in dev and docker-compose?

Assumptions
- Many users will run the backend on a laptop/workstation with env keys set and 0.0.0.0 binding (as per Docker default), making WS unauthenticated access feasible.
- The hosted version sets IS_PROD correctly and may disable client-specified base URLs; the local/dev default remains permissive.
- The attacker can reach the backend over the network or induce the victim browser to connect to localhost via WS.
