# APPLICATION THREAT MODEL

## ASSETS
- API credentials
  - Env-based: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, REPLICATE_API_KEY
  - Client-supplied: openAiApiKey, anthropicApiKey, openAiBaseURL (when allowed)
- User inputs
  - Images and videos as base64 data URLs
  - Text prompts and update histories
  - ScreenshotOne API key passed via /api/screenshot
- Generated artifacts
  - Generated HTML/JS/CSS code variants
  - Generated image URLs (DALL·E 3 or Replicate), image cache mappings
- Logs and debug artifacts
  - run_logs/messages_*.json with prompt messages and completion
  - Debug artifacts in DEBUG_DIR and video frames saved to OS temp
  - Evals outputs under backend/evals_data/outputs and results folders
- File system paths
  - Any folder paths passed to evals endpoints (when not restricted)
- Service quotas/billing
  - Upstream LLM and image generation usage tied to API keys

## TRUST BOUNDARIES
- Browser/client to backend FastAPI over HTTP and WebSocket
- Backend to third-party model providers (OpenAI, Anthropic, Google GenAI)
- Backend to third-party image generation providers (OpenAI images, Replicate)
- Backend to third-party screenshot provider (ScreenshotOne)
- Backend process to local filesystem (logs, evals data, temp/debug dirs)
- Client-provided base URL for OpenAI (only when IS_PROD is not set truthy)
- Environment variable ingestion into the running process and Docker images

## DATA FLOWS
- WebSocket /generate-code
  - Client sends config, keys, prompt, history → Backend assembles prompts and streams code back
  - Crosses client/backend boundary
- HTTP /api/screenshot
  - Client posts URL and ScreenshotOne key → Backend calls ScreenshotOne → Returns base64 image
  - Crosses client/backend and backend/third-party boundaries
- Evals APIs (/eval_input_files, /evals, /pairwise-evals, /best-of-n-evals, /run_evals, /output_folders)
  - Client reads/writes evals results; in some endpoints, client supplies arbitrary folder paths
  - Crosses client/backend and backend/filesystem boundaries
- Image generation
  - Backend parses generated code, creates prompts from alt text, calls OpenAI Images or Replicate
  - Crosses backend/third-party boundary
- Logging
  - Backend writes prompt messages (including base64 images) and a completion to disk
  - Crosses backend/filesystem boundary

Data flows crossing trust boundaries are flagged above.

## APPLICATION THREATS
- Arbitrary file read via evals endpoints
  - Description: /evals, /pairwise-evals, and /best-of-n-evals accept folder paths and read .html files from those folders, returning content to the caller. An attacker can supply arbitrary absolute paths to read HTML files from anywhere the process can access.
  - Impact: Disclosure of sensitive server files with .html suffix; reconnaissance of server directory structure; potential leakage of generated artifacts not intended for exposure.
  - Affected components: backend/routes/evals.py (get_evals, get_pairwise_evals, get_best_of_n_evals)
  - Current mitigations: None. Only checks existence of provided folder path; no confinement to an allowlisted base directory.
  - Missing mitigations: Restrict paths to subdirectories of EVALS_DIR; reject absolute paths; canonicalize and validate; add server-side configuration to disable these endpoints in non-dev; require auth for these endpoints.
  - Risk severity: High

- Unauthenticated credit drain and abuse of hosted keys
  - Description: With CORS wide open and no auth everywhere, a third party can call /generate-code or /run_evals from any origin to force the backend to use environment API keys (if present) when the client does not supply keys, or to drive high-cost workloads with their own keys while leveraging your compute.
  - Impact: Financial loss due to API usage; denial of service by resource exhaustion; reputational harm.
  - Affected components: backend/main.py CORS config; backend/routes/generate_code.py ParameterExtractionStage and CodeGenerationMiddleware; backend/routes/evals.py run_evals
  - Current mitigations: None at the app level; the readme positions hosted version as paid, but open-source backend has no built-in controls.
  - Missing mitigations: Require authentication and rate limiting; disable use of env keys when request is unauthenticated; feature flag the evals endpoints off by default for production.
  - Risk severity: High

- SSRF and arbitrary outbound requests via client-controlled OpenAI base URL in non-prod
  - Description: When IS_PROD evaluates falsey, openAiBaseURL from the client is accepted and used to instantiate AsyncOpenAI. A malicious client can point to arbitrary hosts (including internal metadata endpoints) if a publicly reachable dev or staging instance is exposed.
  - Impact: SSRF into internal services; egress to attacker infrastructure; potential data exfiltration from internal network if responses are streamed back.
  - Affected components: backend/routes/generate_code.py ParameterExtractionStage._get_from_settings_dialog_or_env and ModelSelection/OpenAI calls; backend/config.py IS_PROD default handling
  - Current mitigations: Disabled when IS_PROD is truthy. However, IS_PROD is not boolean-parsed, making misconfiguration easy.
  - Missing mitigations: Parse IS_PROD as a strict boolean; disallow client-provided base URLs entirely; maintain allowlist of known OpenAI endpoints; enforce HTTPS; refuse private/reserved IP ranges.
  - Risk severity: High (in any publicly exposed non-prod/staging)

- Sensitive data leakage to disk through logging and debug artifacts
  - Description: write_logs persists prompt messages and a completion to LOGS_PATH/run_logs including base64-encoded images and user text. Video mode stores frames as JPEGs in OS temp when DEBUG = True in video/utils.py. DebugFileWriter writes extracted HTML and thinking segments when IS_DEBUG_ENABLED is truthy. These can contain user PII and proprietary screenshots/videos.
  - Impact: Data exfiltration via filesystem access or backups; regulatory exposure; large disk usage.
  - Affected components: backend/fs_logging/core.py; backend/video/utils.py; backend/debug/DebugFileWriter.py; backend/utils.py print_prompt_summary (stdout logs)
  - Current mitigations: None beyond optional flags; no redaction; no retention policies.
  - Missing mitigations: Redact or drop base64 media from logs; disable DEBUG and IS_DEBUG_ENABLED by default; automatically clean up temp debug files; configurable retention with secure permissions; optionally hash-tag logs instead of raw content.
  - Risk severity: Medium

- Resource exhaustion via large base64 images/videos and unbounded history
  - Description: process_image decodes base64 images in memory before size checks; video processing decodes full video to frames and saves to disk; prompt/history arrays are unbounded. An attacker can submit massive base64 payloads or long histories to consume CPU, memory, disk, and processing time.
  - Impact: Denial of service; out-of-memory; disk fill in temp; degraded service for others.
  - Affected components: backend/image_processing/utils.py process_image; backend/video/utils.py split_video_into_screenshots and save_images_to_tmp; backend/routes/generate_code.py ParameterExtractionMiddleware → PromptCreationStage (history length)
  - Current mitigations: Frame cap TARGET_NUM_SCREENSHOTS = 20; Claude-specific downscaling after decoding.
  - Missing mitigations: Enforce Content-Length and payload size limits at transport; pre-decode base64 length checks; cap history length and message sizes; timeouts and concurrency limits; reject videos above specific size/duration; disable DEBUG image saving by default.
  - Risk severity: Medium

- Cross-origin drive-by abuse via permissive CORS and WebSocket acceptance
  - Description: CORS allow_origins="*" with allow_credentials=True and no auth; WebSocket accepts all without origin checks. Any website can open connections and call expensive operations on an exposed server.
  - Impact: Same as credit drain; also makes targeted DoS trivial from browsers.
  - Affected components: backend/main.py CORSMiddleware; backend/routes/generate_code.py WebSocketSetupMiddleware
  - Current mitigations: None.
  - Missing mitigations: Restrict origins; require auth tokens; validate Origin headers for WebSocket; rate limit per IP/token.
  - Risk severity: High on any public deployment

- Path injection read-amplification through eval listing
  - Description: The evals endpoints list files in arbitrary folders and pair names by prefix. While limited to .html reads, the pairing logic may accidentally expose content if pointed at directories containing sensitive .html (e.g., admin UIs, docs, or config templates).
  - Impact: Data leakage; reconnaissance.
  - Affected components: backend/routes/evals.py
  - Current mitigations: Suffix filtering to .html.
  - Missing mitigations: Constrain to EVALS_DIR; path normalization; server setting to disable endpoints in production.
  - Risk severity: Medium

- Code execution in the browser from untrusted generated code
  - Description: The app’s primary function is to generate and render code with script tags and event handlers. If a hosted multi-tenant front-end renders one user’s generated code in a privileged context, it can exfiltrate other users’ data, browser API keys entered in settings, or perform CSRF against backend.
  - Impact: Account/session compromise; data exfiltration; lateral movement in hosted environments.
  - Affected components: Frontend rendering path receiving "chunk"/"setCode" over WS (not in this batch) and any preview surface; backend’s role is to pass through untrusted code.
  - Current mitigations: Not evident here.
  - Missing mitigations: Render in a fully sandboxed iframe with restrictive sandbox attributes; isolate origins; avoid sharing tokens with preview origin; consider content-security-policy for previews. If single-user local app, risk is accepted; for hosted multi-user, required.
  - Risk severity: High in hosted/multi-tenant; Low in local single-user

- Misconfiguration of production flags leading to unsafe behavior
  - Description: IS_PROD is not parsed to a boolean; any non-empty string is truthy, but logic uses it in negations. Similarly, MOCK uses bool(os.environ.get(...)) causing unexpected truthiness. Misconfiguration can accidentally enable client-controlled base URL or mock mode.
  - Impact: Enabling client-controlled SSRF in production; disabling real inference; inconsistent security posture.
  - Affected components: backend/config.py
  - Current mitigations: Comments noting TODO for MOCK; IS_PROD check exists but not robust.
  - Missing mitigations: Parse envs strictly (e.g., value == "true"); central helper for env booleans; fail-closed defaults for prod.
  - Risk severity: Medium

- External image URL reuse through alt-text mapping
  - Description: create_alt_url_mapping maps alt → src for non-placehold.co images from prior code, then merges with newly generated URLs. Previewing such code can cause the browser to load attacker-controlled remote images silently.
  - Impact: Client IP and user agent leakage; tracking; potential mixed-content or slow loading.
  - Affected components: backend/image_generation/core.py create_alt_url_mapping and generate_images
  - Current mitigations: Only placeholder images are replaced; mapping merges but does not actively fetch on server.
  - Missing mitigations: Option to disable reuse of non-placehold sources; warn users; restrict to known-safe domains when hosted.
  - Risk severity: Low

- Disclosure of upstream provider response details in errors
  - Description: Error messages from openai.NotFoundError or RateLimitError are forwarded to the client (e.message). While keys are not included, upstream metadata may be exposed.
  - Impact: Minor information disclosure; aids attackers enumerating models/limits.
  - Affected components: backend/routes/generate_code.py ParallelGenerationStage._stream_openai_with_error_handling
  - Current mitigations: None specific.
  - Missing mitigations: Sanitize upstream error messages to user-friendly text; log full details server-side only.
  - Risk severity: Low

Notes on omitted controls: Some threats (e.g., untrusted code execution) may be acceptable for single-user local runs; they require controls only for hosted, multi-user contexts.

# DEPLOYMENT THREAT MODEL

The project can be deployed:
- Locally via poetry + yarn for development
- Via docker-compose (backend + frontend dev server)
- As a hosted service (paid version referenced in README)

Mode analyzed: docker-compose deployment exposed to the internet without additional reverse proxy/auth.

## ASSETS
- Secrets in environment (.env used by docker-compose)
- Secrets baked into images (backend Dockerfile copies backend/.env if present)
- Publicly exposed ports: backend ${BACKEND_PORT:-7001}, frontend 5173
- Container file systems holding logs, evals outputs, and temp/debug frames

## TRUST BOUNDARIES
- Internet to containers (0.0.0.0 binding for both)
- Containers to third-party APIs (OpenAI, Anthropic, Google, Replicate, ScreenshotOne)
- Containers to host filesystem (volumes if mounted; image layers contain copied files)
- Compose-level environment (.env) into containers

## DEPLOYMENT THREATS
- Secrets baked into backend image layers
  - Description: Backend Dockerfile COPY ./ /app/ will include backend/.env if present, embedding secrets into image layers that may be pushed or shared.
  - Impact: Secret leakage if image is published or accessed; long-term persistence in layer history.
  - Affected components: backend/Dockerfile; deployment practices using backend/.env
  - Current mitigations: None in Dockerfile.
  - Missing mitigations: Exclude .env via .dockerignore; inject secrets at runtime only; use Docker secrets or environment injection in orchestrator.
  - Risk severity: High

- Publicly exposed dev servers
  - Description: Frontend container runs yarn dev with HMR on 0.0.0.0; backend binds 0.0.0.0. No authentication or rate limiting; CORS wide open.
  - Impact: All application threats become remotely exploitable; DoS and credit drain.
  - Affected components: frontend/Dockerfile CMD; docker-compose.yml ports; backend/main.py CORS; WebSocket
  - Current mitigations: None.
  - Missing mitigations: Use a production build for frontend; place behind authenticated gateway; restrict inbound IPs; configure proper CORS.
  - Risk severity: High

- Unprotected evals endpoints in production
  - Description: Evals endpoints allow reading/writing files and invoking batches of model calls without auth.
  - Impact: Arbitrary file read and cost abuse at scale.
  - Affected components: backend/routes/evals.py; docker-compose default exposure
  - Current mitigations: None.
  - Missing mitigations: Disable in prod; authz; constrain to safe directories.
  - Risk severity: High

- Environment boolean parsing misconfig in production
  - Description: IS_PROD not boolean-parsed may cause unsafe behavior (e.g., enabling client base URL override).
  - Impact: SSRF risk; non-deterministic posture across environments.
  - Affected components: backend/config.py; deployment env values
  - Current mitigations: None.
  - Missing mitigations: Normalize env parsing; test harness to assert prod flags.
  - Risk severity: Medium

- Container egress to arbitrary destinations
  - Description: Client-controlled openAiBaseURL (when enabled) or evals fetching models can direct egress to attacker-controlled hosts.
  - Impact: SSRF-like egress; data exfiltration paths; attack surface expansion through library HTTP stacks.
  - Affected components: backend outbound HTTP
  - Current mitigations: Client-provided base URL disabled when IS_PROD is truthy.
  - Missing mitigations: Network egress policies at container/network level; DNS allowlists; disallow client-provided base URL entirely.
  - Risk severity: Medium

Notes on omitted controls: General platform logging/monitoring and backup strategies are out of scope; the risks above are introduced specifically by project files and deployment choices.

# BUILD THREAT MODEL

## ASSETS
- Dependency manifests: backend/pyproject.toml, poetry.lock; frontend package.json/yarn.lock (not shown in this batch)
- Build containers pulling dependencies from public registries
- Test data and evals scripts that interact with local filesystem
- CI or local build environment variables and credentials (if used)

## TRUST BOUNDARIES
- Package registries (PyPI, npm) to build environment
- Developer machines/CI to Docker daemon and image registry
- .env files on developer machines to build context

## BUILD THREATS
- Unpinned frontend dependencies
  - Description: Frontend Dockerfile runs yarn install; without lockfile enforcement, transitive deps may drift. (package.json/yarn.lock not visible here; if missing or not honored, risk increases.)
  - Impact: Supply chain compromise; build instability.
  - Affected components: frontend/Dockerfile
  - Current mitigations: None visible in Dockerfile (no frozen lockfile flag).
  - Missing mitigations: Ensure yarn.lock is present and used; use --frozen-lockfile; vendor critical assets where feasible.
  - Risk severity: Medium

- Secrets present in build context
  - Description: Building backend image copies entire backend directory, including backend/.env if used. Compose also references a root .env file.
  - Impact: Secrets leak into images and build caches; accidental commit of .env is common.
  - Affected components: backend/Dockerfile; docker-compose.yml
  - Current mitigations: None.
  - Missing mitigations: .dockerignore to exclude .env and other secrets; use build args or runtime env injection; avoid committing .env.
  - Risk severity: High

- Test and eval scripts writing outside intended directories
  - Description: Evals runner accepts model and stack, writes outputs under EVALS_DIR/results. Misuse during CI could write large files and artifacts; run_evals endpoint can be triggered if test server is reachable during build.
  - Impact: Disk usage; longer builds; potential leakage if artifacts uploaded.
  - Affected components: backend/evals/*
  - Current mitigations: EVALS_DIR fixed to ./evals_data.
  - Missing mitigations: Separate build profiles to skip evals; restrict network at build; ensure CI does not expose test servers.
  - Risk severity: Low

- Dev-only dependencies in runtime
  - Description: pre-commit listed under runtime dependencies in pyproject.toml, increasing attack surface if any hooks or plugins are pulled in during install.
  - Impact: Slightly larger surface/attack chain if supply chain compromised.
  - Affected components: backend/pyproject.toml
  - Current mitigations: None.
  - Missing mitigations: Move pre-commit to dev dependencies group.
  - Risk severity: Low

# QUESTIONS & ASSUMPTIONS
- Who is the intended user of the open-source backend in your deployment?
  - Assumed both local single-user and potentially internet-exposed demo/hosted. If only local, several high risks (auth, CORS, evals file read) are reduced but still exploitable by local processes.
- Will a hosted, multi-tenant frontend render one user’s generated code in a context that has access to other users’ data or tokens?
  - Assumed possible for hosted version, driving the high severity of untrusted code execution in previews.
- Is IS_PROD consistently set in all deployed environments?
  - Assumed sometimes omitted or mis-set due to non-boolean parsing; this materially affects security posture.
- Are evals endpoints intended to be publicly exposed?
  - Assumed dev-only. If exposed, the arbitrary folder read risk is high and should be closed.
- Do you plan to allow client-provided openAiBaseURL in any environment accessible beyond localhost?
  - Assumed not; leaving it enabled outside strictly local networks increases SSRF risk.
- Will the backend store any server-managed API keys in env for production?
  - Assumed yes for hosted; if so, unauthenticated access becomes a credit-drain vector.

Notes on why some threats have no associated controls:
- Rendering untrusted code is intrinsic to the product; in local single-user mode it may be acceptable not to sandbox. Controls become necessary only in hosted/multi-tenant contexts.
- External screenshot provider misuse is mostly limited by the client providing their own ScreenshotOne key; impact to the server is minimal beyond potential bandwidth.
