APPLICATION THREAT MODEL

ASSETS
- Tenant API keys: Unique API keys per Meal Planner client used by API Gateway to authenticate requests.
- Tenant configuration and onboarding data: Control Plane data about tenants, ACLs, rate limits, billing.
- API Gateway configuration: Routes, plugins, ACLs, rate limits, authentication configs.
- Dietitian content samples: Tenant-provided content stored in API database.
- LLM prompts and outputs: Requests and responses sent to and received from ChatGPT-3.5; may include sensitive or proprietary content.
- Multi-tenant isolation metadata: Tenant identifiers, mappings between API keys and tenant data scopes.
- Administrative capabilities: Control Plane functions that can create/update tenants, manage API keys, and adjust authorization rules.
- Database contents: Control Plane Database (tenant/billing/config), API Database (content samples, LLM request/response history).

TRUST BOUNDARIES
- Internet boundary: Between external Meal Planner applications and API Gateway (HTTPS).
- External LLM boundary: Between Backend API and ChatGPT-3.5 over the public internet (HTTPS).
- Admin access boundary: Between Administrator’s environment and Web Control Plane.
- Service-to-database boundary: Between ECS services (Web Control Plane, API Application) and their RDS databases.
- Intra-service boundary: Between API Gateway and Backend API (assumed internal network/VPC).
- Tenant data boundary: Logical boundary separating tenants’ data within shared databases and services.

DATA FLOWS
- Meal Planner -> API Gateway (HTTPS/REST). Crosses Internet boundary.
- API Gateway -> Backend API (HTTPS/REST). Internal; if on separate subnets, internal trust boundary applies.
- Backend API -> API Database (TLS read/write). Crosses service-to-database boundary.
- Backend API -> ChatGPT-3.5 (HTTPS/REST). Crosses External LLM boundary.
- Web Control Plane -> Control Plane Database (TLS read/write). Crosses service-to-database boundary.
- Administrator -> Web Control Plane (HTTPS/Web). Crosses Admin access boundary.
- Implied: Web Control Plane -> API Gateway Admin/API or config channel (to manage API keys/ACLs). Crosses intra-service/config boundary.

APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|---|
| 0001 | API Gateway (Kong) | The attacker could try to get access to the secret of a particular client in order to replay its API requests with stolen API key | Spoofing | Per-tenant API key authentication is used; stolen keys enable impersonation | Partially mitigated: API keys + TLS from client per Security section | Use short-lived signed tokens or HMAC request signing with nonce/timestamp; rotate keys per tenant; detect anomalous usage by key; optionally bind keys to IP or mTLS | Credential theft via client compromise or leakage is common | Full tenant impersonation, data exfiltration/manipulation across all API endpoints allowed by ACLs | High |
| 0002 | API Gateway (Kong) | Misconfigured ACL permits unauthorized access to endpoints or tenants | Elevation of Privilege | Gateway enforces ACL rules; misconfiguration can over-grant | Not mitigated by design; ACL existence does not prevent human/config error | Adopt declarative, version-controlled Kong config with policy-as-code checks; default deny; automated tests for per-tenant ACLs | Config drift or mistakes are plausible | Could expose data/actions across tenants, bypassing backend authorization if present | High |
| 0003 | API Gateway (Kong) | Bypass input filtering and inject prompts that subvert downstream LLM behavior | Tampering | Gateway performs input filtering; LLM is sensitive to prompt injection | Partially mitigated: filtering exists but efficacy unknown | Add content controls in backend to constrain system prompts; validate/transform inputs; isolate user content from instructions; employ allow-list schemas per endpoint | Prompt injection attempts are frequent in LLM-integrated APIs | May cause data leakage, unsafe outputs, reputational harm | Medium |
| 0004 | API Gateway (Kong) | Distributed requests evade rate limits to cause backend and LLM cost spikes | Denial of Service | Gateway provides rate limiting; distributed sources or per-key distribution may evade | Partially mitigated: rate limiting exists | Enforce per-tenant quotas and budgets; burst detection across IPs and keys; circuit breakers in backend for LLM calls | Abuse against public APIs is common | Service degradation and unexpected cost amplification due to LLM usage | Medium |
| 0005 | API Gateway (Kong) | Kong admin API exposure allows attacker to change routes/plugins/ACLs | Elevation of Privilege | If admin API or management port is reachable, attacker can reconfigure | Not described as mitigated | Isolate admin API on private network only; authN/Z for admin API; restrict by IP; disable if using declarative config | Misconfigurations occur; exploit depends on exposure | Complete compromise of gateway policy and traffic | High |
| 0006 | Backend API | Trusting client-provided tenant identifiers in headers leads to cross-tenant access | Elevation of Privilege | If backend uses headers (e.g., X-Tenant) without verifying via gateway mapping, spoofing is possible | Not described as mitigated | Derive tenant identity from validated principal (API key) passed by gateway via an internal auth context/credential, not from client headers | Common implementation pitfall | Cross-tenant read/write of data | High |
| 0007 | Backend API | Cross-tenant data exposure due to improper query scoping | Information Disclosure | Multi-tenant data in shared API DB; buggy scoping leaks data | Not described as mitigated | Enforce row-level security/tenant_id conditions in all queries; apply service-layer tenancy guardrails; test per-tenant isolation | Multi-tenant bugs are frequent | Leak of dietitian content and LLM histories across tenants | High |
| 0008 | Backend API | Unbounded or recursive LLM calls cause resource exhaustion | Denial of Service | Each request can trigger external LLM; unbounded size or retries overrun resources | Not mitigated | Enforce payload size limits, token limits, timeouts, and concurrency caps; budget-aware throttling | Likely if inputs aren’t constrained | Exhaustion of threads/connections; high cost spikes | Medium |
| 0009 | Backend API | Backend trusts gateway origin and is reachable from outside internal network | Spoofing | If backend endpoint is exposed, attacker bypasses gateway authentication | Not described as mitigated | Place backend behind private network; require mTLS between gateway and backend; validate internal auth token from gateway | Misexposure happens if mis-deployed | Full bypass of gateway protections | High |
| 0010 | Backend API | Prompt injection leaks prior conversation/system prompts via LLM response | Information Disclosure | LLM integration; user content can steer model to disclose context | Not mitigated per description | Use strict system prompts; strip tenant identifiers; don’t include other tenants’ context; enable content moderation; post-process to redact sensitive patterns | Prompt injection attempts are common | Leakage of proprietary templates or other tenants’ content | Medium |
| 0011 | API Database (RDS) | Tenant content tampering via API due to missing server-side validation | Tampering | Stores dietitian samples; lack of validation allows corrupted/malicious content | Not described as mitigated | Enforce schema/format validation; content sanitization; versioned writes with integrity checks | Common if validation is weak | Corrupts model inputs/outputs; downstream leakage | Medium |
| 0012 | API Database (RDS) | Untraceable changes to LLM request/response history | Repudiation | Keeping histories without immutable change tracking enables dispute | Not mitigated | Implement write-once append-only logs for LLM exchanges with per-tenant correlation IDs | Disputes are plausible but not constant | Hard to attribute misuse/cost disputes | Low |
| 0013 | Web Control Plane | CSRF/confused-deputy altering tenant config or API keys | Tampering | Control plane changes keys, ACL, config | Not described as mitigated | Enforce CSRF protections; same-site cookies; explicit re-auth for sensitive actions; signed change requests | Web UIs are CSRF targets | Can redirect traffic or weaken auth across system | Medium |
| 0014 | Web Control Plane | Role misassignment lets lower-privileged users manage other tenants | Elevation of Privilege | Multi-role system; mis-scoped privileges grant broad access | Not mitigated | Implement fine-grained RBAC by tenant; require break-glass plus approvals for high-risk actions | Role bugs occur | Global configuration compromise; tenant data exposure | High |
| 0015 | Web Control Plane | Leakage of billing or tenant metadata via UI/API enumeration | Information Disclosure | Control plane holds tenant/billing data | Not mitigated | Enforce per-tenant filtering; side-channel safe pagination; avoid exposing identifiers across tenants | Enumeration issues are common | Exposure of business-sensitive information | Medium |
| 0016 | Control Plane Database (RDS) | Stale or orphaned API keys retained after tenant offboarding | Information Disclosure | Keys managed in control plane; offboarding errors leave keys valid | Not mitigated | Automated key revocation on status change; periodic key sweeps; expirations | Operational drift is common | Former clients retain access; compliance issues | Medium |
| 0017 | ChatGPT-3.5 (External) | Sending sensitive tenant data to third-party LLM without tenant consent | Information Disclosure | LLM calls carry tenant content; third-party processing risk | Not mitigated in design | Tenant-level toggle/consent; data minimization; redaction; region-specific endpoints; contractual/data retention controls | Realistic concern for regulated tenants | Regulatory exposure; data leakage outside org boundary | High |
| 0018 | ChatGPT-3.5 (External) | Improper TLS verification enables MITM on LLM traffic | Tampering | External HTTPS dependency | Partially mitigated: use HTTPS; default clients verify certs | Enforce TLS 1.2+; pin CA/endpoint where feasible; verify hostname; reject insecure ciphers | Low if standard libraries used | Altered responses; poisoning of outputs | Low |
| 0019 | ChatGPT-3.5 (External) | Provider rate limiting/outage cascades to service outage | Denial of Service | Single dependency on ChatGPT for core feature | Not mitigated | Use retries with backoff, graceful degradation, queueing; fallbacks or alternative models/providers | Third-party outages occur | Feature unavailability; SLA impact; cost of retries | Medium |
| 0020 | API Gateway/Backend | Insufficient request/response redaction stores PII/sensitive data in logs/history | Information Disclosure | API DB stores requests/responses; content may include sensitive info | Not mitigated | Redact or tokenize sensitive data before storage; configurable retention | Likely if inputs free-form | Privacy exposure, larger breach blast radius | Medium |
| 0021 | Meal Planner Client | Malicious or malformed content samples poison shared prompts/templates | Tampering | Clients upload content samples | Partially mitigated: gateway input filtering | Validate and sandbox templates; isolate per-tenant prompts; content safety scans | Common avenue for abuse | Degraded or unsafe outputs across tenant | Medium |
| 0022 | Administrator (Person) | Social engineering to change system configuration via control plane | Spoofing | Admin has power to alter keys/config | Not mitigated in file; outside technical scope | Require strong MFA, out-of-band approvals for key changes | Social engineering is common | System-wide compromise via policy changes | High |
| 0023 | Backend API | Reflection of LLM output without post-processing could return harmful content | Tampering | LLM output may violate policies | Not mitigated | Add output moderation, allow-list formats, and safety constraints | Common LLM issue | Harmful content to end-users; reputational harm | Medium |
| 0024 | API Gateway | Header smuggling or improper forwarding reveals internal headers to client | Information Disclosure | Kong forwards headers to/from backend | Not mitigated | Strip sensitive headers; maintain explicit header allow-list | Possible with custom plugins | Leak of auth context, internal IPs | Low |

Notes:
- 0018 considered low likelihood given standard HTTPS client behavior in Golang; no additional control may be justified if using default TLS correctly.
- 0012 considered low severity; implement if disputes/auditability become a requirement.

DEPLOYMENT THREAT MODEL

Possible deployment architectures
- Option A: AWS ECS services (Kong, Web Control Plane, Backend API) in private subnets behind an internet-facing ALB; RDS (Control Plane DB, API DB) in private subnets; NAT Gateway for outbound to ChatGPT-3.5.
- Option B: EKS (Kubernetes) with Ingress Controller and private services; RDS as above; egress via NAT.
- Option C: EC2 VMs running Docker; self-managed networking and security groups; RDS as above.

Selected architecture for modeling: Option A (AWS ECS + ALB + RDS + NAT), as implied by the file.

ASSETS
- ALB listeners and TLS certificates for public ingress to Kong.
- ECS task roles and execution roles for Kong, Web Control Plane, Backend API.
- Security Groups and Network ACLs controlling access to ECS tasks and RDS.
- RDS instances and snapshots for Control Plane DB and API DB.
- NAT Gateway egress to the internet for ChatGPT access.
- Kong admin interface network path (should be private only).
- Secrets storage for API keys, database credentials, OpenAI credentials.

TRUST BOUNDARIES
- Public Internet to ALB/Kong boundary.
- Private subnets hosting ECS tasks.
- Egress boundary via NAT to public internet for ChatGPT.
- AWS IAM boundary between services and AWS APIs (roles, policies).
- Database private subnets with restricted access from ECS tasks only.

DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|
| D0001 | ALB/Kong | Weak TLS config or misissued cert allows downgrade or interception | Public ingress terminates TLS | Not described | Enforce TLS 1.2+/1.3, strong ciphers, ACM-managed certs, HSTS | Misconfig common if manual | Data exposure and session compromise | Medium |
| D0002 | Security Groups | Backend API reachable from public internet bypassing gateway | If SG allows 0.0.0.0/0 or ALB targets mis-set | Not mitigated | Restrict backend SG to Kong SG only; no public IPs on tasks | Occurs with drift | Auth bypass → full API compromise | High |
| D0003 | RDS Instances | RDS publicly accessible or wide SG exposure | RDS should be private-only | Not mitigated | Ensure private subnets, no public access, SG allows from app SGs only | Frequent misconfig | Data breach/exfiltration | High |
| D0004 | ECS Task Roles | Over-privileged roles allow unintended AWS actions (e.g., exfil via S3) | Tasks need minimal AWS access | Not mitigated | Least-privilege IAM policies; scoped to Secrets Manager/CloudWatch as needed | Over-privilege is common | Lateral movement, data exfiltration | Medium |
| D0005 | NAT Gateway Egress | Unrestricted egress permits data exfiltration to arbitrary hosts | Backend requires internet for ChatGPT | Not mitigated | Egress allow-list to OpenAI endpoints via VPC endpoints/proxy; firewall rules | Commonly open | Unmonitored data leakage | Medium |
| D0006 | Kong Admin API | Admin port exposed within VPC to many sources | Kong needs admin for config | Not mitigated | Place admin interface in isolated subnet; SG restrict to control plane only; or use DB-less declarative with no admin port | Likely if defaults kept | Full policy compromise | High |
| D0007 | Secrets Handling | Storing API keys and DB creds in ECS env vars leads to leakage via crash/metrics | Services require secrets | Not mitigated | Use AWS Secrets Manager or SSM Parameter Store; inject at runtime; no logging of secrets | Common pitfall | Credential exposure | Medium |
| D0008 | ALB Target Health | Misconfigured health checks enable path probing or amplify traffic to heavy endpoints | Health checks on app paths | Not mitigated | Use dedicated lightweight health endpoints; SG restricts checkers to ALB | Possible | DoS and info leakage from verbose errors | Low |
| D0009 | RDS Snapshots | Unrestricted snapshot sharing exposes tenant data | Snapshots for backup | Not mitigated | Disable public snapshot sharing; enforce snapshot policies | Known cloud risk | Full DB disclosure if shared | Medium |
| D0010 | Container Images | Pulling mutable latest tags leads to unintended versions deployed | ECS services use images | Not mitigated | Pin digests; use ECR with immutable tags; enable image scanning | Common | Introduces vulnerable/unvetted builds | Medium |
| D0011 | Network ACLs | Overly permissive NACLs allow lateral traffic between services | Multi-tier VPC | Not mitigated | Default-deny east-west; SG/NACL micro-segmentation by tier | Possible | Increases blast radius | Medium |
| D0012 | Outbound DNS | Compromised app resolves attacker-controlled domains for exfil | NAT egress relies on DNS | Not mitigated | Use Route 53 Resolver rules and DNS firewall to restrict domains | Plausible | Covert exfiltration channel | Low |

BUILD THREAT MODEL

ASSETS
- Source code for Web Control Plane and Backend API (Golang).
- Kong configuration (routes, plugins, ACLs) as code.
- Dockerfiles and base images for ECS services.
- OpenAI/ChatGPT API credentials used by backend.
- Tenant API key provisioning scripts/config managed by control plane.
- Build artifacts (container images), image registry (ECR).

TRUST BOUNDARIES
- Developer workstations to VCS/CI system.
- CI/CD system to artifact registry (ECR) and AWS deployment.
- Secrets storage for CI/CD (OpenAI keys, DB creds) vs build logs/artifacts.
- Promotion between environments (dev/test/prod).

BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|
| B0001 | Kong Config Repo | Misconfigured ACLs/routes promoted to prod due to lack of policy checks | Kong governs auth/routing | Not mitigated | Treat Kong config as code; add policy-as-code tests (e.g., OPA) to verify tenant isolation and default-deny | Config mistakes are common | Broad unauthorized access in prod | High |
| B0002 | Backend API Build | Embedding OpenAI API keys into images at build time | Backend needs API key | Not mitigated | Inject secrets at runtime only; fail build if secret found in image | Common pitfall | Key leakage to anyone pulling image | Medium |
| B0003 | Go Modules | Dependency tampering via unpinned module versions | Golang app uses modules | Not mitigated | Pin versions with go.mod/go.sum; checksum DB/GOPROXY; vendor critical deps | Common supply chain risk | Introduces malicious code | Medium |
| B0004 | Docker Base Image | Using untrusted/mutable base images | Dockerfiles for ECS | Not mitigated | Use minimal, pinned, trusted bases; image signing/verification | Common | Vulnerabilities/backdoors | Medium |
| B0005 | CI Pipeline | Cross-environment promotion risk mixing tenant config or keys | Control plane provisions keys | Not mitigated | Separate pipelines and stores per env; guardrails to prevent prod key use in non-prod | Operational mistakes happen | Exposure of prod tenants or outage | Medium |
| B0006 | Artifact Registry (ECR) | Overwrite of tags leading to rollback to vulnerable images | Tag mutability | Not mitigated | Immutable tags; require digest pinning in deployment | Common | Deploys unintended code | Medium |
| B0007 | CI Secrets | Leakage of tenant onboarding credentials or API key seed material in logs | CI runs provisioning tasks | Not mitigated | Redact logs; scoped runner permissions; separate secrets stores | Possible | Tenant impersonation at scale | High |
| B0008 | Kong Plugins | Introducing unsafe or custom plugins that bypass auth | Kong supports plugins | Not mitigated | Review/allow-list plugins; CI checks that auth plugins are enforced per route | Possible | Auth bypass on selected paths | High |
| B0009 | LLM Prompt Templates | Publishing unreviewed prompt templates that cause data leakage | Backend uses templates | Not mitigated | Template review gates; tests to prevent cross-tenant references; static checks | Possible with LLM work | Leakage or harmful responses | Medium |
| B0010 | Release Process | Skipping canary for routes that invoke ChatGPT can cause cost spikes | LLM cost sensitivity | Not mitigated | Canary releases with cost guardrails; feature flags | Common | Rapid unforeseen cost/outage | Low |

QUESTIONS & ASSUMPTIONS
- Assumptions:
  - Backend API and Web Control Plane run on AWS ECS in private subnets; RDS is private-only; Kong is fronted by an ALB.
  - Kong admin API is either present for management or configuration is provided declaratively at startup.
  - Tenant identity is derived from API Gateway authentication and needs propagation to backend securely.
  - LLM provider is OpenAI ChatGPT-3.5 over HTTPS, with standard TLS validation via Golang HTTP client.
  - No additional in-app authorization beyond Gateway ACLs was specified; if backend has its own checks, some risks reduce.

- Questions:
  - How is the Kong admin/config interface exposed and authenticated? Is it disabled in production (DB-less) or isolated?
  - Does the backend perform its own per-tenant authorization, or rely solely on Gateway ACLs?
  - How are tenant IDs propagated from Gateway to Backend (headers, JWT, mTLS)? Are client-supplied tenant headers ignored?
  - Are there constraints on request size/tokens/timeouts for LLM calls to prevent DoS and runaway costs?
  - Is there tenant consent and data minimization/redaction before sending content to ChatGPT?
  - What retention policy exists for LLM request/response histories stored in the API database?
  - Are the databases configured as private-only, with SGs restricted to specific ECS task SGs?
  - How are secrets managed for ECS tasks and CI (Secrets Manager/SSM vs env vars)?
  - Is Kong configuration managed declaratively via code with CI checks for ACL/rate-limit correctness?
  - Are prompt templates/versioning and validation part of the release process?

Notes on scope:
- Generic controls like “enable logging” or “do audits” were avoided unless directly tied to this architecture (e.g., immutable histories for repudiation).
- Some low-likelihood threats (e.g., TLS MITM against ChatGPT via standard clients) are noted but may not warrant extra controls beyond defaults.
