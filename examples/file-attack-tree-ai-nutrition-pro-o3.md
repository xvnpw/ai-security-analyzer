Threat Modeling Analysis for AI Nutrition-Pro Using Attack Trees
===============================================================

────────────────────────────────────────────────────────────────
1. Understand the Project
────────────────────────────────────────────────────────────────
Project Name: AI Nutrition-Pro

Overview
• SaaS-style backend that lets 3rd-party “Meal Planner” applications upload sample dietitian content and fetch AI-generated text created through ChatGPT 3.5.
• Deployed on AWS ECS as three containers behind a Kong API-Gateway.
• Stores tenant/billing metadata in a “Control-Plane DB” and LLM-related artefacts in an “API DB”.

Key Components & Features
• Kong API Gateway – authenticates clients with per-tenant API keys, filters input, rate-limits.
• Backend API (Golang) – exposes REST endpoints that call OpenAI’s API, persists requests, responses, and uploaded samples.
• Web Control Plane (Golang) – admin/on-boarding UI; manipulates tenant records & billing.
• Control-Plane DB (Amazon RDS) – metadata.
• API DB (Amazon RDS) – dietitian samples, prompts, LLM responses.
• External Systems – Meal-Planner apps, ChatGPT 3.5.

Dependencies
• Golang libraries (OpenAI client, ORM/SQL driver, JWT/Key handling, etc.)
• Kong plugins (Lua/Go).
• AWS SDK (IAM, ECS, RDS).

────────────────────────────────────────────────────────────────
2. Root Goal of the Attack Tree
────────────────────────────────────────────────────────────────
“Compromise organisations that use AI Nutrition-Pro by abusing weaknesses in AI Nutrition-Pro’s code, configuration, or supply chain, resulting in unauthorised data disclosure, remote code execution, or delivery of malicious content to Meal-Planner clients.”

────────────────────────────────────────────────────────────────
3. High-Level Attack Paths (Sub-Goals)
────────────────────────────────────────────────────────────────
1. Bypass or abuse authentication/authorisation at the API Gateway.
2. Exploit Web Control Plane vulnerabilities to gain admin/tenant control.
3. Exploit Backend API vulnerabilities to exfiltrate data or attain RCE.
4. Deliver malicious output through LLM-prompt manipulation (poisoning).
5. Compromise data stores directly (RDS).
6. Exploit container / infrastructure mis-config to pivot inside AWS.
7. Inject malicious code via supply-chain or build pipeline.

────────────────────────────────────────────────────────────────
4. Detailed Attack Tree (Visualised)
────────────────────────────────────────────────────────────────
Legend:
• [OR] siblings ‑ any one is sufficient.
• [AND] siblings ‑ all required.
• Leaves are prefixed with “(L)”.
```
ROOT: Compromise systems that use AI Nutrition-Pro
[OR]
+-- 1. Bypass/abuse API-Gateway authZ
|   [OR]
|   +-- 1.1 (L) Brute-force or guess poorly-generated API keys
|   +-- 1.2 Exploit Kong misconfiguration
|       [OR]
|       +-- 1.2.1 (L) Path-based routing flaw exposes internal routes
|       +-- 1.2.2 (L) Disabled ACL plugin allows open access
|   +-- 1.3 (L) Header spoofing over non-mutual-TLS internal hop
|
+-- 2. Control-Plane takeover
|   [OR]
|   +-- 2.1 Web Control-Plane App vuln
|       [OR]
|       +-- 2.1.1 (L) SQLi in tenant/billing endpoints -> DB admin
|       +-- 2.1.2 (L) XSS -> steal admin JWT via UI
|       +-- 2.1.3 (L) Authentication bypass / weak session handling
|   +-- 2.2 (L) Compromised admin credentials (phishing, creds reuse)
|
+-- 3. Backend API exploitation
|   [OR]
|   +-- 3.1 (L) SQLi through dietitian sample upload → read/write API DB
|   +-- 3.2 (L) Path Traversal / arbitrary file write in Golang handler
|   +-- 3.3 Achieve RCE in container
|       [AND]
|       +-- 3.3.1 (L) Upload crafted file triggering vulnerable 3rd-party library
|       +-- 3.3.2 (L) Gain code execution -> escape to ECS task role
|
+-- 4. Malicious LLM output delivered to Meal-Planner
|   [AND]
|   +-- 4.1 (L) Prompt-injection forces ChatGPT to return <script> payload
|   +-- 4.2 (L) Meal-Planner renders response without sanitisation -> XSS
|
+-- 5. Direct DB compromise
|   [OR]
|   +-- 5.1 (L) Obtain RDS credentials from leaked ECS task-definition
|   +-- 5.2 (L) Network-level exposure (improper security-group) → connect
|   +-- 5.3 (L) Weak DB user privileges allow privilege-escalation
|
+-- 6. Container / AWS pivot
|   [OR]
|   +-- 6.1 (L) Escape from Docker to underlying ECS host (kernel CVE)
|   +-- 6.2 (L) Abuse over-privileged IAM role attached to task
|   +-- 6.3 (L) Compromise shared ECR image & spread to all tasks
|
+-- 7. Supply-chain injection
    [OR]
    +-- 7.1 (L) Publish malicious update to upstream Go dependency
    +-- 7.2 (L) Tamper with Kong plugin from public repo
    +-- 7.3 (L) Compromise CI pipeline to inject backdoor in container
```

────────────────────────────────────────────────────────────────
5. Node Attributes (excerpt for key leaves)
────────────────────────────────────────────────────────────────
| # | Leaf Attack Step                                             | Likelihood | Impact | Effort | Skill | Detection |
|---|--------------------------------------------------------------|-----------|--------|--------|-------|-----------|
|1.1| Brute-force weak API keys                                    | Low-Med   | Med    | Low    | Low   | Easy      |
|1.2.1| Exploit path-based routing flaw                            | Med       | High   | Low    | Med   | Moderate  |
|2.1.1| SQLi in control-plane endpoints                            | Low       | High   | Med    | High  | Moderate  |
|2.1.2| Stored XSS in control-plane                                | Med       | Med    | Low    | Low   | Hard      |
|3.1| SQLi in Backend API                                         | Med       | High   | Med    | Med   | Moderate  |
|3.3.2| Container RCE → ECS role                                   | Low       | Critical| High | High | Hard      |
|4.1/4.2| Prompt-injection chain → XSS on Meal-Planner            | High      | High   | Low    | Low   | Hard      |
|5.1| RDS creds leaked via task-def                                | Low       | High   | Low    | Low   | Easy      |
|6.2| Abuse over-privileged IAM task role                          | Low-Med   | Critical| Med | High | Hard      |
|7.1| Malicious Go dependency released                             | Low       | High   | High   | High | Hard      |

────────────────────────────────────────────────────────────────
6. Risk Analysis & Prioritisation
────────────────────────────────────────────────────────────────
High-Risk Paths
A. Prompt-Injection → XSS (4.1 + 4.2)
 • Highest likelihood because adversary controls prompt content; impact extends to every Meal-Planner UI.
B. Kong Misconfiguration (1.2.*)
 • Small config change can fully bypass auth; easy and high impact.
C. Backend API SQLi (3.1)
 • Would leak all dietitian samples & prompt history; medium likelihood due to many input fields.
D. Over-privileged IAM Role (6.2)
 • Lower likelihood but *critical* blast-radius (full AWS account pivot).

Critical Nodes (fixing them blocks many branches)
• Robust input validation on Backend API (hurts 1.2, 3.1, 4.1).
• Strict IAM least-privilege for ECS tasks (blocks 3.3, 5.1, 6.*).
• Secure Kong configuration & automated tests (blocks 1.*).

────────────────────────────────────────────────────────────────
7. Mitigation Strategies (focused on project-specific controls)
────────────────────────────────────────────────────────────────
1. Kong
   – Automated configuration validation; unit tests to ensure ACL & auth filters remain active.
   – Rotate API keys on predictable patterns; enforce high entropy.

2. Web Control-Plane
   – Parameterised SQL access & ORM query builders.
   – Content-Security-Policy & HTML encoder in templates to kill stored XSS.

3. Backend API
   – Centralised validator for all dietitian sample fields; reject LLM-dangerous tokens.
   – Run LLM response through allow-list HTML sanitizer before persisting/returning.
   – Minimal Linux capabilities in container; read-only root FS; Seccomp profile.

4. LLM Interaction
   – System-prompt enforced wrapper; strip “<script”, “</script>” etc.
   – Rate-limit & monitor for token patterns indicative of prompt escapes.

5. Data Stores / AWS
   – Separate IAM roles per service; deny RDS:Modify*, S3:* by default.
   – RDS password in AWS Secrets Manager with task-level policy limiting access.

6. Supply-Chain
   – Lock Go module versions; signed, checksum-verified builds; deploy images from private ECR only.

────────────────────────────────────────────────────────────────
8. Summary of Findings
────────────────────────────────────────────────────────────────
• The easiest yet impactful avenue is manipulating prompts to deliver malicious HTML/JS back to Meal-Planner UIs (4.*).
• Single-point configuration errors in Kong can remove *all* external security controls.
• Classical injection flaws (SQLi, XSS) remain plausible in both Golang services; combined with over-broad IAM these escalate to full AWS compromise.
• Supply-chain risks are lower-probability but evade perimeter defences and deserve deterministic, signed builds.

Focus remediation on:
1. Harden & test Kong rules, rotate high-entropy API keys.
2. Enforce strict input/response sanitisation around LLM usage.
3. Apply least-privilege IAM and container hardening to limit blast-radius.

────────────────────────────────────────────────────────────────
9. Questions & Assumptions
────────────────────────────────────────────────────────────────
• Are LLM responses ever rendered directly in any web browser without sanitisation?
• Do containers run with the default ECS task execution role or unique roles per service?
• Is Kong’s admin API exposed internally or disabled?
• Are Go dependencies pinned and built in a CI pipeline with provenance attestation?

Assumptions:
• All traffic between components inside AWS is TLS-encrypted except noted.
• Meal-Planner UIs render AI output as rich text/HTML.
• No mutual-TLS between Kong and internal services.
