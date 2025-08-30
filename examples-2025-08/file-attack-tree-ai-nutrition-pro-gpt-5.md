# Threat Modeling Analysis for AI Nutrition-Pro Using Attack Trees

## 1. Understand the Project

Project Name: AI Nutrition-Pro

Overview:
- AI Nutrition-Pro provides AI-assisted content generation for dietitians. External Meal Planner applications upload sample content and fetch generated results.
- It exposes an API through Kong API Gateway, a Backend API written in Go on AWS ECS that calls ChatGPT-3.5 (OpenAI API), and a Web Control Plane (Go on ECS) for onboarding/config/billing, each backed by Amazon RDS databases.
- Data stored includes dietitian content samples and the requests/responses exchanged with the LLM.

Key Components and Features:
- API Gateway (Kong): API key authentication per Meal Planner, ACL-based authorization, input filtering, and rate limiting.
- Backend API (Go on ECS): Accepts requests, persists samples and LLM interactions, calls ChatGPT-3.5 via HTTPS/REST.
- API Database (RDS): Stores samples and LLM requests/responses.
- Web Control Plane (Go on ECS): Manages client onboarding, configuration, billing; accessed by Admin, App Onboarding Manager, and Meal Planner application managers.
- Control Plane Database (RDS): Stores control-plane data.
- External systems: Meal Planner applications; ChatGPT-3.5 API.

Dependencies:
- Kong API Gateway, AWS ECS, Amazon RDS, OpenAI ChatGPT-3.5 API, TLS for network encryption externally and DB connections.

## 2. Define the Root Goal of the Attack Tree

Attacker’s ultimate objective:
- Compromise applications and tenants using AI Nutrition-Pro by exploiting weaknesses in AI Nutrition-Pro’s architecture, configuration, and LLM integration to gain unauthorized access, exfiltrate or corrupt data, inject malicious content into downstream apps, or impose abusive costs.

## 3. High-Level Attack Paths (Sub-Goals)

- Exploit Kong API Gateway weaknesses (authz, routing, input filtering, rate limiting).
- Abuse Web Control Plane to mint/view keys, alter ACLs/config, or access tenant data.
- Exploit Backend API multi-tenancy or object access flaws to read/modify other tenants’ data.
- Leverage LLM-specific risks (prompt and output injection) to compromise downstream Meal Planner apps or exfiltrate stored content.
- Abuse cost model via token-burning and rate-limit gaps to cause financial/resource impact.
- Cause unintentional data egress to OpenAI due to over-broad prompt construction or context assembly.

## 4. Expand Each Attack Path with Detailed Steps

1) Exploit Kong API Gateway weaknesses
- Route/Plugin misconfiguration
  - Misordered or overlapping routes allow bypass of key-auth/ACL plugin on specific paths.
  - Anonymous/“health” routes leak functionality due to shared upstream paths.
- ACL rule mistakes
  - Over-broad ACLs grant write/export endpoints to read-only clients.
  - Tenant scoping not enforced at gateway for endpoints that accept tenant IDs.
- Input filtering assumptions
  - Gateway “filtering” fails to mitigate LLM prompt injection or payloads with alternate encodings that evade simple filters.
- Rate limiting gaps
  - Per-request limits but no per-token limits enable long prompts/responses to bypass intended cost controls.
  - Distributed requests across multiple API keys from the same tenant circumvent limits if not bound to tenant.

2) Abuse Web Control Plane
- Role/permission flaws
  - App Onboarding Manager or Meal Planner manager can view or generate API keys for other tenants due to role design or UI/API leakage.
  - Horizontal privilege escalation between managers via predictable tenant identifiers.
- Insecure key exposure workflows
  - Control plane displays full API keys in plaintext, enabling shoulder-surfing or screenshot exfiltration.
- Config and ACL propagation risks
  - Control plane writes misconfigured ACLs to Kong (e.g., enables powerful routes for the wrong tenant).
- Social engineering of a control-plane user
  - Convince an onboarding manager to provision an account or grant access to a malicious “Meal Planner” posing as a legitimate client.

3) Backend API multi-tenancy and object access flaws
- IDOR/tenant scoping bugs
  - Endpoints fetching “samples” or stored “requests/responses” accept object IDs without verifying tenant_id, enabling cross-tenant reads/updates.
- Search/listing leakage
  - Listing endpoints return other tenants’ artifacts if pagination or filtering defaults are wrong.
- Data export endpoints
  - Bulk export includes data beyond tenant scope; lack of server-side tenant constraints.
- Data retention choices
  - Storing all LLM requests/responses increases blast radius if any read endpoint is exposed or compromised.

4) LLM-specific output and prompt risks impacting downstream clients
- Output injection to Meal Planner (critical)
  - Attacker submits crafted samples instructing the LLM to generate HTML/JS; if Meal Planner renders responses unsafely, results in XSS/RCE-in-browser in the Meal Planner environment.
- Cross-tenant leakage via prompt assembly
  - If the Backend API composes prompts from stored data without strict tenant boundaries, a malicious tenant’s prompt can elicit inclusion of other tenants’ sample snippets.
- Persistent prompt poisoning
  - Poisoned samples stored for a tenant continue to produce malicious outputs over time; if templates or defaults get reused across tenants due to config bugs, this becomes cross-tenant.
- Model instruction smuggling
  - Inputs exploit the absence of robust system/assistant prompt segregation, causing the model to ignore safety instructions and disclose internal metadata from stored contexts.

5) Cost and resource abuse
- Token-burning prompts
  - Long or adversarial prompts induce large completions, exhausting shared budgets or causing financial impact on shared billing accounts.
- Rate/Quota fragmentation
  - Multiple keys for one tenant used concurrently to bypass single-key rate limits if controls are not tenant-aware.

6) Unintended data egress to OpenAI
- Over-broad prompt construction
  - Backend includes unnecessary tenant data in the prompt (e.g., full sample corpus or prior outputs) when only a subset is needed; this leaks more data to a third party than necessary.
- Logging/metadata pass-through
  - System includes internal tags/identifiers or error traces in prompt messages sent to OpenAI.

## 5. Visualize the Attack Tree

Root Goal: Compromise apps/tenants using AI Nutrition-Pro via weaknesses in AI Nutrition-Pro
[OR]
+-- A. Exploit API Gateway (Kong)
    [OR]
    +-- A1. Route/plugin misconfig allows auth bypass
    +-- A2. Over-broad ACLs grant unintended access
    +-- A3. Input filtering ineffective vs LLM payloads
    +-- A4. Rate limiting not token-aware -> cost abuse
+-- B. Abuse Web Control Plane
    [OR]
    +-- B1. Role/permission flaw exposes cross-tenant keys
    +-- B2. Key exposure in UI/API (plaintext/full key)
    +-- B3. Misconfigured ACLs propagated to gateway
    +-- B4. Social engineer onboarding to get legitimate access
+-- C. Backend API multi-tenancy flaws
    [OR]
    +-- C1. IDOR: object access without tenant checks
    +-- C2. Listing/search returns other tenants’ data
    +-- C3. Bulk export over-shares data
    +-- C4. Large retention increases breach impact
+-- D. LLM-specific output/prompt attacks
    [OR]
    +-- D1. Output injection -> downstream Meal Planner XSS
    +-- D2. Cross-tenant leakage via prompt composition
    +-- D3. Persistent sample poisoning
    +-- D4. Instruction smuggling defeats safeguards
+-- E. Cost/resource abuse
    [OR]
    +-- E1. Token-burning prompts drain budgets
    +-- E2. Multi-key concurrency bypasses per-key limits
+-- F. Unintended data egress to OpenAI
    [OR]
    +-- F1. Over-broad context sends excess tenant data
    +-- F2. Internal metadata/errors included in prompts

## 6. Attributes for Key Nodes

Scale: Likelihood (Low/Med/High), Impact (Low/Med/High/Critical), Effort (Low/Med/High), Skill (Low/Med/High), Detection Difficulty (Easy/Med/Hard)

- A1 Route/plugin misconfig: Likelihood Med; Impact High; Effort Med; Skill Med; Detection Hard
- A2 Over-broad ACLs: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Med
- A3 Filtering ineffective vs LLM: Likelihood High; Impact High; Effort Low; Skill Low; Detection Hard
- A4 No token-aware limiting: Likelihood High; Impact Med; Effort Low; Skill Low; Detection Med

- B1 Role flaw exposes keys: Likelihood Med; Impact High; Effort Med; Skill Med; Detection Med
- B2 Key exposure in UI/API: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Easy
- B3 Misconfig propagated: Likelihood Med; Impact High; Effort Med; Skill Med; Detection Hard
- B4 Social engineer onboarding: Likelihood Med; Impact Med; Effort Med; Skill Low; Detection Hard

- C1 IDOR (tenant checks absent): Likelihood Med; Impact Critical; Effort Med; Skill Med; Detection Hard
- C2 Listing/search leakage: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Med
- C3 Over-sharing in export: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Easy
- C4 Retention increases impact: Likelihood High; Impact High; Effort N/A; Skill N/A; Detection N/A (design risk)

- D1 Output injection -> XSS: Likelihood High; Impact Critical (compromises downstream clients); Effort Low; Skill Low; Detection Hard (appears as “valid content”)
- D2 Cross-tenant leakage via prompt: Likelihood Med; Impact High; Effort Med; Skill Med; Detection Hard
- D3 Persistent poisoning: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Med
- D4 Instruction smuggling: Likelihood High; Impact Med–High; Effort Low; Skill Low; Detection Hard

- E1 Token-burning prompts: Likelihood High; Impact Med; Effort Low; Skill Low; Detection Easy–Med
- E2 Multi-key concurrency: Likelihood Med; Impact Med; Effort Low; Skill Low; Detection Med

- F1 Over-broad context to OpenAI: Likelihood Med; Impact High; Effort Low; Skill Low; Detection Hard
- F2 Metadata/errors sent: Likelihood Med; Impact Med; Effort Low; Skill Low; Detection Med

## 7. Analyze and Prioritize Attack Paths

High-Risk Paths (by Impact x Likelihood):
- D1 Output injection to Meal Planner (Critical, High likelihood): Justification: The system returns LLM-generated content that downstream apps likely render; gateway “input filtering” won’t prevent malicious output, making downstream XSS highly plausible.
- C1 IDOR / tenant scoping flaws (Critical impact, Medium likelihood): Justification: Multi-tenant storage of samples and LLM logs is central; any missing tenant_id enforcement on read/write endpoints yields full cross-tenant compromise.
- A1/A2 Misconfigured Kong routes/ACLs (High impact, Medium likelihood): Justification: Kong relies on correct route/plugin order and ACL precision. Common missteps can expose sensitive operations.
- A4/E1 Lack of token-aware quotas and long prompts (High likelihood, Medium impact): Justification: Rate limiting is called out, but token-based controls are not. This can cause major cost incidents and reliability degradation.
- F1 Over-broad prompt context to OpenAI (High impact, Medium likelihood): Justification: Architectural choice to store and reuse samples/LLM traffic increases chance of excessive context assembly.

Critical Nodes to Address (mitigates multiple paths):
- Enforced per-tenant authorization at both service and data layers (addresses C1/C2/C3, D2).
- Content/output sanitization/constraints on API responses (addresses D1/D3/D4).
- Kong configuration hygiene and validation (addresses A1/A2/A3).
- Token-aware quotas and tenant-scoped rate limiting (addresses A4/E1/E2).
- Prompt construction minimization and context isolation (addresses D2/D4/F1/F2).

## 8. Mitigation Strategies (project-specific)

API Gateway (Kong):
- Route/plugin hardening:
  - Ensure key-auth and ACL plugins are attached at service and route levels consistently; prohibit anonymous access on any upstream paths used by the API.
  - Avoid overlapping/wildcard routes that could bypass plugins; explicitly test high-risk paths (export/listing/write).
- Authorization at gateway:
  - Enforce tenant binding at gateway where feasible (e.g., require a tenant identifier bound to the API key; reject requests that specify a mismatched tenant_id).
- Rate limiting by tokens:
  - Implement quotas and rate limits tied to estimated tokens (prompt + completion size), not just request count; track per-tenant not only per-key.

Web Control Plane:
- Role scoping and views:
  - Separate permissions so that App Onboarding Managers cannot view existing tenants’ full keys or sensitive configs; show only masked keys with explicit re-issue workflows.
  - Ensure tenant isolation on all control-plane pages and APIs; deny cross-tenant list/view operations by server-side checks.
- Safe key lifecycle:
  - Display only a short-lived one-time secret on creation; thereafter show only masked key identifiers; require explicit regenerate to reissue.

Backend API and Data Layer:
- Strong multi-tenancy enforcement:
  - Require tenant_id from a trusted binding (derived from API key) and validate on every request; ignore client-supplied tenant_id.
  - Enforce server-side tenant scoping in all queries; add database-level constraints (e.g., require tenant_id columns and uniqueness constraints including tenant_id).
- Safe listing/export:
  - Default-filter lists by authenticated tenant; cap page sizes; for export endpoints, re-check tenant ownership server-side and log/export only tenant-owned rows.
- Data minimization/retention:
  - Store only necessary parts of prompts/responses; age out or redact high-risk fields to reduce impact of any future exposure.

LLM Integration and Output Safety:
- Response content constraints:
  - Return structured JSON fields and explicitly disallow/strip HTML/scripts; if HTML is required for rendering, sanitize server-side with an allowlist policy and set Content-Type precisely.
  - Instruct the LLM via system prompts to emit only plain text or Markdown without HTML/script; refuse outputs violating policy.
- Prompt/context assembly:
  - Build prompts using only the current tenant’s minimal necessary context; do not include historical logs by default; never mix tenants.
  - Validate that “samples” injected into prompts are from the authenticated tenant; cap context length to reduce inadvertent leakage.
- Poisoning resistance:
  - Treat tenant-provided “samples” as untrusted; scan for dangerous patterns (e.g., instructions to output HTML/JS), and either reject or bypass such samples.

Cost Controls:
- Tenant-scoped budgets:
  - Enforce per-tenant monthly/daily token quotas and request limits; throttle or cut off when exceeded.
  - Detect unusually long prompts or completion requests and require higher tier/explicit permission.

Data Egress to OpenAI:
- Minimal disclosure:
  - Redact or omit unnecessary fields before sending to ChatGPT; include only the specific sample slices needed for the current task.
  - Strip internal metadata, identifiers, and error traces from messages sent to OpenAI.

## 9. Summary of Findings

Key Risks Identified:
- LLM output injection leading to XSS in downstream Meal Planner apps (D1).
- Multi-tenant authorization/scoping flaws in Backend API and DB (C1–C3).
- Kong misconfiguration enabling auth/ACL bypass (A1–A2) and ineffective input filtering against LLM-specific payloads (A3).
- Token-based cost abuse due to rate limiting not tied to tokens/tenant (A4/E1/E2).
- Excessive data sent to OpenAI via over-broad prompt assembly (F1).

Recommended Actions (prioritized):
- Enforce strict tenant isolation at API and DB layers; verify tenant_id server-side on every access.
- Constrain and sanitize API responses; prefer structured formats; prevent HTML/script output from LLM reaching clients.
- Review and harden Kong routes/plugins; remove anonymous paths to protected upstreams; validate ACLs.
- Implement tenant-scoped token quotas and cost-aware throttling.
- Minimize prompt context; isolate by tenant; strip internal metadata before sending to ChatGPT.

## 10. Questions & Assumptions

Questions:
- Does the Backend API ever render or pass through HTML/Markdown to clients, and how do Meal Planner apps render it?
- Are prompts assembled using any historical or shared corpus beyond the current tenant’s samples?
- How are API keys stored and displayed in the Control Plane? Are keys masked after creation?
- What exact Kong plugins and route structures are used? Any anonymous/health routes pointed to the same upstream?
- Are rate limits and quotas currently per-key or per-tenant? Any token-aware controls in place?
- What database engine is used in RDS, and can DB-level tenant constraints (e.g., RLS) be applied?

Assumptions:
- Meal Planner apps may render AI outputs into a web UI without guaranteed sanitization.
- Prompt construction may include tenant “samples” and could include historical elements within a tenant.
- API keys are the sole client authentication mechanism; no mTLS or JWT binding is currently used.
- ACLs and rate limits are primarily configured at Kong; Backend API also enforces authorization but details are unspecified.
- Stored requests/responses in the API database are retrievable via API endpoints for the owning tenant.
