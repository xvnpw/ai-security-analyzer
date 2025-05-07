MITIGATION STRATEGIES

• Tenant-scoped API key life-cycle management
  – Description
    1. Issue a different API key for every Meal Planner tenant at onboarding time.
    2. Store only a salted hash of the key inside Control-Plane DB.
    3. Expose rotation endpoint in the Web Control Plane so tenants can roll keys without support intervention.
    4. Add automatic expiry metadata (e.g., 90 days) and send expiration-warning web-hooks.
    5. Revoke keys immediately on tenant off-boarding and propagate the revocation list to Kong via its Admin API.
  – Threats mitigated
    • Stolen/Leaked API key abuse – HIGH
    • Cross-tenant data access via shared credentials – HIGH
    • Long-lived key replay attacks – MEDIUM
  – Impact
    • Eliminates unlimited-lifetime keys, reducing likelihood of successful abuse from “very likely” to “low”.
  – Currently implemented
    • “each has individual API key” (Architecture §Security-1). No rotation, expiry, or revocation workflow.
  – Missing implementation
    • Key hashing, expiry metadata, automated rotation endpoint, and revocation propagation.

• Prompt-injection resistant request templating
  – Description
    1. Accept user dietitian samples in a dedicated JSON field; do not concatenate raw text into the system prompt.
    2. Build an immutable system prompt template; insert the sample inside delimited boundaries (e.g., triple-bracket tokens).
    3. Escape brackets and other meta-characters inside the user sample.
    4. Reject samples containing known jailbreak strings (e.g., “/system”, “Assistant:”).
    5. Keep user content and system instructions in different ChatGPT messages (role=”user” vs. role=”system”).
  – Threats mitigated
    • Prompt injection leading to data exfiltration or policy override – HIGH
    • Malicious content persistence into API DB – MEDIUM
  – Impact
    • Cuts success rate of prompt-injection from “probable” to “rare”.
  – Currently implemented
    • None mentioned beyond “filtering of input” at Kong; no LLM-specific protections.
  – Missing implementation
    • Prompt template, delimiter escaping, role-segregation, input reject rules.

• Post-LLM output safety filter
  – Description
    1. Run every ChatGPT response through OpenAI moderation endpoint or an in-house classifier.
    2. Reject or mask disallowed content (hate speech, medical misinformation).
    3. Attach moderation result to the response stored in API DB for audit purposes.
    4. Return safe-error code (HTTP 422) to caller when content is blocked.
  – Threats mitigated
    • Delivery of harmful or non-compliant text to end users – HIGH
    • Compliance liability (medical advice) – HIGH
  – Impact
    • Reduces probability of harmful content from “possible” to “very unlikely”.
  – Currently implemented
    • Not mentioned.
  – Missing implementation
    • Moderation call, error mapping, storage of moderation verdict.

• Row-level tenant isolation in Control-Plane DB and API DB
  – Description
    1. Add tenant_id column to every table that stores business data.
    2. Use Postgres/ MySQL row-level security policies to automatically append “WHERE tenant_id = :ctx” to every query.
    3. Inject tenant_id into database connection context based on validated API key.
    4. Include unit tests verifying that cross-tenant queries return zero rows.
  – Threats mitigated
    • Accidental or malicious cross-tenant data leakage – HIGH
  – Impact
    • Brings cross-tenant disclosure likelihood down to “very low”.
  – Currently implemented
    • Logical separation implied but not enforced at database level.
  – Missing implementation
    • RLS policies, tenant context injection, automated tests.

• PII redaction before persistence and LLM submission
  – Description
    1. Run a lightweight PII detector on uploaded dietitian samples.
    2. Replace e-mail, phone, names with consistent placeholders before storing and before forwarding to ChatGPT.
    3. Keep the mapping only in tenant’s own RDS schema encrypted with KMS; never transmit mapping to LLM.
  – Threats mitigated
    • Exposure of personally identifiable or sensitive health data to OpenAI – HIGH
    • Breach impact if API DB compromised – MEDIUM
  – Impact
    • Converts exposure impact from “high” to “low”.
  – Currently implemented
    • Not mentioned.
  – Missing implementation
    • PII detector, placeholder substitution pipeline, encrypted mapping storage.

• Cost & abuse guardrails for ChatGPT usage
  – Description
    1. Store per-tenant monthly token quota in Control-Plane DB.
    2. After Kong authentication, pass tenant_id to Backend-API which decrements a Redis counter per request.
    3. Block requests when quota exhausted; return HTTP 429.
    4. Expose self-service quota dashboard in Web Control Plane.
  – Threats mitigated
    • Unexpected cost spikes due to runaway calls – HIGH
    • Denial of wallet attacks – MEDIUM
  – Impact
    • Caps financial exposure; makes cost predictable.
  – Currently implemented
    • Kong rate limiting exists, but not token-based LLM quota.
  – Missing implementation
    • Token counters, quota enforcement, dashboard.

• Size-and-schema validation in API Gateway
  – Description
    1. Configure Kong “request-size-limiting” plugin (e.g., 1 MB).
    2. Add Kong “JSON-schema-validator” plugin with explicit schema for dietitian sample uploads.
    3. Reject oversize or schema-violating requests before they reach containers.
  – Threats mitigated
    • Resource exhaustion / DoS on Backend-API – MEDIUM
    • Injection of unexpected fields that bypass business logic – MEDIUM
  – Impact
    • Lowers attack surface; DoS feasibility from “moderate” to “low”.
  – Currently implemented
    • Kong exists; no evidence of size or schema plugins configured.
  – Missing implementation
    • Plugin configuration in Kong declarative file.

• Fine-grained IAM roles for ECS tasks
  – Description
    1. Create a distinct IAM role for Web Control Plane and for Backend-API.
    2. Grant Backend-API only “rds-db:connect” to API DB and “secretsmanager:GetSecretValue” for OpenAI key.
    3. Deny outbound access to AWS services not required (e.g., S3).
    4. Enable task role session names carrying container id for audit.
  – Threats mitigated
    • Lateral movement from compromised container to other AWS resources – HIGH
    • Secret exfiltration – MEDIUM
  – Impact
    • Limits blast radius; reduces post-compromise impact from “high” to “low”.
  – Currently implemented
    • ECS deployment is mentioned but IAM scoping not described.
  – Missing implementation
    • Separate roles, restrictive policies, deny-by-default.

• Secure storage of OpenAI / ChatGPT credentials
  – Description
    1. Store OpenAI API key in AWS Secrets Manager with KMS encryption.
    2. Inject secret into ECS task as an environment variable at runtime via task role.
    3. Rotate the secret quarterly and automatically restart tasks.
  – Threats mitigated
    • Theft of LLM credentials leading to cost abuse or data access – HIGH
  – Impact
    • Lowers likelihood of secret theft from “medium” to “very low”.
  – Currently implemented
    • Not mentioned.
  – Missing implementation
    • Secrets Manager usage, rotation, task restart hooks.

These nine targeted strategies address the specific risk landscape of AI Nutrition-Pro without drifting into generic operational controls.
