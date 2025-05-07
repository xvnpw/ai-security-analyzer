APPLICATION THREAT MODEL
========================

ASSETS
------

1. Tenant API keys (authentication secrets for Meal Planner applications)
2. Dietitians’ sample content provided by tenants
3. Generated LLM responses
4. Tenant configuration and billing data (Control Plane DB)
5. Service-to-service credentials (DB passwords, AWS IAM roles, OpenAI API key)
6. Audit logs (API Gateway, Web Control Plane, Backend API)
7. Availability of the AI Nutrition-Pro API itself

TRUST BOUNDARIES
----------------

1. Internet ↔ API Gateway (external clients cross into internal cloud)
2. Internet ↔ Web Control Plane (administrator access)
3. API Gateway ↔ Backend API (internal service call)
4. Backend API ↔ ChatGPT-3.5 (egress to third-party SaaS)
5. Web Control Plane ↔ Control Plane DB
6. Backend API ↔ API DB
7. Administrator workstation ↔ Web Control Plane

DATA FLOWS
----------

DF1  Meal Planner → API Gateway (HTTPS/REST)  [CROSSES 1]
DF2  API Gateway → Backend API (HTTPS, internal)  [CROSSES 3]
DF3  Backend API → ChatGPT-3.5 (HTTPS)  [CROSSES 4]
DF4  Backend API ↔ API DB (TLS)
DF5  Administrator → Web Control Plane (HTTPS)  [CROSSES 2 & 7]
DF6  Web Control Plane ↔ Control Plane DB (TLS)

APPLICATION THREATS (STRIDE per element)
----------------------------------------

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | API Gateway (Kong) | Brute-forcing or enumeration of tenant API keys to impersonate Meal Planner apps | Spoofing | Gateway relies on shared secret API keys; attacker can test key space over Internet | Only rate-limiting is mentioned | Enforce strong, randomly-generated keys; limit key reuse; add IP reputation checks and automatic key rotation | Medium – keys can be guessed over time despite rate limit | Full tenant impersonation, data exfiltration, billing fraud | High |
| 0002 | API Gateway | Crafted payload bypasses input filter and injects malicious prompt into LLM chain | Tampering | Gateway filters “input” but LLM prompt safety isn’t detailed | No mention of contextual filtering for LLM | Add prompt sanitisation and output moderation layer before calling ChatGPT | Medium | Could poison model response, leak sensitive data, reputational damage | High |
| 0003 | Backend API | Cross-tenant request (tenant A ID in header/body) accesses tenant B data | Tampering | Backend API builds queries based on tenant identifier | Not described | Enforce authenticated tenant context in database queries, row-level security | Medium | Regulatory exposure, loss of trust | High |
| 0004 | Backend API ↔ ChatGPT | Prompt-response contains another tenant’s data due to context bleed or system prompt injection | Information Disclosure | LLM may keep history / system prompt; multi-tenant context mixing a risk | No isolation described | Use separate conversations per request; strip PII; control tokens; use content filters | Medium | Confidential data leakage | High |
| 0005 | Backend API | LLM returns executable code which backend blindly executes (e.g., eval in template) | Elevation of Privilege | If backend reflects LLM output in subsequent processing | Not mitigated in doc | Never execute LLM output; treat as untrusted data | Low | Remote code execution compromise | Critical |
| 0006 | API Database | Poisoning of stored dietitian samples via repeated malicious uploads | Tampering | Meal Planner can upload arbitrary text | No validation described | Content validation, rate & size limits, quarantine scans | Medium | Model drift, offensive content generation | Medium |
| 0007 | API Gateway | Bypass rate limiting via distributed attack → overwhelm backend | Denial of Service | Gateway rate limits per-IP; attacker uses botnet | Partially mitigated by rate limit | Add global token bucket per tenant, upstream WAF, auto-scale Gateway | Medium | Service unavailability for all tenants | High |
| 0008 | Web Control Plane | Session hijack of administrator cookie → change billing data | Spoofing | Admin uses browser session over Internet | Only TLS mentioned | Secure cookies, MFA, short session TTL, CSRF tokens | Medium | Financial impact & mis-configuration | High |
| 0009 | Control Plane DB | Unauthorized SQL modification of billing tables by exploited Web Control Plane | Tampering | Same container houses app logic & db credentials | Not mitigated | Use least-privileged DB user, write-only role separation | Low | Over-/under-billing of customers | Medium |
| 0010 | Backend API | Missing request logging allows repudiation of abusive tenant actions | Repudiation | Tenants might deny content they submitted | Not addressed | Signed request IDs, immutable logs, per-tenant audit retention | Medium | Disputes, legal issues | Medium |
| 0011 | API Gateway | Error message leaks internal stack traces, DB DSN | Information Disclosure | Kong may pass upstream errors verbatim | Not stated | Custom error handler, scrub headers | Medium | Facilitates further attacks | Medium |
| 0012 | Backend container | Privilege escalation inside container → break isolation and access host | Elevation of Privilege | Running on ECS with potentially privileged mode | Not stated | Drop Linux capabilities, read-only FS, seccomp/apparmor | Low | Compromise other containers / AWS credentials | Critical |

DEPLOYMENT THREAT MODEL
=======================

The platform is expected to run on AWS using:

• AWS Application Load Balancer → Kong (ECS/Fargate)
• Backend API (ECS/Fargate)
• Web Control Plane (ECS/Fargate)
• Two Amazon RDS (PostgreSQL) in private subnets
• NAT gateway egress to ChatGPT-3.5 API

ASSETS
------

1. AWS IAM roles and policies assigned to ECS tasks
2. RDS instances and snapshots (tenant and billing data)
3. Secret values stored in AWS Secrets Manager (DB creds, OpenAI key)
4. Network perimeter (VPC, Security Groups)
5. Container images stored in ECR

TRUST BOUNDARIES
----------------

1. Public ALB ↔ VPC (Internet to AWS)
2. VPC private subnet ↔ NAT gateway (egress to ChatGPT)
3. ECS tasks ↔ RDS (database subnet boundary)
4. ECS tasks ↔ AWS control plane (IAM role boundary)
5. ECR ↔ CI/CD pipeline pushing images

DEPLOYMENT THREATS
------------------

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D-01 | ECS Task IAM Role | Over-privileged task role used by Backend API allows S3:* and RDS:* | Service only needs SecretsManager:Get + RDS connect | Not described | Apply least-privilege IAM policy, use permissions boundary | Medium | Stolen credentials → lateral movement | High |
| D-02 | RDS Snapshot | Automated snapshots copied to public share by mistake | RDS snapshots default private but can be shared | No control plane guard | Enable org-level SCP blocking public share; snapshot encryption | Low | Full disclosure of tenant data | Critical |
| D-03 | Security Groups | Misconfiguration leaves RDS port 5432 open to Internet | Possible user error | Not described | Use SG inbound only from ECS, config drift detection | Low | Direct DB compromise | High |
| D-04 | NAT Gateway | Malicious code in container exfiltrates data to random domain | NAT allows any egress | No egress restrictions | Add egress SG/Network ACL allow-list only ChatGPT endpoints | Medium | Data exfil to attacker | High |
| D-05 | ECR Image | Public base image is replaced upstream with malicious layer | Pulls latest alpine/golang | Not mitigated | Pin digest, enable ECR image scanning, use private base | Medium | Backdoor in production containers | High |
| D-06 | Secrets Manager | Secret value exposed via mis-configured IAM policy of developer | Dev role allows secrets:Get* | Not described | Split prod & dev secrets, MFA session for read, audit alerts | Medium | Credential misuse | High |
| D-07 | ALB | HTTP to HTTPS redirect disabled accidentally → plaintext creds | Human error during TF change | Not mitigated | Enforce HTTPS via AWS Config rule, HSTS | Low | API keys intercepted | Medium |

BUILD THREAT MODEL
==================

ASSETS
------

1. Source code repositories (Golang services, Kong configs)
2. Container build pipeline definition (e.g., GitHub Actions)
3. AWS deployment credentials (OIDC or long-lived keys)
4. Container registry (ECR)
5. Third-party dependencies (go modules)

TRUST BOUNDARIES
----------------

1. Developer laptop ↔ Git hosting (push)
2. Git hosting ↔ CI runner
3. CI runner ↔ AWS (deploy)
4. CI runner ↔ Internet (dependency download, base image pull)

BUILD THREATS
-------------

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B-01 | GitHub Actions Workflow | PR from fork can run build with AWS OIDC token and push malicious image | Public repo default allows `pull_request` workflows | Not specified | Require `permissions: write-none`, environment protection rules | Medium | Compromised prod image | High |
| B-02 | Dependency Management | Malicious go module typosquatting `github.com/openai/go-sdk` | Backend imports many libs | No mention of checksum | Enable `GONOSUMDB`, use checksum DB, periodic audit | Medium | Backdoor insertion | High |
| B-03 | Build Cache | Poisoning Docker layer cache on shared runner | Multiple projects share runners | Not mitigated | Isolate cache per repo, verify image digest | Low | Build produces trojaned binary | Medium |
| B-04 | Release Signing | Container images not signed → attacker pushes impostor tag | ECR accepts any tag if creds valid | Not mitigated | Enable Sigstore Cosign signing & verify in deploy | Medium | Supply-chain attack | High |
| B-05 | Secrets in CI | OpenAI key stored as plain env var in workflow logs | CI echoes commands | Not mitigated | Use masked secrets, avoid `set -x`, rotate keys | Medium | Key theft → cost abuse | High |
| B-06 | Static Analysis | SAST skipped; hard-coded DB creds make it into repo | Developers forget | Not mitigated | Mandatory SAST job blocking merge | Low | Secrets leak, easier exploit | Medium |

QUESTIONS & ASSUMPTIONS
-----------------------

1. Assume AWS ECS Fargate is the chosen deployment model; confirm whether EKS or EC2 is used instead.
2. Are separate AWS accounts used for dev/stage/prod? Threats above assume single account.
3. Is Kong deployed as a dedicated container per tenant or shared? Cross-tenant attacks considered shared.
4. What logging/audit mechanisms exist? Repudiation threats assume minimal logging.
5. Does Backend API ever execute or template LLM output? EoP Threat 0005 assumes unsanitised use.
6. Build pipeline assumed to be GitHub Actions using OIDC to AWS; confirm tooling.
7. NAT egress restriction to ChatGPT not confirmed; threats consider unrestricted egress.

Default assumptions were made where documentation is silent; update sections once architecture clarifications are available.
