APPLICATION THREAT MODEL

ASSETS

- Meal Planner Application API Keys: Unique keys issued to each Meal Planner app for authentication.
- Dietitian Content Samples: Uploaded by Meal Planner applications, considered proprietary and possibly sensitive.
- AI-generated Content: Including generated dietary advice/results sent to clients.
- Billing and Tenant Configuration Data: Managed by Web Control Plane, sensitive to both billing and functional operations.
- Application Configuration: Managed by Admin via Control Plane, may contain operational secrets.
- LLM Requests and Responses: Requests to and responses from ChatGPT-3.5, could inadvertently leak sensitive/request context.
- User Credentials (for Admin/Managers): Used for accessing and configuring the Web Control Plane.

TRUST BOUNDARIES

1. Between Meal Planner Applications (External) and API Gateway (Internal).
2. Between API Gateway and Backend API.
3. Between Backend API and ChatGPT-3.5 (External).
4. Between Web Control Plane and Control Plane Database.
5. Between API Application and API Database.
6. Between Admin (Internal) and Web Control Plane.
7. Between Backend API and API Database.
8. AWS Elastic Container Service deployment environment vs External Internet.

DATA FLOWS

1. Meal Planner App → API Gateway: Content sample/file uploads, fetch AI results (Crosses trust boundary #1)
2. API Gateway → Backend API: Forwarded above requests (Crosses trust boundary #2)
3. Backend API → ChatGPT-3.5: Sends content samples for LLM processing; receives generated responses (Crosses trust boundary #3)
4. Admin → Web Control Plane: Administration/configuration (Crosses trust boundary #6)
5. Web Control Plane ↔ Control Plane Database: Config/billing/tenant data (Crosses trust boundary #4)
6. Backend API ↔ API Database: Store dietitian content, LLM logs, etc. (Crosses trust boundary #7)
7. API Application ↔ API Database: Data requests and storage (Crosses trust boundary #7)
8. System deployment: Internet ↔ AWS ECS (Crosses trust boundary #8)

APPLICATION THREATS

| THREAT ID | COMPONENT NAME    | THREAT NAME                                                                                                                                                    | STRIDE CATEGORY | WHY APPLICABLE                                                                                                     | HOW MITIGATED                                               | MITIGATION                                                                                  | LIKELIHOOD EXPLANATION                                  | IMPACT EXPLANATION                                                              | RISK SEVERITY |
|-----------|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------|--------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|---------------------------------------------------------------------------------------------|---------------------------------------------------------|----------------------------------------------------------------------------------|---------------|
| 0001      | API Gateway       | Attacker replays or guesses API keys of Meal Planner applications to access AI Nutrition-Pro                                                                   | Spoofing         | API keys issued to external apps, high value, subject to interception/guessing                                      | API Gateway authenticates and rate limits                   | Enforce key rotation, use stronger credentials, enable anomaly detection                     | Moderate: API keys can be leaked but rate limits help   | Could expose all application functionality, cause DoS, data theft               | High          |
| 0002      | API Gateway       | Malicious or malformed requests bypass input filtering and are processed by backend services                                                                   | Tampering        | Handles user-supplied data (content samples), improper filtering is common attack vector                           | Uses API Gateway to filter input                           | Implement strict schema validation, deep content inspection                                 | Moderate: Possible bypass with clever evasion           | Could let attacker poison content, cause app errors, impact LLM-integrity       | High          |
| 0003      | API Application   | Unauthorized Meal Planner app gains access to dietitian content samples or generated responses of other tenants                                                | Information Disclosure | Multi-tenant, per-tenant info separation required                                                          | API Gateway ACLs, per-tenant auth                          | Enforce strict tenant isolation, review ACLs, audit access controls                           | Low: ACLs in place, but risk exists                     | Data breach, commercial/regulatory harm for clients                             | Medium        |
| 0004      | Backend API       | Attacker manipulates request/response payloads to/from ChatGPT-3.5 (e.g., prompt injection or data exfiltration)                                               | Tampering        | LLMs can be manipulated via crafted input, responses can leak data or cause misbehavior                           | Not covered in design                                      | Filter/monitor prompts, sanitize both input and LLM output                                   | Moderate: Novel attack but possible                     | Poisoning of responses, exfiltration of internal data, reputational damage      | High          |
| 0005      | Control Plane DB  | Unauthorized access to tenant and billing configuration data                                                                                                   | Information Disclosure | Stores highly sensitive operational and financial data                                                     | Implicit via internal-only access                          | Encrypt data at rest, strong RBAC, enforce access auditing                                   | Low: Internal database is more protected                 | Could cause billing fraud, privacy breach, regulatory risk                     | Medium        |
| 0006      | API Database      | Injection or corruption of stored LLM prompts or responses (e.g., stored prompt/response manipulation)                                                         | Tampering        | Application stores LLM interaction history, which may be consumed/relied on downstream                            | Not described                                               | Input sanitation, checksum/hashing, output validation                                       | Moderate: Depends on input controls                      | Persistent compromise of AI outputs, data integrity violation                  | High          |
| 0007      | Web Control Plane | Escalation of privileges by administrator impersonation in web control plane interface                                   | Elevation of Privilege | Admin interface controls all system config, impersonation/abuse is high value                                     | Not specified                                               | MFA for admin logins, session security, audit/admin separation                               | Low: Admin access considered rare                        | Total system compromise                                                        | High          |

DEPLOYMENT THREAT MODEL

Possible deployment architectures:
1. All containers host-networked within a single AWS VPC, with AWS-managed RDS and internet-facing API Gateway.
2. Split availability zones for ECS and RDS, with network segregation.
3. Air-gapped ECS with only API Gateway exposed via public ALB.

Modeling Deployment Option 1: All containers in single AWS VPC; RDS managed in same VPC; API Gateway (Kong) internet-exposed via AWS ALB.

ASSETS

- AWS VPC network segmentation
- Running containers (API Gateway, Control Plane, API Application)
- RDS Databases (API and Control Plane)
- AWS IAM roles used for in-cluster communication
- ECS Task definitions and container images

TRUST BOUNDARIES

- External Internet vs AWS VPC/ALB
- AWS ALB vs API Gateway container
- API Gateway vs ECS internal service mesh (API Application, Web Control Plane)
- ECS containers vs RDS over private subnets
- AWS IAM management plane vs deployed resources

DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME           | THREAT NAME                                                                                   | WHY APPLICABLE                                                                                   | HOW MITIGATED                | MITIGATION                                                                                     | LIKELIHOOD EXPLANATION                             | IMPACT EXPLANATION                                                       | RISK SEVERITY |
|-----------|-------------------------|----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|------------------------------|------------------------------------------------------------------------------------------------|----------------------------------------------------|---------------------------------------------------------------------------|---------------|
| 0001      | API Gateway ALB         | Port scanning/discovery attack on public ALB/API Gateway                                      | ALB is exposed to Internet, could reveal open services                                           | Not described                | Restrict to whitelisted IPs if possible; hide internal error details; use WAF                 | High: All public endpoints targeted automatically    | Discovery and enumeration of service, informs further attacks             | Medium        |
| 0002      | ECS Containers          | Container breakout; attacker gains ECS host-level access                                      | Failure in container isolation allows host compromise                                            | Standard ECS isolation        | Enable task-level IAM isolation, apply least privilege, run unprivileged containers           | Low: ECS is robust but misconfigs exist              | Could fully compromise app infrastructure                                | High          |
| 0003      | RDS Instance            | Attacker laterally moves from compromised ECS task to RDS database                            | ECS network allows connections to RDS private IP; risk if app task compromised                  | Not described                | Enforce strict security groups, disable non-task DB access, use IAM auth for DB access        | Moderate: Lateral movement after initial compromise   | Data exfiltration or corruption, system-wide impact                      | High          |
| 0004      | IAM Roles               | IAM credentials hijacked from container environment                                           | Short-lived credentials in ECS can be misused                                                    | Not described                | Rotate roles aggressively, environment hardening, monitor credential use                      | Moderate: Known container risk                        | Account takeover, data theft, persistent foothold                        | High          |
| 0005      | Container Images        | Supply chain attack via compromised or vulnerable container image                             | Containers deployed from registry, images could be poisoned                                      | Not described                | Immutable image digests; frequent scanning for vulnerabilities                                | Low: With reputable sources, rare but possible         | Attacker runs custom code within internal network                        | High          |

BUILD THREAT MODEL

ASSETS

- Source code for API Gateway, Backend API, Web Control Plane
- Container build configurations (Dockerfiles, ECS definitions)
- Image registries for containers
- Build secrets (e.g., tokens for pushing images, build environment credentials)

TRUST BOUNDARIES

- Developer workstations vs Source code repository
- CI pipeline vs production image registry
- Source code repo vs external dependencies
- Build pipeline vs AWS deployment environment

BUILD THREATS

| THREAT ID | COMPONENT NAME           | THREAT NAME                                                                                     | WHY APPLICABLE                                                                   | HOW MITIGATED  | MITIGATION                                                                               | LIKELIHOOD EXPLANATION                                  | IMPACT EXPLANATION                                                 | RISK SEVERITY |
|-----------|-------------------------|-----------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|---------------|------------------------------------------------------------------------------------------|---------------------------------------------------------|---------------------------------------------------------------------|---------------|
| 0001      | Build Pipeline          | Compromised build pipeline injects malicious code into containers                             | If CI or pipeline is exposed/compromised, attacker controls code/modules         | Not described | Restrict CI access, run static source analysis, restrict who can push to main branches    | Moderate: Supply chain attacks rising                     | May deliver malicious code to prod, system-wide compromise          | High          |
| 0002      | Container Image Registry| Registry poisoning (attacker overwrites trusted container image with malicious version)        | Registry used as source-of-truth for deploy                                      | Not described | Use image signing, immutable images, RBAC on registry                                   | Low: With RBAC and image signing, low but possible          | Full compromise of deployed code                                  | High          |
| 0003      | Build Secrets           | Leakage of build secrets/tokens into built containers or logs                                 | Secrets needed in build, risk of disclosure                                      | Not described | Use dedicated secrets management, strict separation of build/runtime secrets             | Moderate: Often occurs through misconfig                    | Attacker gains access to deployment, privilege escalation, etc.     | High          |

QUESTIONS & ASSUMPTIONS

1. Are all containers and database services deployed within private subnets or is any exposed to the Internet outside of API Gateway?
2. Is API Gateway (Kong) configured for mutual TLS or only API key authentication?
3. Are admin and operator accounts on Web Control Plane protected via MFA and strict RBAC?
4. Are container images built from scratch or based on public open-source images?
5. Are end-to-end logs and monitoring outside of application responsibility (left out per instructions)?
6. No mention of code signing, supply chain monitoring, or SAST in build process documentation.

Assumptions:
- All RDS databases are in the same VPC as ECS cluster and not internet-facing.
- API Gateway is the only point of ingress from the Internet.
- Only API Gateway presents public endpoints; others are private.
- All communication uses TLS in transit.
- Security mitigations not explicitly mentioned are presumed missing/not implemented unless stated.
