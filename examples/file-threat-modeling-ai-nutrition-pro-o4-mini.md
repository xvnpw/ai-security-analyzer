# APPLICATION THREAT MODEL

## ASSETS
- API keys for Meal Planner applications
- Dietitian content samples (uploaded prompts)
- AI-generated results (LLM responses)
- Tenant configuration and billing data
- Administrator credentials
- Control Plane configuration and metadata
- LLM request/response logs stored in API database

## TRUST BOUNDARIES
- Between Internet (Meal Planner apps) and API Gateway
- Between API Gateway and Backend API
- Between Backend API and ChatGPT (external LLM)
- Between Administrator’s browser and Web Control Plane
- Between Web Control Plane and Control Plane Database
- Between Backend API and API Database

## DATA FLOWS
- MealApp → API Gateway: HTTPS/REST with API key (crosses Internet→trusted boundary)
- API Gateway → Backend API: HTTPS/REST (crosses gateway trust boundary)
- Backend API → ChatGPT: HTTPS/REST to external OpenAI API (crosses trust boundary)
- Administrator → Web Control Plane UI: HTTPS (crosses Internet→trusted boundary)
- Web Control Plane → Control Plane DB: TLS-protected connections
- Backend API → API DB: TLS-protected connections

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME            | THREAT NAME                                                                                                                                      | STRIDE CATEGORY    | WHY APPLICABLE                                                                                 | HOW MITIGATED                                                                                               | MITIGATION                                                                                                                                                 | LIKELIHOOD EXPLANATION                                         | IMPACT EXPLANATION                                                                  | RISK SEVERITY |
|-----------|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------|
| 0001      | API Gateway               | Attacker spoofs API key to impersonate a Meal Planner application and invoke AI Nutrition-Pro API                                                | Spoofing           | API Gateway authenticates clients solely with static API keys                                   | individual API keys and ACL rules in Kong but keys have no expiry or automated rotation                   | issue short-lived JWTs or HMAC-signed tokens with timestamps, enforce automated key rotation and usage monitoring                                         | medium – static keys may be leaked or shared by tenants              | high – unauthorized access to sensitive data and service misuse                         | high          |
| 0002      | API Gateway               | Tampering of request payload to bypass input filtering and ACL rules                                                                             | Tampering          | Kong filters inputs and applies ACL but may not cover all edge cases                            | basic Kong policies in place, no deep packet inspection or schema enforcement                             | enforce strict JSON schema validation at gateway and backend, integrate WAF for OWASP common payloads                                                     | medium – crafted payloads often bypass simple filters                | medium – could allow injection of unauthorized operations or data leakage                 | medium        |
| 0003      | API Gateway               | Denial of Service by exhausting per-tenant rate limits to degrade or halt service                                                                 | Denial of Service  | API Gateway rate limiting is configured but thresholds and per-tenant quotas are unspecified      | global rate limiting present, no per-tenant or adaptive throttling                                         | implement per-tenant quotas, adaptive throttling, integrate AWS Shield or WAF DDoS protection                                                              | high – automated tools can generate high volumes of calls               | high – legitimate traffic blocked and LLM costs spike                              | high          |
| 0004      | API Gateway               | Misconfiguration in ACL rules allows unauthorized access to internal or management endpoints                                                      | Elevation of Privilege | ACL rules are manually configured in Kong                                                         | no policy-as-code or automated review                                                               | define ACL policies in code with peer review, enforce path-based restrictions, use approval workflows                                                    | medium – manual config errors are common                            | high – attacker could modify system configuration or read tenant data                      | high          |
| 0005      | Backend API               | Direct access to Backend API bypassing API Gateway due to network or security group misconfiguration                                              | Spoofing           | Backend API deployed in same VPC, exposed on ECS network, no explicit restriction to Gateway      | relies on assumed security group default                                                              | restrict Backend API security group to accept traffic only from API Gateway IP ranges, enforce private subnets                                             | medium – lateral movement in VPC is feasible                         | high – bypassing authentication and authorization                                    | high          |
| 0006      | Backend API               | Prompt injection via malicious input that manipulates AI-generated content                                                                        | Tampering          | Backend API composes LLM prompts from user-supplied diet data without sanitization               | no prompt sanitization or template enforcement                                                         | apply input validation and sanitization on prompt parameters, use parameterized templates with fixed system prompt                                          | medium – prompt injection is a known LLM attack vector                | medium – malicious or harmful content generation                                      | medium        |
| 0007      | Backend API               | Information disclosure when LLM responses include PII or data from previous sessions                                                             | Information Disclosure | API DB stores past prompts/responses, LLM may bleed context                                       | no context purging or PII redaction                                                                  | purge LLM context between requests, redact PII before sending to LLM, enforce response filters                                                             | high – LLM “memory” leaks are common                                | high – leakage of personal or proprietary data                                        | high          |
| 0008      | Backend API               | Denial of Service via high-volume LLM invocations that exhaust API capacity or drive up costs                                                      | Denial of Service  | Cost and capacity tied to LLM usage, only gateway rate limits protect                              | global rate limiting at gateway                                                                 | enforce per-tenant LLM usage quotas, implement budget alarms and cost-based throttling                                                                   | medium – automated abuse possible                                    | medium – service stalls or costs become prohibitive                                | medium        |
| 0009      | Web Control Plane         | Brute-force or credential-stuffing attacks on administrator login                                                                                 | Spoofing           | Control plane UI exposed externally, no MFA or lockout described                                  | basic authentication, no MFA or CAPTCHA                                                              | enforce MFA, account lockout after failed attempts, integrate CAPTCHA                                                                                      | high – credential attacks are widespread                              | high – unauthorized system configuration and tenant/billing manipulation               | high          |
| 0010      | Web Control Plane         | Tampering of tenant configuration or billing settings via insufficient authorization checks                                                      | Tampering          | Control plane manages client config and billing, no RBAC defined                                   | single admin role, no fine-grained RBAC                                                              | implement role-based access control, validate permissions per operation                                                                                    | medium – missing RBAC common in early designs                        | high – revenue loss or misconfigurations                                             | high          |
| 0011      | Web Control Plane         | Information disclosure of other tenants’ data through insecure API or UI endpoints                                                                | Information Disclosure | UI/API endpoints return tenant data without field-level authorization                              | no field-level ACL, no tenant-isolation checks                                                      | enforce field-level ACL, validate tenant context on each request                                                                                           | medium – multi-tenant leaks often due to missing checks               | medium – leak of configuration or billing details to other tenants                     | medium        |
| 0012      | Control Plane Database    | Theft of database credentials leads to unauthorized read/write access to control plane data                                                      | Spoofing           | DB credentials likely stored in ECS environment or parameter store, rotation unspecified          | IAM roles may permit Secrets Manager access, but no rotation                                        | store credentials in AWS Secrets Manager with automatic rotation, restrict IAM roles, use encryption at rest                                              | medium – credential leaks possible via compromised containers         | high – full compromise of control plane data                                          | high          |
| 0013      | Control Plane Database    | SQL injection via unsanitized control plane inputs leading to data tampering or exfiltration                                                     | Tampering          | Control plane uses user inputs to build SQL queries, sanitization unspecified                    | no evidence of parameterized queries                                                              | use parameterized queries or ORM, validate and sanitize all inputs                                                                                         | medium – SQL injection remains a top risk                             | high – data corruption or unauthorized access                                         | high          |
| 0014      | API Database              | Unauthorized read of API DB exposing dietitian samples and LLM request/response history                                                           | Information Disclosure | API DB stores proprietary content and interaction history                                         | no per-user DB permissions described                                                               | enforce least-privilege DB roles, enable encryption at rest, restrict access via network ACL                                                              | medium – lateral access from compromised components                   | high – exposure of proprietary or personal data                                      | high          |

# DEPLOYMENT THREAT MODEL

## Deployment Options
1. AWS ECS Fargate with public Application Load Balancer, private subnets for tasks, RDS in private subnets
2. AWS ECS on EC2 instances in a VPC
3. Self-hosted Kubernetes on-prem

Chosen architecture: AWS ECS Fargate in private subnets behind a public ALB, Amazon RDS in private subnets.

## ASSETS
- VPC, public/private subnets
- Security groups and network ACLs
- Application Load Balancer (ALB)
- ECS Fargate task definitions and containers
- Amazon RDS instances (Control Plane DB, API DB)
- IAM roles for ECS tasks and admin users
- AWS Secrets Manager or Parameter Store for secrets
- Container images in ECR

## TRUST BOUNDARIES
- Internet ↔ ALB
- ALB ↔ ECS tasks
- ECS tasks ↔ RDS
- AWS Management Console ↔ AWS resources
- Developer workstation/CI ↔ ECR and code repository

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                                                              | WHY APPLICABLE                                                          | HOW MITIGATED                                                                                       | MITIGATION                                                                                                                                | LIKELIHOOD EXPLANATION                              | IMPACT EXPLANATION                                              | RISK SEVERITY |
|-----------|----------------------|----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|------------------------------------------------------------------|---------------|
| 0001      | Application Load Balancer | Publicly accessible ALB may allow unauthorized IPs to reach API Gateway                                       | ALB exposes ports 80/443 to Internet                                       | security group allows 0.0.0.0/0 on 80/443                                                           | restrict ingress to known tenant IP ranges, integrate AWS WAF with IP allowlists                                                              | high – Internet-facing endpoints are frequent targets    | medium – increases attack surface but gateway still enforces auth    | medium        |
| 0002      | ECS Task IAM Role     | Over-privileged IAM role attached to ECS tasks allows lateral access to other AWS services                 | ECS tasks require access to RDS and Secrets Manager                         | single IAM role with broad permissions assumed                                                     | apply least privilege to task roles, separate roles per service, use IAM policies with lowest privileges                                     | medium – roles often over-privileged by default         | high – attacker can escalate to other AWS resources               | high          |
| 0003      | Security Groups       | Misconfigured security groups allow RDS instance to accept connections from Internet                      | RDS resides in VPC, SG rules define access                                  | unspecified; assumed default deny for public, but misconfig risk                                    | ensure RDS SG only allows inbound from ECS task SG, deny 0.0.0.0/0, enforce VPC endpoints for AWS services                                      | medium – human error in SG is common                   | high – direct DB compromise                                     | high          |
| 0004      | Amazon ECR            | Public or misconfigured private ECR repository exposes container images to unauthorized users             | Images stored in ECR, access controls not defined in spec                   | repository assumed private but not enforced                                                       | enforce private repo, enable image scanning, require image signing (Cosign) before deploy                                                      | medium – default ECR repos can be public                | medium – malicious images run in production                        | medium        |
| 0005      | AWS Management Console | Weak IAM policies or missing MFA for admin roles leads to console compromise                               | Administrators manage resources via AWS console                             | no MFA or least-privilege policy specified                                                       | enforce MFA for all admin/root users, adopt least-privilege IAM policies, monitor console login patterns                                       | medium – credential theft and phishing common           | high – full environment takeover                                | high          |
| 0006      | Network Egress        | Unrestricted outbound egress from ECS tasks allows compromised containers to exfiltrate data or call C2    | ECS SG may allow 0.0.0.0/0 egress by default                                 | not specified                                                                                      | restrict egress to only necessary endpoints (OpenAI API, DB subnet), use VPC endpoints to limit Internet egress                               | medium – wide TLS egress common in microservices        | medium – data exfiltration or unwanted external communication       | medium        |

# BUILD THREAT MODEL

## ASSETS
- Source code repository (e.g., Git)
- Go module dependencies and go.sum file
- Dockerfiles and build scripts
- CI/CD pipeline definitions and runner credentials
- Container images in registry

## TRUST BOUNDARIES
- Developer workstation ↔ source code repository
- CI/CD runner ↔ source code repository
- CI/CD runner ↔ container registry
- External module registry (proxy to public modules) ↔ build system

## BUILD THREATS

| THREAT ID | COMPONENT NAME            | THREAT NAME                                                                                         | WHY APPLICABLE                                                              | HOW MITIGATED                                                                                       | MITIGATION                                                                                                                           | LIKELIHOOD EXPLANATION                                | IMPACT EXPLANATION                                               | RISK SEVERITY |
|-----------|---------------------------|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|-----------------------------------------------------------------|---------------|
| 0001      | Source Code Repository    | Unauthorized commit or branch modification via compromised repository credentials                    | Code hosted in Git with no pipeline described                                | no VCS hardening specified                                                                        | enforce MFA on VCS, protect branches with required reviews, enable push restrictions                                             | medium – stolen tokens enable pushes                  | high – backdoors or data exfiltration                             | high          |
| 0002      | Dependency Management     | Malicious or vulnerable third-party Go module injected via dependency update                         | Go modules used, go.sum present but not verified                              | go.sum provides checksum but no audit                                                               | pin module versions, regularly audit go.sum, use vulnerability scanning tools                                                    | medium – supply chain attacks increasing               | medium – introduces critical vulnerabilities                       | medium        |
| 0003      | Dockerfile / Build Scripts | Tampering of Dockerfile or build scripts to include malicious steps                                 | Build scripts and Dockerfiles stored in same repo as code                     | no integrity checks described                                                                       | store Dockerfiles in protected folder, sign build scripts, implement pipeline-as-code with reviews                                    | low-medium – insiders or CI compromise required      | high – malicious images can compromise production                  | medium        |
| 0004      | CI/CD Runner              | Compromise of CI/CD runner credentials leads to unauthorized builds or deployments                  | CI/CD runner likely has deploy permissions                                    | no runner isolation or token rotation described                                                     | use ephemeral runners, isolate builds in dedicated accounts, rotate CI tokens frequently                                         | medium – CI systems targeted by attackers             | medium – unauthorized artifacts or deployments                     | medium        |
| 0005      | Container Registry        | Pulling unverified or unsigned container images into production                                      | Registry policies not specified                                                | registry assumed private, no signing                                                             | enforce image signing (Cosign), scan images for vulnerabilities, require signed manifests before deployment                        | low-medium – signing adoption growing but not universal | high – running malicious images undermines entire system security   | medium        |

# QUESTIONS & ASSUMPTIONS

- What is the exact network layout (public/private subnets, VPC endpoints, peering) for ECS tasks and RDS?
- How are API keys and other secrets stored and rotated (Parameter Store, Secrets Manager, env vars)?
- Is there an existing CI/CD pipeline (GitHub Actions, Jenkins, etc.) and are there SAST or container image scans configured?
- Are database instances encrypted at rest and in transit, and is automated backup enabled?
- Does the Web Control Plane use any RBAC framework or support multi-factor authentication?
- Are there WAF rules or AWS Shield protections in front of the ALB?
- Do you enforce tenant isolation at network, application, and data layers?

Assumptions made:
- AWS ECS Fargate is used in private subnets behind a public ALB.
- No existing WAF or DDoS protections beyond basic rate limits.
- Secrets are stored but rotation and access control are not fully automated.
- CI/CD pipeline details are unspecified and assumed minimal.
- Default security group rules may allow broad ingress/egress without further restrictions.
