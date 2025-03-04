# APPLICATION THREAT MODEL

## ASSETS

1. API Keys - Valuable credentials that enable external Meal Planner applications to authenticate and access AI Nutrition-Pro API.
2. Control Plane Database - Tenant information, billing data, and application configuration.
3. API Application Database - Dietitians' content samples, LLM requests, responses data, dietitian-generated content.
4. Web Control Plane - Administrator privileges, client onboarding functionalities, application configuration, and billing management.
5. API Gateway Configuration - ACL rules, rate-limiting configuration and authentication configuration.
6. Generated Content (AI responses) - AI-generated dietary advice, recommendations, etc.

## TRUST BOUNDARIES

1. Boundary between external Meal Planner applications and internal API Gateway.
2. Boundary between internal API Application and external ChatGPT service.
3. Boundary between administrator and internal Web Control Plane.
4. Boundary between internal systems (API Gateway, API Application, Web Control Plane) and internal databases (Control Plane Database, API Database).

## DATA FLOWS

1. Meal Planner —> API Gateway (crosses boundary)
2. API Gateway —> API Application (internal trusted flow)
3. API Application —> ChatGPT API (crosses boundary)
4. API Application —> API Database (internal trusted)
5. Web Control Plane —> Control Plane Database (internal trusted)
6. Administrator —> Web Control Plane (crosses boundary)

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|-----------------|----------------|---------------|------------|-----------------------|--------------------|---------------|
| 0001 | API Gateway | Attacker attempts to use stolen API keys to spoof legitimate Meal Planner application | Spoofing | API keys authenticate Meal Planner apps | Mitigated partially by existing individual API keys and TLS (FILE: Security section 1, 3) | Regular API keys rotation, monitor unusual activities suggesting compromise, short-lived and revocable API keys | Medium, API keys may leak due to human factor or insecure key management | High, Unauthorized access could lead to significant data leakage or abuse of services | High |
| 0002 | Web Control Plane | Attacker attempts unauthorized admin access via improper authentication | Spoofing | Manages sensitive functionalities including onboarding, billing | Architecture documentation does not specify controls for admin authentication explicitly | Employ multi-factor authentication, strong authentication mechanisms (OIDC, password-less authentication) | Medium, Admin interfaces are often targeted | Critical, full compromise could expose sensitive data and allow attacker to reconfigure entire application | Critical |
| 0003 | API Database | Attacker modifies stored dietary recommendation samples or LLM responses to provide inappropriate dietary advice | Tampering | Database stores valuable input/output for dietary recommendations | Not explicitly mitigated in current architecture description | Enforce database access permissions, principle of least privilege, validate and audit data regularly for integrity | Low, database secured internally | High, altered content could have severe reputation and legal implications | Medium |
| 0004 | API Gateway | Attacker bypasses or alters ACL rules to access unauthorized API endpoints or functionality | Elevation of Privilege | ACLs intended as security guard rails | Not explicitly mitigated in current architecture description | Frequent ACL audits, RBAC, secure configuration and validation | Medium, dependent on ACL management practices | High, could lead to unauthorized sensitive data and feature access | High |
| 0005 | API Application | Attacker injects malicious input to manipulate LLM integration, causing harmful output | Tampering | API Application directly interfaces with external LLM API | Partially mitigated by input filtering in API Gateway ongoing (FILE - API Gateway "filtering input") | Strong server-side input validation at API application level, sanitize and validate all input thoroughly | Medium, attackers commonly target LLM integration points with injection attacks | High, application may distribute harmful dietary recommendations, resulting in liability and loss of reputation | High |
| 0006 | API Application | Attacker intercepts or monitors sensitive AI-generated dietary advice between the API application and external ChatGPT API | Information Disclosure | Integration transmits potentially sensitive data externally (dietary advice and information) | Mitigated partially by existing HTTPS/TLS encrypted traffic (FILE: Container diagram states HTTPS explicitly) | Additional data encryption, minimize amount of personal or sensitive data transfer externally, encrypt sensitive portions of requests/responses | Low, HTTPS significantly reduces interception risk in transit | Medium, Diet information is moderately sensitive user data | Medium |

# DEPLOYMENT THREAT MODEL

AI Nutrition-Pro application deployment can possibly occur in:

- AWS Elastic Container Service (ECS), RDS for databases, and Kong API Gateway deployment (Single deployment provided)

Selecting AWS ECS and RDS as explicitly mentioned deployment architecture from provided input.

## ASSETS

1. AWS ECS containers (API Application, Web Control Plane)
2. RDS instances (Control Plane Database, API Database)
3. Kong API Gateway deployment and configuration
4. API keys, credentials, IAM roles and permissions used in and for deployment

## TRUST BOUNDARIES

1. Boundary between AWS infrastructure and external administrators accessing deployment accounts (AWS Console, CLI)
2. Boundary between the Kong API Gateway service and external network (internet)
3. Boundary separating individual AWS resources (ECS Instances, RDS) based on AWS IAM permissions

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|-----------------------|--------------------|---------------|
| 0001 | ECS Containers | Unauthorized container access or privilege escalation due to misconfigured IAM roles/policies | Overly permissive IAM roles give attackers elevated privileges | Not explicitly mitigated in current architecture description | Use least-privilege IAM permissions, audit roles frequently | Medium; misconfigurations common | High; attacker gains elevated access or data | High |
| 0002 | RDS Databases | Attacker gains database access due to insecure configuration or overly exposed network security groups | Sensitive data stored in RDS databases | Not explicitly mitigated or detailed in provided info | Secure database configurations with restricted security groups, limit access via IAM DB Authentication | Medium; dependent on AWS configurations | Critical; attacker can exfiltrate or manipulate sensitive data | Critical |
| 0003 | Kong API Gateway Instance | Compromised API Gateway deployment due to insecure configurations and vulnerabilities | Public-facing API gateway exposed to the Internet | Filtering and authentication functions already identified (FILE: API Gateway container definition) | Regular vulnerability scanning of gateway, rapid patch updates and strong endpoint security rules | Medium; likely due to exposure to internet | High; key gateway compromise affects application functioning and security | High |

# BUILD THREAT MODEL

## ASSETS

1. Source code of API Application and Web Control Plane.
2. Docker containers and images.
3. Build pipeline infrastructure (build runners, repositories, and CI/CD)

## TRUST BOUNDARIES

1. Boundaries between developers and repositories / CI environments.
2. Boundaries between CI/CD pipeline infrastructure and deployment targets.

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|-----------------------|--------------------|---------------|
| 0001 | CI/CD Pipeline | Malicious code injection via compromised dependencies from third-party libraries | Application depends on third-party libraries and dependencies | No explicit control stated in input | Dependency scanning, application source code reviews, securing dependency management systems | Medium, increasingly common supply chain issue | High, could significantly compromise system functioning, confidentiality | High |
| 0002 | Docker Container Images | Attacker modifies Docker images or injects malicious content unauthorizedly | Docker container images directly deployed | Not explicitly mitigated in documentation | Protect Container registry access, sign container images, verify signatures before deployment | Medium, attacking container registries occurs frequently | High, attacker can install persistent malicious components | High |

# QUESTIONS & ASSUMPTIONS

- Question: How are admin accounts currently protected in Web Control Plane?
- Question: Are IAM roles/policies reviewed regularly?
- Assumption: No explicit CI/CD pipeline security controls identified, assumed insufficiently protected until provided otherwise.
