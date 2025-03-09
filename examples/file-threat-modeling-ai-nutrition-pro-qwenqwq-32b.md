# APPLICATION THREAT MODEL

## ASSETS
- **API Keys**: Used by Meal Planner applications for authentication.
- **Control Plane Data**: Tenant configurations, billing info in `control_plan_db`.
- **API Application Data**: Dietitian content samples and LLM interactions stored in `api_db`.
- **Admin Credentials**: Used by the Administrator to manage system configuration.
- **Network Traffic**: Data in transit between Meal Planner apps and API Gateway.

---

## TRUST BOUNDARIES
1. External users (Meal Planner apps) to API Gateway.
2. API Gateway to internal API Application.
3. External Admin to Web Control Plane.
4. Internal components to their respective databases (Control Plane DB and API DB).

---

## DATA FLOWS
| Flow | From → To | Crosses Trust Boundary? |
|---|---|---|
| Meal Planner → API Gateway | ✔️ Yes (External → Internal) |
| API Gateway → API Application | ✔️ Yes (Gateway to backend) |
| API Application → ChatGPT API | ❌ No (External system, but via HTTPS) |
| Admin → Web Control Plane | ✔️ Yes (External → Internal) |

---

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|---|
| 0001 | API Gateway | Unauthorized access via stolen API key | **Spoofing** | Meal Planner apps rely on API keys for authentication. | Keys are used but no mention of key rotation or IP restrictions. | Enforce API key rotation policies and restrict API key usage to specific IP ranges. | Medium (API keys can be intercepted or exposed in logs.) | High (Bypass authentication, allowing unauthorized API access.) | High |
| 0002 | Control Plane Database | Tampered tenant configurations via SQL injection | **Tampering** | Web Control Plane writes tenant data to `control_plan_db` without explicit mention of input validation. | No mention of parameterized queries or WAF protections. | Implement input validation, parameterized queries, and a WAF for the Control Plane API. | Low (Requires injection vector in Web Control Plane code.) | High (Tampered tenant data could disrupt billing or access control.) | Medium |
| 0003 | API Application | Exfiltration of dietitian content samples | **Information Disclosure** | API Application stores dietitian samples in `api_db`. | Data is encrypted "at rest" (if implied by RDS defaults) but not explicitly stated. | Enforce explicit encryption at rest (e.g., AWS KMS) and audit RDS security settings. | Low (Requires access to `api_db` or API Application compromise.) | Medium (Exposure of dietitian content could harm competitive advantage.) | Medium |
| 0004 | Web Control Plane | Privilege escalation via misconfigured ACLs | **Elevation of Privilege** | ACL rules in API Gateway are mentioned but not their enforcement granularity. | No details on how ACL rules are audited or applied per role (e.g., Admin vs. app manager). | Define role-based ACL rules and implement regular RBAC audits via IaC policies. | Medium (ACL misconfig could allow excessive permissions.) | High (Unauthorized configuration changes could break billing or access controls.) | High |
| 0005 | ChatGPT API Integration | Manipulation of AI-generated content | **Tampering** | API Application sends unvalidated inputs to ChatGPT, which could return malicious content. | No validation of ChatGPT responses or rate limits for API usage. | Sanitize ChatGPT outputs, enforce rate limits on API calls, and monitor for anomalous API usage patterns. | Low (Requires OpenAI API abuse or response poisoning.) | Medium (Malicious content could mislead users or damage brand.) | Medium |

---

# DEPLOYMENT THREAT MODEL

## ASSETS
- **AWS ECS Instances**: Host API Gateway, Web Control Plane, and API Application.
- **AWS RDS Instances**: Store sensitive tenant and API data.
- **AWS IAM Credentials**: Used for AWS service access.

---

## TRUST BOUNDARIES
1. Public Internet → API Gateway (AWS ALB/ELB).
2. ECS task containers → RDS databases (private network traffic).
3. AWS Management Console → EC2 instances (admin access).

---

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|---|
| 001 | AWS ECS Containers | Unauthorized access to container logs exposing API keys | **Spoofing** | ECS task logs may contain API keys or credentials. | No mention of log encryption or access controls. | Restrict log access to IAM roles, encrypt sensitive logs, and remove credentials from log outputs. | Medium (Exposed logs may leak keys via misconfiguration.) | High (Exfiltrated keys enable API abuse or data theft.) | High |
| 002 | AWS RDS Instances | Data theft via exposed database endpoints | **Information Disclosure** | RDS instances may have public endpoints or weak security groups. | Input does not mention network ACLs or VPC isolation. | Deploy RDS instances in private subnets with EC2-Classic disabled, restrict access via security groups. | Medium (Default AWS configurations often have open ports.) | High (Exfiltration of tenant data or billing info.) | High |
| 003 | AWS IAM Credentials | Compromise via exposedd credentials in ECS task definitions | **Repudiation** | ECS tasks may hardcode IAM credentials in config files. | No mention of IAM credential management (e.g., AWS Secrets Manager). | Use IAM roles for tasks instead of long-lived keys, rotate credentials regularly. | Medium (Common misconfiguration in ECS setups.) | High (Unrestricted AWS API access could lead to full system takeover.) | High |
| 004 | API Gateway | DDoS attack overwhelming Kong instance | **Repudiation** | No mention of DDoS protection (e.g., AWS Shield). | Kong’s built-in rate limits described but no mention of cloud DDoS mitigation. | Enable AWS Shield Advanced and auto-scaling for Kong instances. | High (API gateways are common DDoS targets.) | Critical (Service outage for all users.) | Critical |

---

# BUILD THREAT MODEL

## ASSETS
- **Source Code Repository**: Contains application logic (Golang code).
- **Build Artifacts: Docker images for ECS deployment.
- **CI/CD Secrets**: AWS credentials for deploying to ECS and RDS.

---

## TRUST BOUNDARIES
1. External repo contributors → CI/CD pipeline.
2. CI/CD system → AWS account (deploy permissions.

---

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|---|---|---|---|---|---|---|---|---|---|
| 001 | CI/CD Pipeline | Compromise of build artifacts via supply chain attack | **Tampering** | Build process not described, so no assurance on dependency checks. | No mention of artifact signing or dependency scanning. | Enforce SBoM (Software Bill of Materials) and SCA (Software Composition Analysis) in builds. | Medium (If build uses third-party Go modules with vulnerabilities.) | High (Malicious code deployed to production.) | High |
| 002 | AWS Credentials in Build Pipeline | Leaked AWS credentials via CI logs | **Spoofing** | Build pipelines often store AWS credentials in CI tools (e.g., GitHub Secrets. | No details on credential rotation or IAM permissions scope. | Use IAM roles with least-privilege permissions and rotate credentials monthly. | Medium (CI logs or repo leaks can expose keys.) | High (Full AWS account access permits data exfiltration.) | High |

---

# QUESTIONS & ASSUMPTIONS
1. **Question**: Is AWS Secrets Manager or similar used to store API keys and database credentials? Default assumption: Assume credentials are stored in plaintext unless stated otherwise.
2. **Question**: Are AWS RDS instances encrypted at rest and in transit? Default assumption: AWS defaults apply (encryption at rest enabled by default in RDS.)
3. **Assumption**: ChatGPT API responses are validated for structure and content by the API Application.
4. **Assumption**: ECS task definitions do not hardcode IAM credentials; assume IAM roles are used instead.

---

## Notes:
- Threats related to lack of input validation (e.g., 0002) are medium risk as SQLi requires code-level vulnerability.
- Build process threats (e.g., supply chain) are critical if third-party modules are unvalidated.
- DDoS on API Gateway (004) is critical due to business-critical availability impact.
