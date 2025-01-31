# APPLICATION THREAT MODEL

## ASSETS
1. API Keys - Used for authentication with Meal Planner applications
2. Control Plane Data - Tenant configurations, billing information, system settings
3. Dietitian Content Samples - Proprietary nutrition/diet templates
4. LLM Interactions - Inputs sent to ChatGPT and generated responses
5. Administrator Credentials - Access to control plane configuration

## TRUST BOUNDARIES
1. Between Meal Planner applications and API Gateway (external<->internal)
2. Between API Gateway and Backend API (internal boundary)
3. Between Backend API and ChatGPT (internal<->external)
4. Between Administrator and Web Control Plane (human<->system)

## DATA FLOWS
1. Meal Planner -> API Gateway (HTTPS) - Crosses trust boundary
2. API Gateway -> Backend API (HTTPS) - Internal
3. Backend API -> ChatGPT (HTTPS) - Crosses trust boundary
4. Administrator -> Web Control Plane - Crosses trust boundary

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME    | THREAT NAME                                                                 | STRIDE CATEGORY | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|-------------------|-----------------------------------------------------------------------------|-----------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | API Gateway       | Attacker spoofs Meal Planner identity using stolen API keys                 | Spoofing        | API keys are primary authentication mechanism                                  | TLS encryption in transit              | Implement key rotation + HMAC validation                                   | Medium - API keys could be leaked          | Unauthorized access to API resources        | High          |
| 0002      | Backend API       | Tampering with LLM input parameters to generate harmful content             | Tampering       | Direct control over ChatGPT inputs                                            | Input validation filters               | Add content moderation layer pre-ChatGPT submission                        | Low-Medium                                 | Reputation damage from bad outputs          | Medium        |
| 0003      | API Database      | Disclosure of dietitian content samples through SQL injection               | Information Disclosure | Stores sensitive nutrition templates                                         | Not mentioned in security controls     | Implement parameterized queries + database encryption                      | Medium                                     | Loss of intellectual property               | High          |
| 0004      | Control Plane DB  | Elevation of privilege via admin credential leakage                         | Elevation of Privilege | Contains system configuration and billing data                               | TLS for data in transit                | Add MFA for admin access + credential vaulting                             | Low                                        | Full system compromise                      | Critical      |
| 0005      | API Gateway       | Denial of Service through excessive rate-limited requests                   | Denial of Service | External-facing entry point                                                  | Basic rate limiting                    | Implement adaptive rate limiting + AWS Shield                              | High                                       | Service unavailability                      | High          |

# DEPLOYMENT THREAT MODEL

## ASSETS
1. AWS ECS Task Definitions
2. RDS Database Credentials
3. Container Images
4. AWS IAM Roles

## TRUST BOUNDARIES
1. Internet <-> API Gateway (public ECS service)
2. ECS Cluster <-> RDS Instances (private VPC)
3. Control Plane <-> AWS Management APIs

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME    | THREAT NAME                                                                 | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|-------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | ECS Tasks         | Unauthorized access to container runtime through exposed management ports   | Containers may have vulnerable services                                       | Not specified                          | Implement security groups restricting access + runtime protection tools    | Medium                                     | Container compromise                        | High          |
| 0002      | RDS Instances     | Data exfiltration through public network exposure                           | Misconfigured RDS security groups                                             | TLS encryption                         | Enable RDS encryption-at-rest + strict network policies                    | Low                                        | Mass data theft                             | Critical      |
| 0003      | IAM Roles         | Privilege escalation through over-permissive task roles                     | Common AWS configuration error                                                | Not addressed                          | Implement least-privilege roles + regular permission audits                | High                                       | AWS account compromise                      | Critical      |

# BUILD THREAT MODEL

## ASSETS
1. Source Code Repository
2. CI/CD Pipeline Secrets
3. Docker Registry Credentials
4. Build Artifacts

## TRUST BOUNDARIES
1. Developer Workstations <-> CI/CD System
2. CI/CD System <-> AWS Deployment Targets

## BUILD THREATS

| THREAT ID | COMPONENT NAME    | THREAT NAME                                                                 | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|-------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | CI Pipeline       | Injection of malicious code through compromised dependencies               | Reliance on third-party packages                                              | Not specified                          | Implement software bill of materials + dependency scanning                 | Medium                                     | Backdoor in production                      | High          |
| 0002      | Docker Images     | Distribution of vulnerable base images with known CVEs                     | Common container security issue                                               | Not addressed                          | Use distroless images + regular vulnerability scanning                     | High                                       | Exploitable runtime vulnerabilities         | High          |

# QUESTIONS & ASSUMPTIONS

1. Assumption: TLS 1.2+ is properly configured on all HTTPS connections
2. Question: Are API keys stored hashed or encrypted in the control plane database?
3. Assumption: AWS security best practices are followed for ECS/RDS
4. Question: Is there monitoring for abnormal ChatGPT response patterns?
5. Assumption: Administrator access requires VPN/private network
6. Question: Are database backups encrypted and access-controlled?
