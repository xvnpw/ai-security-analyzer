# APPLICATION THREAT MODEL

## ASSETS
1. API Keys - Used for authentication with Meal Planner applications
2. Control Plane Data - Tenant configurations, billing information, and system settings
3. Dietitians' Content Samples - Proprietary nutrition/diet content used for LLM training
4. LLM Requests/Responses - Input data and AI-generated output containing sensitive health information
5. Administrator Credentials - Access to system configuration and management functions

## TRUST BOUNDARIES
1. Between Meal Planner applications and API Gateway (external<->internal)
2. Between ChatGPT and Backend API (external LLM provider<->internal system)
3. Between Administrator and Web Control Plane (human<->system boundary)
4. Between API Gateway and internal services (edge<->core services)

## DATA FLOWS
1. Meal Planner -> API Gateway (HTTPS) - Crosses trust boundary
2. API Gateway -> Backend API (HTTPS)
3. Backend API -> ChatGPT (HTTPS) - Crosses trust boundary
4. Web Control Plane -> Control Plane DB (TLS)
5. Backend API -> API Database (TLS)

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                                 | STRIDE CATEGORY | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|----------------------|-----------------------------------------------------------------------------|-----------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | API Gateway          | Attacker spoofs Meal Planner application using stolen API keys              | Spoofing        | API keys are primary authentication mechanism                                  | TLS encryption in transit              | Implement key rotation and monitoring for abnormal usage patterns          | Medium - API keys could be leaked/stolen   | Unauthorized access to AI capabilities      | High          |
| 0002      | Backend API          | Tampering with LLM requests to inject malicious prompts                     | Tampering       | Direct interaction with external LLM service                                   | Input validation at API Gateway        | Implement content signing and request validation at multiple layers        | Low-Medium                                 | Generation of inappropriate/dangerous content | Critical      |
| 0003      | Control Plane DB     | Disclosure of tenant billing information through SQL injection              | Information Disclosure | Web Control Plane interacts with relational database                         | TLS encryption in transit              | Implement prepared statements and role-based access control                | Medium                                     | Financial data exposure                     | High          |
| 0004      | API Database         | Repudiation of LLM training data modifications                              | Repudiation     | Stores critical training data and model outputs                                | Database transaction logs              | Implement immutable audit trails with user context                         | Low                                        | Loss of data integrity audit capability     | Medium        |
| 0005      | API Gateway          | Denial of Service through excessive rate-limited requests                   | Denial of Service | External-facing entry point                                                  | Basic rate limiting                    | Implement adaptive rate limiting based on client behavior patterns         | High                                       | Service unavailability                      | High          |

# DEPLOYMENT THREAT MODEL

## ASSETS
1. AWS ECS Task Roles - IAM credentials for container permissions
2. RDS Database Credentials - Access to sensitive databases
3. Container Images - Deployment artifacts containing application code
4. TLS Certificates - Encryption credentials for secure communications

## TRUST BOUNDARIES
1. Between AWS public network and ECS containers
2. Between container orchestration layer and application containers
3. Between CI/CD pipeline and production environment

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                                 | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|----------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | AWS ECS              | Unauthorized access to container tasks through compromised IAM roles        | ECS tasks require AWS permissions                                             | IAM role best practices                | Implement least-privilege roles and regular credential rotation            | Medium                                     | Full system compromise                      | Critical      |
| 0002      | RDS Instances        | Exposure of database credentials in environment variables                   | Containers require DB access credentials                                      | TLS encrypted connections              | Use AWS Secrets Manager with automatic credential rotation                 | High                                       | Database takeover                           | High          |
| 0003      | Container Registry   | Deployment of tampered container images                                     | Images are built externally and pushed to registry                            | Basic access controls                  | Implement image signing and vulnerability scanning                         | Medium                                     | Malware injection                           | High          |

# BUILD THREAT MODEL

## ASSETS
1. Source Code Repository - Contains application logic and configurations
2. CI/CD Pipeline - Deployment automation credentials
3. Dependency Packages - Third-party libraries and modules

## TRUST BOUNDARIES
1. Between developer workstations and CI/CD system
2. Between public package repositories and build process
3. Between build artifacts and deployment targets

## BUILD THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                                 | WHY APPLICABLE                                                                 | HOW MITIGATED                          | MITIGATION                                                                 | LIKELIHOOD EXPLANATION                     | IMPACT EXPLANATION                          | RISK SEVERITY |
|-----------|----------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|----------------------------------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------|---------------|
| 0001      | CI/CD Pipeline       | Injection of malicious code through compromised dependencies               | Reliance on third-party packages                                              | Basic vulnerability scanning           | Implement software bill of materials (SBOM) and artifact signing           | Medium                                     | Supply chain compromise                     | High          |
| 0002      | Build Environment    | Exposure of AWS credentials in build scripts                                | Deployment requires cloud access                                              | Environment segregation                | Use OIDC-based temporary credentials for cloud deployments                 | High                                       | Unauthorized cloud resource access          | Critical      |
| 0003      | Source Repository    | Unauthorized code modifications through compromised developer accounts      | Multiple contributors with push access                                        | Basic access controls                  | Implement mandatory code reviews and signed commits                        | Low-Medium                                 | Backdoor insertion                          | High          |

# QUESTIONS & ASSUMPTIONS

## Assumptions
1. TLS 1.2+ is properly configured on all external-facing endpoints
2. AWS security best practices are followed for IAM and network security
3. Database encryption at rest is enabled for RDS instances
4. Regular vulnerability scanning is performed on container images

## Questions
1. Are API keys stored using AWS Secrets Manager or similar secure storage?
2. What monitoring exists for detecting anomalous LLM request patterns?
3. How often are database credentials rotated for RDS access?
4. Is MFA enforced for administrator access to Web Control Plane?
5. What process exists for validating third-party dependencies in builds?
