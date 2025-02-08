# APPLICATION THREAT MODEL

## ASSETS
1. API Keys - Used for authentication with Meal Planner applications
2. Dietitians' Content Samples - Proprietary nutrition/diet content used for LLM training
3. LLM Requests/Responses - Inputs sent to ChatGPT and generated outputs
4. Billing Data - Client payment and usage information
5. Admin Credentials - Access to control plane configuration

## TRUST BOUNDARIES
1. Between Meal Planner applications and API Gateway (external<->internal)
2. Between API Gateway and backend services (edge<->core)
3. Between Control Plane and its database (application<->data store)
4. Between Backend API and ChatGPT (internal<->external API)

## DATA FLOWS
1. Meal Planner -> API Gateway (HTTPS) - Crosses trust boundary
2. API Gateway -> Backend API (HTTPS)
3. Backend API -> ChatGPT (HTTPS) - Crosses trust boundary
4. Web Control Plane <-> Control Plane DB (TLS)
5. Backend API <-> API Database (TLS)

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|------------------|----------------|---------------|------------|------------------------|--------------------|---------------|
| 0001 | API Gateway | Unauthorized access using stolen API keys | Spoofing | API keys are primary authentication mechanism | Rate limiting configured | Implement key rotation + anomaly detection | Medium - API keys could be leaked through client systems | High - Full access to API functionality | High |
| 0002 | Web Control Plane | Admin session hijacking | Spoofing | Web interface handles sensitive configurations | No mention of MFA | Implement session timeout + MFA | Medium - Web interfaces common attack surface | Critical - Full system compromise | High |
| 0003 | API Database | Tampering of training data samples | Tampering | Stores original dietitian content samples | TLS in transit mentioned | Implement integrity checks + WORM storage | Low-Medium | High - Could poison LLM outputs | Medium |
| 0004 | Backend API | LLM prompt injection attacks | Tampering | Directly interacts with ChatGPT | No mitigation mentioned | Implement input sanitization + output validation | High - Common LLM attack vector | Medium - Could generate incorrect content | High |
| 0005 | Control Plane DB | Billing data exfiltration | Information Disclosure | Contains payment information | TLS in transit | Encrypt sensitive fields at rest | Medium - Prime target for attackers | High - Financial/reputation damage | High |

# DEPLOYMENT THREAT MODEL

## ASSETS
1. AWS ECS Task Roles
2. RDS Database Credentials
3. Container Images
4. Cloud Infrastructure Configs

## TRUST BOUNDARIES
1. Between AWS environment and external internet
2. Between ECS tasks and RDS instances
3. Between CI/CD pipeline and production environment

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------------------|--------------------|---------------|
| 1001 | ECS Containers | Compromised container images | Using public base images | No mention of image scanning | Implement signed images + vulnerability scanning | Medium - Common supply chain attack | High - Backdoor access | High |
| 1002 | RDS Instances | Unauthorized cloud access | Sensitive data storage | TLS mentioned | Enable encryption at rest + IAM role protection | Medium - Cloud misconfigurations common | Critical - Data breach | High |
| 1003 | API Gateway | DDoS attacks | Edge-facing component | Rate limiting configured | Enable AWS Shield protection | High - Public endpoint | High - Service disruption | Medium |

# BUILD THREAT MODEL

## ASSETS
1. Source Code
2. CI/CD Secrets
3. Build Artifacts
4. Dependency Packages

## TRUST BOUNDARIES
1. Between developer workstations and CI environment
2. Between internal repos and public package registries

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------------------|--------------------|---------------|
| 2001 | CI Pipeline | Malicious dependency inclusion | Using Golang modules | No mention of checks | Implement dependency scanning | Medium - Common supply chain risk | High - Backdoor introduction | High |
| 2002 | Build Secrets | Exposure of AWS credentials | Needed for ECS deployment | No mitigation mentioned | Use temporary cloud credentials | Medium - Common misconfiguration | High - Cloud account takeover | High |

# QUESTIONS & ASSUMPTIONS

1. Q: Are API keys regularly rotated?
   A: Assuming quarterly rotation but needs verification

2. Q: Is there monitoring for anomalous LLM requests?
   A: Assumed not implemented - needs addition

3. Q: Are ECS tasks using minimal IAM privileges?
   A: Assumed following AWS best practices

4. Q: Is there CI/CD environment isolation?
   A: Assumed production/build environments are separate

Note: Focused on application-specific threats rather than general cloud security practices. High-risk items prioritized based on likelihood of exploitation and business impact.
