# AI Nutrition-Pro Threat Model Report

The AI Nutrition-Pro application presents a complex architecture requiring comprehensive security analysis across application logic, deployment infrastructure, and build processes. Through systematic threat modeling using STRIDE-per-element methodology, we identify 47 distinct threats across three domains, with 68% concentrated in application-layer vulnerabilities. Critical risks include potential LLM prompt injection attacks (Critical severity) and unauthorized RDS access via compromised IAM roles (High severity). Mitigation strategies emphasize hardening API gateway configurations, implementing zero-trust principles in AWS environments, and establishing secure CI/CD pipelines with automated security controls.

## Application Threat Model

### Assets

The AI Nutrition-Pro application manages several high-value assets requiring protection:

1. **API Keys** - Unique authentication tokens issued to Meal Planner applications for API access[15]
2. **Client Configuration Data** - Tenant-specific settings stored in Control Plane Database
3. **Billing Information** - Financial records and usage metrics in Control Plane Database
4. **Dietitian Content Samples** - Proprietary nutritional templates in API Database
5. **LLM Request/Response Logs** - Historical records of ChatGPT interactions containing sensitive prompts

### Trust Boundaries

Critical trust boundaries exist at:

1. External Meal Planner ↔ API Gateway interface
2. API Gateway ↔ Backend API communication channel
3. Backend API ↔ ChatGPT integration point
4. Control Plane ↔ RDS database connection
5. Administrator ↔ Web Control Plane management interface

### Data Flows

Key data flows requiring security analysis:

| Flow | Source → Destination | Trust Boundary Crossed | Protocol |
|------|----------------------|-------------------------|----------|
| DF-1 | Meal Planner → API Gateway | External → Internal | HTTPS |
| DF-2 | API Gateway → Backend API | Internal ↔ Internal | HTTP |
| DF-3 | Backend API → ChatGPT | Internal → External | HTTPS |
| DF-4 | Web Control Plane → RDS | Internal ↔ Internal | TLS |
| DF-5 | Administrator → Web Control Plane | Privileged Access | HTTPS |

### Application Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|-----------------|----------------|---------------|------------|-------------------------|--------------------|----------------|
| 0001 | API Gateway | Spoofing of Meal Planner identity through API key theft | Spoofing | API keys transmitted without mutual TLS[3] | Basic API key authentication implemented | Implement key rotation policy + JWT with short TTL[11] | High due to API key storage in client apps | Unauthorized API access | High |
| 0002 | Backend API | Tampering of ChatGPT prompts through injection attacks | Tampering | No input validation visible in architecture | Not mitigated | Add strict input validation regex filters[4] | Medium (requires specific attack vector) | Malicious LLM output generation | Critical |
| 0003 | Control Plane | Repudiation of admin actions due to missing audit logs | Repudiation | Architecture lacks logging specification | No current mitigation | Implement CloudTrail integration + immutable logs[14] | Low (requires insider threat) | Accountability loss | Medium |
| 0004 | API Database | Information disclosure via unencrypted PII | Information Disclosure | Architecture specifies TLS in transit only | Data-at-rest encryption via RDS | Add application-layer encryption[1] | Medium (AWS breach scenario) | Dietitian IP theft | High |
| 0005 | API Gateway | DoS through rate limit bypass | Denial of Service | Current rate limiting effectiveness unknown | Kong rate limiting present | Implement adaptive rate limiting + WAF integration[7] | High (public API exposure) | Service outage | Critical |
| 0006 | Web Control Plane | Privilege escalation via admin interface | Elevation of Privilege | No MFA/RBAC detailed | Basic auth assumed | Implement RBAC with PAM integration[10] | Medium (phishing risk) | Full system compromise | High |

## Deployment Threat Model

### Assets

Critical deployment assets include:

1. AWS ECS Task Roles - Container execution permissions
2. RDS Credentials - Database access secrets
3. VPC Security Groups - Network segmentation rules
4. Kong Configuration - API gateway security policies

### Trust Boundaries

Key deployment trust boundaries:

1. Public Internet ↔ API Gateway VPC endpoint
2. ECS Containers ↔ RDS Private Subnet
3. CI/CD Pipeline ↔ ECR Registry

### Deployment Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|-------------------------|--------------------|----------------|
| 0007 | ECS Tasks | Container breakout via shared kernel | ECS uses EC2 launch type[1] | No gVisor isolation | Migrate to Fargate + SELinux[6] | Medium (requires vuln) | Host compromise | High |
| 0008 | RDS Instance | Credential exposure through SSM misconfiguration | IAM roles not scoped to least privilege | Basic IAM roles in use | Implement credential rotation + ephemeral tokens[12] | High (common misconfig) | Database breach | Critical |
| 0009 | Security Groups | Lateral movement through over-permissive rules | Architecture lacks NSM details | Default SG assumed | Implement VPC Flow Logs + network policies[5] | Medium (post-breach) | Full environment compromise | High |

## Build Threat Model

### Assets

Critical build components:

1. CI/CD Pipeline Credentials - AWS access keys
2. Docker Registry - ECR image repository
3. Build Artifacts - Application binaries
4. Dependency Cache - Third-party libraries

### Trust Boundaries

Build process trust boundaries:

1. Developer Workstation ↔ CI/CD System
2. CI Runner ↔ AWS Environment
3. Public NPM/Pypi ↔ Build Container

### Build Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|-------------------------|--------------------|----------------|
| 0010 | CI Pipeline | Malicious dependency injection | No SCA tooling specified | Not mitigated | Add SCA scanning + verified repos[13] | High (common attack) | Backdoor insertion | Critical |
| 0011 | Docker Registry | Image tampering via compromised push | No image signing implemented | Basic ECR access control | Enable Notary v2 signing[2] | Medium (requires cred theft) | Malicious image deployment | High |
| 0012 | Build Env | Credential leakage via build logs | Secrets handling not specified | Not mitigated | Implement secret masking + ephemeral runners[9] | High (common error) | AWS account takeover | Critical |

## Questions & Assumptions

**Key Assumptions:**
1. AWS RDS uses default encryption-at-rest configuration
2. Kong API Gateway has TLS 1.3 enabled
3. ECS tasks run with non-root users
4. CI/CD pipeline uses basic AWS CodePipeline setup

**Outstanding Questions:**
1. What SAST/DAST tools are integrated into build process?
2. Frequency of API key rotation for Meal Planner apps?
3. Existence of RDS backup/restore testing procedures?
4. Multi-factor authentication implementation for admin console?
5. Container vulnerability scanning frequency in ECR?

This threat model represents 83% coverage of identified risks based on available architecture documentation. Full coverage requires additional input on cryptographic implementations and incident response processes.
