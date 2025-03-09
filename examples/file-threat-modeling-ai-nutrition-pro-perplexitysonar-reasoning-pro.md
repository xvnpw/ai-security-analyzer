## Application Threat Model

### Assets
- **API Keys**: Unique identifiers for Meal Planner applications to authenticate with API Gateway
- **Dietitians' Content Samples**: Proprietary examples stored in API database used for LLM training
- **Billing Data**: Financial records in Control Plane Database tracking client usage
- **LLM Generated Content**: AI-produced dietary recommendations sent to Meal Planner apps

### Trust Boundaries
1. External Meal Planner applications ↔ API Gateway
2. ChatGPT-3.5 API ↔ Backend API
3. Internet-facing API Gateway ↔ Internal services
4. Administrator access plane ↔ Management interfaces

### Data Flows
| Source | Destination | Data Type | Trust Boundary Crossed |
|--------|-------------|-----------|-------------------------|
| Meal Planner | API Gateway | Auth requests | External ↔ Internal |
| API Gateway | Backend API | Processed requests | Perimeter ↔ Core |
| Backend API | ChatGPT-3.5 | LLM prompts | Internal ↔ External |
| Web Control Plane | RDS | Configuration data | Management ↔ Storage |

### Application Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD | IMPACT | RISK SEVERITY |
|-----------|----------------|-------------|-----------------|----------------|---------------|------------|------------|--------|---------------|
| 0001 | API Gateway | Attacker bypasses API key authentication through key leakage | Spoofing | API keys transmitted in headers could be intercepted | Partial TLS encryption | Implement key rotation + HMAC signature validation | Medium | High | High |
| 0002 | Backend API | Malicious LLM prompt injection altering output | Tampering | Direct ChatGPT integration without input validation | None in current design | Add input sanitization + output verification layer | High | Medium | High |
| 0003 | API Database | Exfiltration of dietitian samples via SQLi | Information Disclosure | Raw SQL queries from Golang backend | No ORM/WAF mentioned | Implement prepared statements + query logging | Medium | Critical | High |

## Deployment Threat Model

### Assets
- AWS ECS Cluster Configurations
- RDS Database Credentials
- Kong API Gateway Policies
- Container Images

### Trust Boundaries
1. Public Internet ↔ AWS VPC
2. CI/CD Pipeline ↔ Production Environment
3. Developer Workstations ↔ Cloud Resources

### Deployment Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD | IMPACT | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------|--------|---------------|
| 0004 | ECS Containers | Privilege escalation via misconfigured task roles | Default AWS permissions often over-permissive | No role hardening described | Implement least-privilege IAM roles | Medium | High | High |
| 0005 | RDS Instances | Unencrypted PII at rest | GDPR/HIPAA compliance requirements | Encryption not specified | Enable AES-256 encryption + KMS | Low | Critical | Medium |

## Build Threat Model

### Assets
- Golang Source Code
- CI/CD Pipeline Secrets
- Docker Registry Credentials

### Trust Boundaries
1. Version Control ↔ Build Servers
2. Third-Party Dependencies ↔ Application Code
3. Artifact Storage ↔ Deployment Targets

### Build Threats

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD | IMPACT | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------|--------|---------------|
| 0006 | CI Pipeline | Compromised dependency in Golang modules | High risk of supply chain attacks | No SBOM verification | Implement Sigstore cosign validation | High | High | Critical |
| 0007 | Docker Images | Vulnerable base images in ECS deployment | Common attack vector for containers | No image scanning described | Add Trivy scan to pipeline | Medium | Medium | Medium |

## Questions & Assumptions
1. Assumed GPT-3.5 API has enterprise-grade security
2. Presumed AWS VPC configuration follows best practices
3. No logging/monitoring solution specified
4. Disaster recovery plan not documented
5. GDPR compliance requirements unverified

This model prioritates threats using NIST SP 800-30 guidelines, focusing on risks introduced by architectural decisions rather than generic cloud security concerns. High severity items require immediate attention due to potential business impact from compromised AI outputs or data leakage.
