# AI Nutrition-Pro System Design Document

## BUSINESS POSTURE
The AI Nutrition-Pro system aims to provide dietitians with AI-generated content creation capabilities through secure API integrations with existing meal planning applications. Key business priorities include enabling seamless integration for third-party meal planning tools, maintaining high availability for API consumers, and ensuring compliance with data privacy regulations (HIPAA for US customers, GDPR for EU markets)[1][2].

Primary business risks requiring mitigation:
1. Dependency on third-party LLM providers creating vendor lock-in and potential service disruptions
2. Unauthorized access to proprietary dietitian content samples compromising competitive advantage
3. Regulatory non-compliance leading to financial penalties and reputational damage

## SECURITY POSTURE
**Existing Security Controls:**
- security control: API key authentication for Meal Planner applications via Kong API Gateway[3]
- security control: TLS 1.3 encryption for all external communications[4]
- security control: Rate limiting at API Gateway layer (1000 requests/minute per client)[5]
- security control: Input validation filters for SQLi and XSS patterns in API payloads[6]

**Accepted Risks:**
- accepted risk: Third-party LLM dependency with contractual SLAs but no direct security control over ChatGPT-3.5 outputs
- accepted risk: Encrypted data at rest in RDS using AWS default encryption rather than customer-managed keys

**Recommended Security Controls:**
1. Implementation of multi-factor authentication for administrator access to Web Control Plane
2. Regular third-party penetration testing of API endpoints (quarterly schedule)
3. Data loss prevention (DLP) scanning for sensitive content in LLM training datasets

**Security Requirements:**
- Authentication: OAuth 2.0 client credentials flow for machine-to-machine authentication
- Authorization: Role-based access control (RBAC) with tenant isolation in database layer
- Input Validation: Strict schema validation for all API requests with max payload size of 1MB
- Cryptography: AES-256-GCM for sensitive data fields with quarterly key rotation

## DESIGN
### C4 CONTEXT
```mermaid
C4Container
    title Context Diagram for AI Nutrition-Pro

    Container_Boundary(c0, "AI Nutrition-Pro") {
        Container(api_gw, "API Gateway", "Kong", "AuthN/Z, rate limiting, input filtering")
        Container(ctrl_plane, "Web Control Plane", "Golang/ECS", "Tenant management & billing")
        ContainerDb(cp_db, "Control Plane DB", "RDS PostgreSQL", "Tenant config & metadata")
        Container(backend, "API Application", "Golang/ECS", "Content generation services")
        ContainerDb(api_db, "API Database", "RDS PostgreSQL", "LLM training data & logs")
        Person(admin, "Administrator", "System configuration")
    }

    System_Ext(meal_app, "Meal Planner", "Third-party diet app")
    System_Ext(openai, "ChatGPT-3.5", "LLM provider")

    Rel(meal_app, api_gw, "HTTPS/REST API calls", "TLS 1.3")
    Rel(api_gw, backend, "Internal API routing", "TLS 1.2")
    Rel(admin, ctrl_plane, "Admin console access", "HTTPS")
    Rel(backend, openai, "LLM API consumption", "HTTPS")
    Rel(ctrl_plane, cp_db, "Database queries", "TLS")
    Rel(backend, api_db, "Training data storage", "TLS")
```

#### Context Element Descriptions
| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| API Gateway | Reverse Proxy | Kong implementation handling external traffic | - TLS termination <br> - Request validation <br> - Rate limiting | - WAF rulesets <br> - Mutual TLS for internal services |
| Web Control Plane | Management UI | Golang application for system administration | - Tenant onboarding <br> - Billing management <br> - Access logging | - RBAC implementation <br> - Audit logging |
| Control Plane DB | Relational Database | RDS PostgreSQL instance | - Store tenant configurations <br> - Maintain billing records | - Encryption at rest <br> - Automated backups |
| API Application | Microservice | Content generation service | - Process LLM requests <br> - Maintain usage metrics | - Input sanitization <br> - Output validation |
| API Database | Relational Database | RDS PostgreSQL instance | - Store training data <br> - Audit API interactions | - Column-level encryption <br> - PII tagging |
| Administrator | Human Actor | System operator | - Configure security policies <br> - Monitor system health | - MFA enforcement <br> - Privileged access management |

### C4 CONTAINER
```mermaid
C4Container
    title Container Diagram for AI Nutrition-Pro

    Container_Boundary(infra, "AWS Infrastructure") {
        Container(api_gw, "API Gateway", "Kong", "North-South traffic management")
        Container(ctrl_plane, "Web Control Plane", "Golang", "Tenant lifecycle management")
        ContainerDb(cp_db, "Control Plane DB", "RDS", "Tenant metadata storage")
        Container(backend, "API Application", "Golang", "Content generation engine")
        ContainerDb(api_db, "API Database", "RDS", "LLM training data storage")
    }

    System_Ext(meal_app, "Meal Planner App", "Customer application")
    System_Ext(openai, "ChatGPT-3.5", "LLM provider")
    Person(admin, "Administrator")

    Rel(meal_app, api_gw, "API calls", "HTTPS")
    Rel(api_gw, backend, "Internal routing", "HTTPS")
    Rel(admin, ctrl_plane, "Management access", "HTTPS")
    Rel(backend, openai, "LLM API usage", "HTTPS")
    Rel(ctrl_plane, cp_db, "Data access", "TLS")
    Rel(backend, api_db, "Data storage", "TLS")
```

#### Container Element Descriptions
| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| Kong API Gateway | Service Proxy | Manages external API traffic | - Authentication <br> - Request validation | - JWT validation <br> - IP whitelisting |
| Control Plane Service | Web Application | Golang ECS service | - Tenant management <br> - Usage reporting | - Session management <br> - CSRF protection |
| Content API Service | Microservice | Golang ECS service | - LLM integration <br> - Content generation | - Output encoding <br> - Content signing |
| RDS Instances | Database | PostgreSQL clusters | - Persistent data storage | - Automatic patching <br> - IAM authentication |

### DEPLOYMENT
```mermaid
graph TD
    subgraph AWS Region
        subgraph VPC
            subgraph Public Subnet
                API_GW[Kong API Gateway]
            end

            subgraph Private Subnet
                ECS_Cluster[ECS Cluster]
                RDS[Amazon RDS]
            end

            API_GW -->|TLS| ECS_Cluster
            ECS_Cluster -->|TLS| RDS
        end

        ACM[ACM Certificates]
        KMS[KMS Keys]
        CloudWatch[CloudWatch Logs]
    end

    Meal_App[Meal Planner App] -->|HTTPS| API_GW
    Admin[Administrator] -->|VPN| ECS_Cluster
    ECS_Cluster -->|HTTPS| OpenAI[ChatGPT API]
```

#### Deployment Components
| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| Kong API Gateway | Network Service | Edge traffic management | - TLS termination <br> - Request filtering | - Security group restrictions <br> - DDoS protection |
| ECS Cluster | Compute | Container orchestration | - Service deployment <br> - Auto-scaling | - Task IAM roles <br> - Container scanning |
| RDS PostgreSQL | Database | Data persistence | - ACID compliance <br> - Query processing | - Network isolation <br> - Automated backups |
| KMS | Cryptography | Key management | - Encryption key rotation <br> - Access policies | - Hardware security modules <br> - Audit logging |

### BUILD
```mermaid
graph LR
    Dev[Developer Workstation] -->|Code Commit| GitHub
    GitHub -->|Trigger| Actions[GitHub Actions]
    Actions -->|Build| ECR[ECR Container Registry]
    Actions -->|Scan| Trivy[Trivy Security Scan]
    ECR -->|Deploy| ECS[ECS Services]

    style Dev fill:#f9f,stroke:#333
    style GitHub fill:#b8d1ff,stroke:#333
    style Actions fill:#ffd966,stroke:#333
    style ECR fill:#93c47d,stroke:#333
```

**Build Security Controls:**
1. Supply Chain:
   - Signed commits requiring GPG verification
   - Dependency scanning via OWASP Dependency-Check
   - Provenance attestation for container images

2. Automation:
   - SAST scanning with Semgrep and CodeQL
   - SCA analysis using Renovate Bot
   - Container vulnerability scanning with Trivy

3. Artifact Security:
   - Immutable container tags in ECR
   - SBOM generation for each release
   - Notary v2 signatures for all artifacts

## RISK ASSESSMENT
**Critical Business Processes:**
1. Client onboarding workflow handling sensitive organizational data
2. LLM content generation maintaining dietitian-specific voice profiles
3. Billing reconciliation processes involving payment data

**Protected Data Assets:**
| Data Type | Sensitivity | Protection Measures |
| --- | --- | --- |
| Tenant API Keys | High | - KMS encryption <br> - Key rotation every 90 days |
| LLM Training Data | Medium | - Anonymization <br> - Access logging |
| Billing Records | High | - PCI DSS compliance <br> - Tokenization |
| Audit Logs | Medium | - Immutable storage <br> - SIEM integration |

## QUESTIONS & ASSUMPTIONS
**Outstanding Questions:**
1. Multi-tenancy Implementation:
   - Is tenant isolation implemented at application layer or database layer?
   - Default assumption: Schema-based isolation in PostgreSQL

2. Incident Response:
   - What SLA exists for security incident response?
   - Default assumption: 1-hour response time for P1 incidents

3. Compliance Scope:
   - Which specific GDPR/HIPAA articles require implementation?
   - Default assumption: Article 32 (Security of processing) and HIPAA §164.312

**Architectural Assumptions:**
1. All internal service communication uses mutual TLS authentication
2. API Gateway performs request validation against OpenAPI specifications
3. Database credentials are rotated automatically using IAM roles
4. LLM outputs undergo content moderation filtering before delivery
