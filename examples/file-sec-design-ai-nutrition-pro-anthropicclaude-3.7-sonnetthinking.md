# AI Nutrition-Pro Design Document

## BUSINESS POSTURE

AI Nutrition-Pro is a software-as-a-service application designed to provide AI-enhanced nutrition content generation capabilities to meal planning applications. The system leverages large language models (specifically ChatGPT-3.5) to generate personalized nutritional content based on dietitians' sample content.

Business priorities and goals include:
1. Enabling dietitians to scale their expertise through AI-assisted content generation
2. Providing a multi-tenant platform that can serve multiple meal planning applications
3. Offering high-quality, personalized nutrition content generation
4. Maintaining data separation between different clients
5. Establishing a reliable and scalable cloud infrastructure

Key business risks that need to be addressed:
1. Dependency on third-party LLM provider (OpenAI's ChatGPT)
2. Content quality and accuracy risks when generating nutritional advice
3. Cost management of LLM API usage
4. Multi-tenant data separation and privacy concerns
5. Scaling challenges as the platform grows

## SECURITY POSTURE

Existing security controls and accepted risks:

- Security control: Authentication with API keys for each Meal Planner application integration
- Security control: Authorization via API Gateway ACL rules that allow or deny specific actions
- Security control: Network traffic encryption using TLS between Meal Planner applications and API Gateway
- Security control: Containerized applications running on AWS Elastic Container Service
- Security control: Database isolation using Amazon RDS
- Accepted risk: Dependency on third-party LLM provider (OpenAI) security

Recommended high-priority security controls:
- Security control: Implement proper secrets management for API keys and credentials
- Security control: Add input validation and content filtering before requests reach the LLM
- Security control: Implement logging and monitoring for security events
- Security control: Add data encryption at rest for all databases
- Security control: Implement regular security scanning of container images
- Security control: Deploy web application firewall (WAF) in front of API Gateway

Security requirements:

Authentication:
- Strong API key management with key rotation capabilities
- Multi-factor authentication for administrator access to control plane
- Token-based authentication with short expiration times

Authorization:
- Role-based access control (RBAC) for administrative functions
- Fine-grained permissions for API access based on client subscription level
- Tenant data isolation enforced at the database and application level

Input Validation:
- Sanitization of all client inputs before processing
- Schema validation for API requests
- Rate limiting to prevent abuse
- Content filtering to prevent prompt injection attacks

Cryptography:
- TLS 1.2+ for all communications
- Data encryption at rest for databases
- Secure key management for encryption keys
- Strong hashing algorithms for sensitive data

## DESIGN

### C4 CONTEXT

```mermaid
C4Context
    title System Context diagram for AI Nutrition-Pro

    Person(dietitian, "Dietitian", "A nutrition professional who creates meal plans")
    Person(admin, "Administrator", "Administrator of the AI Nutrition-Pro platform")

    System(aiNutritionPro, "AI Nutrition-Pro", "Generates AI-enhanced nutrition content based on dietitians' samples")

    System_Ext(mealPlannerApp, "Meal Planner", "Application used by dietitians to create meal plans")
    System_Ext(openai, "OpenAI ChatGPT", "Large Language Model provider")

    Rel(dietitian, mealPlannerApp, "Uses to create meal plans")
    Rel(mealPlannerApp, aiNutritionPro, "Sends sample content and receives AI-generated nutrition content", "HTTPS/REST")
    Rel(aiNutritionPro, openai, "Sends prompts and receives generated content", "HTTPS/REST")
    Rel(admin, aiNutritionPro, "Manages platform, clients, and configuration")
```

#### Context Elements

| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| Dietitian | Person | Nutrition professional who creates meal plans | - Creates meal plans<br>- Provides sample content<br>- Reviews AI-generated content | - Training on system usage<br>- Content quality review |
| Administrator | Person | Admin of AI Nutrition-Pro platform | - Onboard new clients<br>- Configure system<br>- Monitor usage and billing<br>- Troubleshoot issues | - MFA authentication<br>- RBAC authorization<br>- Activity logging |
| AI Nutrition-Pro | System | Core system providing AI-enhanced nutrition content | - Process nutrition content requests<br>- Interface with OpenAI<br>- Manage client accounts<br>- Track usage and billing | - API authentication<br>- Data encryption<br>- Input validation<br>- Rate limiting |
| Meal Planner | External System | Third-party application used by dietitians | - Provide UI for meal planning<br>- Send requests to AI Nutrition-Pro<br>- Display AI-generated content | - API key management<br>- TLS encryption |
| OpenAI ChatGPT | External System | LLM provider used for content generation | - Process prompts<br>- Generate nutrition content | - API authentication<br>- Data handling policies |

### C4 CONTAINER

```mermaid
C4Container
    title Container diagram for AI Nutrition-Pro

    Person(dietitian, "Dietitian", "A nutrition professional who creates meal plans")
    Person(admin, "Administrator", "Administrator of AI Nutrition-Pro application")

    System_Ext(mealApp, "Meal Planner", "Application to create diets by dietitians")
    System_Ext(chatgpt, "ChatGPT-3.5", "LLM")

    Container_Boundary(c0, "AI Nutrition-Pro") {
        Container(api_gateway, "API Gateway", "Kong", "Authentication of clients, filtering of input, rate limiting")
        Container(app_control_plane, "Web Control Plane", "Golang, AWS Elastic Container Service", "Provides control plane to onboard and manage clients, configuration and check billing data")
        ContainerDb(control_plan_db, "Control Plane Database", "Amazon RDS", "Stores all data related to control plan, tenants, billing")
        Container(backend_api, "API Application", "Golang, AWS Elastic Container Service", "Provides AI Nutrition-Pro functionality via API")
        ContainerDb(api_db, "API database", "Amazon RDS", "Stores dietitian' content samples, request and responses to LLM.")
    }

    Rel(dietitian, mealApp, "Uses to create meal plans")
    Rel(mealApp, api_gateway, "Uses for AI content generation", "HTTPS/REST")
    Rel(api_gateway, backend_api, "Routes authenticated requests", "HTTPS/REST")
    Rel(admin, app_control_plane, "Configure system properties", "HTTPS")
    Rel(backend_api, chatgpt, "Utilizes ChatGPT for LLM-featured content creation", "HTTPS/REST")
    Rel(app_control_plane, control_plan_db, "Read/write data", "TLS")
    Rel(backend_api, api_db, "Read/write data", "TLS")
    Rel(backend_api, app_control_plane, "Checks tenant configuration", "HTTPS/REST")
```

#### Container Elements

| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| API Gateway | Container (Gateway) | Kong API Gateway | - Authentication of clients<br>- Rate limiting<br>- Input filtering<br>- Request routing | - API key validation<br>- TLS termination<br>- Request validation<br>- Rate limiting<br>- WAF integration |
| Web Control Plane | Container (Web Application) | Golang application for system administration | - Client onboarding<br>- System configuration<br>- Billing management<br>- Usage reporting | - MFA authentication<br>- RBAC authorization<br>- Audit logging<br>- Input validation |
| Control Plane Database | Container (Database) | Amazon RDS database for control plane | - Store tenant information<br>- Store billing data<br>- Store system configuration | - Data encryption at rest<br>- Network isolation<br>- Access control<br>- Backup encryption |
| API Application | Container (API Service) | Golang application providing core functionality | - Process content requests<br>- Communicate with OpenAI<br>- Store request/response data<br>- Tenant data isolation | - Request validation<br>- Content filtering<br>- Tenant isolation<br>- Error handling<br>- Logging |
| API Database | Container (Database) | Amazon RDS database for API service | - Store dietitian content samples<br>- Store LLM requests/responses<br>- Store usage metrics | - Data encryption at rest<br>- Tenant data isolation<br>- Access control<br>- Backup encryption |

### DEPLOYMENT

AI Nutrition-Pro is deployed on AWS cloud infrastructure, utilizing containerized services for scalability and reliability. The primary deployment architecture is a multi-region AWS deployment for high availability.

Possible deployment architectures:
1. Single-region AWS deployment
2. Multi-region AWS deployment for high availability
3. Hybrid deployment with on-premise components

For this document, we'll focus on the multi-region AWS deployment.

```mermaid
C4Deployment
    title Deployment Diagram for AI Nutrition-Pro

    Deployment_Node(aws, "Amazon Web Services", "Cloud Provider") {
        Deployment_Node(primary_region, "Primary Region", "us-east-1") {
            Deployment_Node(primary_vpc, "VPC", "Virtual Private Cloud") {
                Deployment_Node(public_subnet, "Public Subnet", "Network Zone") {
                    Deployment_Node(alb, "Application Load Balancer", "AWS ALB") {
                        Container(waf, "Web Application Firewall", "AWS WAF", "Protects against common web exploits")
                    }
                }

                Deployment_Node(private_subnet_1, "Private Subnet - Web Tier", "Network Zone") {
                    Deployment_Node(ecs_cluster_1, "ECS Cluster", "Container Orchestration") {
                        Deployment_Node(api_gateway_task, "API Gateway Task", "ECS Task") {
                            Container(api_gateway_instance, "API Gateway", "Kong", "API Gateway for authentication and routing")
                        }
                        Deployment_Node(control_plane_task, "Control Plane Task", "ECS Task") {
                            Container(control_plane_instance, "Web Control Plane", "Golang", "Admin interface")
                        }
                    }
                }

                Deployment_Node(private_subnet_2, "Private Subnet - App Tier", "Network Zone") {
                    Deployment_Node(ecs_cluster_2, "ECS Cluster", "Container Orchestration") {
                        Deployment_Node(api_app_task, "API App Task", "ECS Task") {
                            Container(api_app_instance, "API Application", "Golang", "Core application logic")
                        }
                    }
                }

                Deployment_Node(private_subnet_3, "Private Subnet - Data Tier", "Network Zone") {
                    Deployment_Node(rds_cp, "RDS Instance", "Database") {
                        ContainerDb(control_plane_db_instance, "Control Plane DB", "PostgreSQL", "Control plane database")
                    }
                    Deployment_Node(rds_api, "RDS Instance", "Database") {
                        ContainerDb(api_db_instance, "API DB", "PostgreSQL", "API application database")
                    }
                }
            }
        }

        Deployment_Node(dr_region, "DR Region", "us-west-2") {
            Deployment_Node(dr_vpc, "VPC", "Virtual Private Cloud") {
                Deployment_Node(dr_private_subnet_3, "Private Subnet - Data Tier", "Network Zone") {
                    Deployment_Node(dr_rds_cp, "RDS Instance", "Database") {
                        ContainerDb(dr_control_plane_db, "Control Plane DB", "PostgreSQL", "Replica of control plane database")
                    }
                    Deployment_Node(dr_rds_api, "RDS Instance", "Database") {
                        ContainerDb(dr_api_db, "API DB", "PostgreSQL", "Replica of API database")
                    }
                }
            }
        }
    }

    Rel(waf, api_gateway_instance, "Forwards filtered traffic", "HTTPS")
    Rel(api_gateway_instance, api_app_instance, "Routes authenticated requests", "HTTPS")
    Rel(api_app_instance, control_plane_instance, "Checks tenant configuration", "HTTPS")
    Rel(api_app_instance, api_db_instance, "Reads/writes data", "TLS")
    Rel(control_plane_instance, control_plane_db_instance, "Reads/writes data", "TLS")
    Rel(control_plane_db_instance, dr_control_plane_db, "Replicates data", "TLS")
    Rel(api_db_instance, dr_api_db, "Replicates data", "TLS")
```

#### Deployment Elements

| Name | Type | Description | Responsibilities | Security Controls |
| --- | --- | --- | --- | --- |
| AWS WAF | Security Component | Web Application Firewall | - Block common web attacks<br>- Filter malicious traffic | - Rule-based filtering<br>- DDoS protection<br>- Bot control |
| Application Load Balancer | Network Component | AWS Load Balancer | - Distribute traffic<br>- Health checking<br>- TLS termination | - TLS 1.2+ support<br>- Security groups<br>- Access logging |
| API Gateway Task | Container Host | ECS Task for API Gateway | - Host Kong API Gateway<br>- Auto-scale based on demand | - Task IAM roles<br>- Task isolation<br>- Security groups |
| Control Plane Task | Container Host | ECS Task for Control Plane | - Host Control Plane application<br>- Auto-scale based on demand | - Task IAM roles<br>- Task isolation<br>- Security groups |
| API App Task | Container Host | ECS Task for API Application | - Host API application<br>- Auto-scale based on demand | - Task IAM roles<br>- Task isolation<br>- Security groups |
| RDS Instances | Database Host | AWS RDS for PostgreSQL | - Host databases<br>- Auto backup<br>- Replicate to DR region | - Database encryption<br>- Network isolation<br>- IAM authentication<br>- Backup encryption |
| VPC | Network Component | AWS Virtual Private Cloud | - Network isolation<br>- Security zoning | - NACL filtering<br>- VPC flow logs<br>- Private subnets |

### BUILD

The build process for AI Nutrition-Pro components follows a secure DevOps pipeline approach, utilizing GitHub for source control, GitHub Actions for CI/CD, and various security tools integrated throughout the process.

```mermaid
graph TD
    A[Developer] -->|Git Commit| B[GitHub Repository]
    B -->|Trigger Build| C[GitHub Actions CI Pipeline]
    C -->|Static Code Analysis| D[SonarQube]
    C -->|Dependency Scanning| E[OWASP Dependency Check]
    C -->|Secret Scanning| F[GitGuardian]
    C -->|Build Containers| G[Docker Build]
    G -->|Scan Container Images| H[Trivy Scanner]
    H -->|Push Images| I[ECR Repository]
    I -->|Deploy to Dev| J[AWS Dev Environment]
    J -->|Run Integration Tests| K[Integration Tests]
    K -->|Manual Approval| L[Release Manager Approval]
    L -->|Promote to Staging| M[AWS Staging Environment]
    M -->|Run Performance Tests| N[Performance Tests]
    N -->|Final Approval| O[Security Team Review]
    O -->|Promote to Production| P[AWS Production Environment]
```

The build process incorporates several security controls:

1. Source code management:
   - Code reviews required for all changes
   - Branch protection rules
   - Signed commits requirement

2. Dependency management:
   - OWASP Dependency Check scans for vulnerable dependencies
   - Approved dependency sources only
   - Regular dependency updates

3. Static analysis:
   - SonarQube for static code analysis
   - Gosec for Go-specific security checks
   - Linting for code quality and security issues

4. Container security:
   - Minimal base images (distroless/alpine)
   - Trivy scanner for container vulnerabilities
   - No root user in containers
   - Immutable file systems

5. Secret management:
   - GitGuardian for secret scanning
   - AWS Secrets Manager for runtime secrets
   - No hardcoded secrets in code/configuration

6. Artifact integrity:
   - Container image signing
   - SHA256 verification of all artifacts
   - Immutable tags in container registry

7. Deployment security:
   - Infrastructure as Code (Terraform) with security checks
   - Least privilege IAM roles
   - Blue/green deployment strategy

## RISK ASSESSMENT

Critical business processes we are trying to protect:
1. AI-powered nutrition content generation
2. Multi-tenant client management
3. User data handling and storage
4. Integration with external LLM providers
5. Billing and subscription management

Data we are trying to protect and their sensitivity:

1. Client API keys and credentials (High sensitivity)
   - Used for authentication between meal planning applications and AI Nutrition-Pro
   - Compromise would allow unauthorized access to API

2. Dietitian content samples (Medium-High sensitivity)
   - Original content written by dietitians
   - May contain intellectual property
   - Could contain personal nutrition information

3. LLM requests and responses (Medium sensitivity)
   - Contains prompts and generated content
   - Could reveal prompt engineering techniques
   - May contain trace amounts of nutritional advice

4. Client billing information (High sensitivity)
   - Contains usage metrics
   - Pricing information
   - Payment details

5. System configuration data (Medium sensitivity)
   - Contains integration settings
   - System parameters
   - API endpoints

6. User credentials for admin portal (High sensitivity)
   - Admin account credentials
   - Session information
   - Access control settings

## QUESTIONS & ASSUMPTIONS

### Business Posture Questions
1. What service level objectives are required for the platform?
2. Is there a specific target market or industry vertical for the service?
3. Are there specific compliance requirements for nutritional advice?
4. What is the target scale in terms of number of clients and request volume?

### Business Posture Assumptions
1. The platform aims to serve multiple meal planning applications (multi-tenant).
2. Cost efficiency of LLM API usage is a business priority.
3. Content quality and accuracy are critical for maintaining trust.
4. The platform needs to scale horizontally as demand grows.

### Security Posture Questions
1. What specific regulatory requirements apply to the nutritional content?
2. Is there a need for data residency requirements in specific regions?
3. What is the incident response process for security events?
4. How are API keys revoked if compromised?

### Security Posture Assumptions
1. The system will need to comply with data protection regulations (GDPR, CCPA).
2. Client data must be logically separated at minimum, physical separation preferred.
3. All sensitive data should be encrypted at rest and in transit.
4. Penetration testing will be conducted regularly.

### Design Questions
1. What is the anticipated request volume per client?
2. What is the required response time for API requests?
3. Are there requirements for offline operation if OpenAI is unavailable?
4. Is there a need for custom LLM fine-tuning?

### Design Assumptions
1. The system will be deployed on AWS using containerized applications.
2. Database backups will be encrypted and stored securely.
3. The system will be designed for high availability with multi-region capabilities.
4. API Gateway will handle authentication, rate limiting, and input validation.
