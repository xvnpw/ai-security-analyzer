# APPLICATION THREAT MODEL

## ASSETS
- API Gateway: The entry point for external Meal Planner applications. It performs API key authentication, rate limiting, and input filtering.
- Web Control Plane: A Golang-based interface for administrators to onboard clients, configure system properties, and check billing data.
- Control Plane Database: An Amazon RDS instance storing sensitive control data such as tenant information and billing records.
- API Application (Backend API): A Golang service deployed on AWS ECS that provides AI Nutrition-Pro functionality and integrates with ChatGPT.
- API Database: An Amazon RDS instance that holds dietitian content samples as well as request and response data exchanged with the LLM.
- External Systems and Actors:
  - Meal Planner Application: An external client that uses REST/HTTPS to interact with the system.
  - ChatGPT-3.5: An external LLM service used by the API Application for generating content.
  - Administrator: A trusted internal person responsible for system configuration and management.

## TRUST BOUNDARIES
- Between the Public Internet and AI Nutrition-Pro: Traffic from Meal Planner applications enters via the API Gateway, crossing from an untrusted external network to an internal network.
- Between API Gateway and Internal Services: Although API Gateway and subsequent services (API Application, Web Control Plane) reside within the same container boundary, the transition from an externally facing component to internal services represents a trust boundary.
- Between Internal Services and External LLM: Communication from the API Application to ChatGPT crosses from the internal secured network to an external system.
- Between Administrative Access and the Application: The Web Control Plane’s administrative interface potentially sits in its own boundary, segregating high-privilege access from routine external API interactions.

## DATA FLOWS
- Meal Planner Application → API Gateway: HTTPS/REST calls accompanied by API key authentication (crosses the external-to-internal trust boundary).
- API Gateway → API Application: Internal HTTPS/REST calls via the secure network.
- Administrator → Web Control Plane: Administrative interactions for configuration and management.
- Web Control Plane → Control Plane Database: Encrypted TLS read/write operations.
- API Application → API Database: Encrypted TLS communications for storing and retrieving dietitian content and LLM records.
- API Application → ChatGPT: HTTPS/REST calls for AI-powered content generation (crosses the internal-to-external trust boundary).

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME    | THREAT NAME                                                                                           | STRIDE CATEGORY       | WHY APPLICABLE                                                                                   | HOW MITIGATED                                       | MITIGATION                                                                                           | LIKELIHOOD EXPLANATION                                  | IMPACT EXPLANATION                                                   | RISK SEVERITY |
|-----------|-------------------|-------------------------------------------------------------------------------------------------------|-----------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------|----------------------------------------------------------------------|---------------|
| 0001      | API Gateway       | Attacker impersonates a Meal Planner application using forged API keys                                | Spoofing              | The gateway relies on API key authentication for externally sourced requests.                  | Basic API key authentication is implemented.       | Enhance API key security by enforcing mTLS, regular key rotation, and anomaly detection on key usage. | Moderately likely if API keys are leaked or mismanaged   | Unauthorized access could lead to broad misuse of the service.         | High          |
| 0002      | API Gateway       | Tampering with HTTP requests to bypass ACL rules                                                     | Tampering             | ACL rules and filtering are crucial, yet an attacker might modify requests to evade these rules. | Rate limiting and ACL rules are applied.           | Introduce strict request validation and anomaly detection to monitor unusual request patterns.        | Moderately likely in directed attacks                  | Successful tampering may result in unauthorized actions and data misuse. | High          |
| 0003      | Web Control Plane | Unauthorized access via compromised administrator credentials                                        | Spoofing              | The control plane holds sensitive configuration and billing information.                       | Authentication is required for administrative access.| Implement multi-factor authentication and enforce strict access policies.                           | Moderately likely if credential hygiene is weak        | A compromise here could affect the entire application's configuration and operation. | Critical      |
| 0004      | Web Control Plane | Data tampering by a malicious insider modifying system configurations                                | Tampering             | Insider access can be abused to change configurations impacting system behavior and billing.   | Administrative changes are limited to authenticated users. | Deploy audit logging, enforce separation-of-duties, and regularly review configuration changes. | Moderately likely given insider risk factors           | Tampered configurations could lead to operational disruptions and financial losses. | High          |
| 0005      | Control Plane Database | Exfiltration of tenant and billing data via compromised credentials                                 | Information Disclosure| This database contains critical and sensitive control data.                                    | Encrypted communications and access controls are used.| Rotate credentials frequently, enforce strict IAM policies, and apply network segmentation.         | Moderately likely if database credentials are leaked    | Data breaches could result in regulatory, financial, and reputational damage. | High          |
| 0006      | API Application   | Tampering with API payloads to manipulate AI Nutrition-Pro responses                                   | Tampering             | The API Application influences AI outputs and handles critical data flows.                     | TLS encryption is used for communications.         | Implement integrity verification (e.g., digital signatures) and strict input/output validation.   | Moderately likely if input validation is insufficient   | Payload manipulation may lead to incorrect or malicious AI behavior affecting service quality. | Medium        |
| 0007      | API Application   | Exposure of sensitive dietitian content due to misconfigured API responses                             | Information Disclosure| The API returns data from the API Database that, if misconfigured, may expose sensitive content. | TLS and role-based access controls are applied.    | Refine API responses based on user roles and conduct regular reviews of endpoint output configurations. | Low to moderate likelihood depending on configuration  | Leakage may compromise intellectual property and affect user privacy.    | Medium        |
| 0008      | API Database      | Tampering with database records to inject malicious content                                            | Tampering             | Integrity of content in the API Database is critical for reliable AI generation.                | Access controls and encrypted links from API Application protect data.| Employ database auditing, integrity checks, and automated alerts for abnormal modifications.         | Low likelihood with proper security measures           | Successful tampering could undermine AI responses, causing erroneous outputs. | High          |
| 0009      | API Application   | Denial of Service by flooding ChatGPT with excessive requests                                          | Denial of Service     | AI content generation relies on external LLM access; flooding can exhaust rate limits or resources.| Basic TLS encryption is used for outgoing communications. | Apply outbound rate limiting, circuit breakers, and monitor request patterns to the LLM service.       | Moderately likely under targeted abuse scenarios       | Service disruption may lead to unavailability of AI features, affecting overall application service. | High          |

# DEPLOYMENT THREAT MODEL

## ASSETS
- AWS Elastic Container Service (ECS) Cluster: Hosts the containerized components including API Gateway, Web Control Plane, and API Application.
- Container Images: Docker images for the API Gateway, Web Control Plane, and API Application.
- AWS RDS Instances: Databases hosting both the Control Plane and API data.
- Load Balancers and TLS Certificates: Manage and secure inbound traffic from external sources.
- AWS IAM Roles and Policies: Define permissions for ECS tasks and other AWS resources.
- Network Configurations: VPC, subnets, security groups, and ACLs that secure the deployment environment.

## TRUST BOUNDARIES
- Public Internet to Load Balancer: External traffic (e.g., from Meal Planner applications) must cross from an untrusted network to the load balancer.
- Load Balancer to ECS Cluster: Traffic flows from the load balancer to containerized services within a secured VPC, creating a boundary.
- ECS Cluster to RDS Instances: Containers access databases over encrypted connections governed by security group rules.
- AWS Management vs. Production Environments: Administrative interfaces and deployment configurations remain isolated from production workloads.

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME             | THREAT NAME                                                                  | WHY APPLICABLE                                                                                 | HOW MITIGATED                                         | MITIGATION                                                                                               | LIKELIHOOD EXPLANATION                                  | IMPACT EXPLANATION                                                   | RISK SEVERITY |
|-----------|----------------------------|------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|-------------------------------------------------------|----------------------------------------------------------------------------------------------------------|--------------------------------------------------------|----------------------------------------------------------------------|---------------|
| 0001      | AWS RDS Instances          | Exposure of RDS instances due to misconfigured security groups                 | Insecure security group settings or ACL misconfigurations could inadvertently expose the DB.   | Deployed within a VPC with basic security group rules. | Enforce strict security group policies, utilize VPC peering and network ACLs to restrict access tightly.    | Moderate if configuration errors are present           | Unauthorized database access could result in major data breaches.        | High          |
| 0002      | ECS Cluster                | Container escape through vulnerabilities in isolation                        | Container vulnerabilities may allow an attacker to break out of one container and affect the host.| Default container isolation is provided by ECS.      | Use hardened, regularly scanned container images, apply runtime security measures, and implement container isolation best practices. | Low to moderate with proper patching and isolation       | A successful escape could lead to compromise of the entire ECS cluster and sensitive data exposure. | High          |
| 0003      | Load Balancer              | TLS certificate mismanagement leading to man-in-the-middle attacks             | Insecure or mismanaged TLS certificates could undermine secured traffic between clients and services. | TLS termination is implemented at the load balancer. | Implement automated certificate management, enforce strong TLS configurations, and conduct regular certificate audits.      | Low likelihood with robust certificate management       | An MITM attack could intercept or alter data in transit, undermining confidentiality and integrity. | High          |
| 0004      | AWS IAM Roles (ECS Tasks)  | Overly permissive IAM roles enabling lateral movement across AWS resources       | Excessive permissions can allow compromised containers to access and affect other resources.     | IAM roles are in use; however, granularity details are not specified. | Regularly review and restrict IAM roles to the principle of least privilege, and audit permissions periodically.             | Moderate if roles are not tightly constrained            | A breach here could escalate access across the AWS environment, leading to widespread impact. | High          |

# BUILD THREAT MODEL

## ASSETS
- Source Code and Repositories: Houses the application code for API Gateway, Web Control Plane, and API Application.
- Build Scripts and Dockerfiles: Instructions and configurations used to build container images.
- CI/CD Pipeline: The automated build and deployment system (e.g., GitHub Workflows, Jenkins) that orchestrates the build process.
- Third-Party Dependencies: Externally sourced libraries and base images used during builds.
- Build Environment and Credentials: The systems and sensitive credentials used during the build and publication processes.

## TRUST BOUNDARIES
- Developer Environment vs. CI/CD Environment: Separation exists between local development systems and the centralized build server.
- CI/CD Environment Isolation: The build process runs in controlled, often ephemeral, environments isolated from production systems.
- Repository Access: The source code repositories are separated by access controls from external public submissions.

## BUILD THREATS

| THREAT ID | COMPONENT NAME                 | THREAT NAME                                                                                  | WHY APPLICABLE                                                                                        | HOW MITIGATED                                                       | MITIGATION                                                                                             | LIKELIHOOD EXPLANATION                                  | IMPACT EXPLANATION                                                   | RISK SEVERITY |
|-----------|--------------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------|----------------------------------------------------------------------|---------------|
| 0001      | Pipeline                       | Injection of malicious code into build scripts via a compromised CI/CD pipeline                | A breach in the build pipeline could allow untrusted code to be built into production images.          | Basic pipeline security is assumed, though specific measures are not detailed. | Harden the CI/CD pipeline with strict access controls, SAST scanning, secure credential management, and mandatory code reviews. | Moderate if pipeline security practices are insufficient  | A compromised pipeline can lead to a full supply chain attack impacting all deployed components.   | Critical      |
| 0002      | Builder/Runner                 | Compromise of the ephemeral build environment leading to leakage of build secrets               | Build environments often process sensitive credentials and secrets during image construction.         | Usage of ephemeral build instances is assumed but secret handling practices are not detailed.  | Utilize dedicated secret management tools, enforce ephemeral instance policies, and restrict access during build processes.   | Moderate if secret management is neglected                | Exposure of build secrets can allow attackers to sign and distribute malicious images or access source code. | High          |
| 0003      | Source Code Repository / Dockerfile | Supply chain attack through compromised third-party dependencies or tampered base images         | Reliance on external components introduces risk if these dependencies or base images are tampered with. | Some dependency scanning is assumed but specifics are not provided.          | Enforce the use of verified base images, implement automated dependency vulnerability scanning, and monitor third-party advisories.       | Moderate due to frequent updates and external dependency risks  | A compromised dependency can infiltrate all built images, undermining the entire application’s security. | High          |

# QUESTIONS & ASSUMPTIONS
- It is assumed that a CI/CD pipeline (such as GitHub Workflows, Jenkins, or similar) is in use even though specific details are not provided.
- Are there detailed security measures in place for CI/CD access control and credential management?
- Is multi-factor authentication enforced for administrator access to the Web Control Plane?
- Are container images and third-party dependencies regularly scanned for vulnerabilities before deployment?
- Is there sufficient isolation between different containers within the ECS cluster (e.g., via micro-segmentation or tightened security groups)?
- It is assumed that TLS encryption is properly configured and maintained across all internal and external data flows.
- Further details regarding the build process and specific security controls would help refine the threat model.
