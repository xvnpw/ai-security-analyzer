# APPLICATION THREAT MODEL

## ASSETS

- Tenant Data: Includes client information, billing data, and configurations stored in the Control Plane Database. This is sensitive business data.
- Dietitian Content Samples: Intellectual property of the dietitians/Meal Planner applications. Could contain sensitive health information if not properly anonymized. Stored in the API Database.
- LLM Prompts and Responses: The history of interactions with ChatGPT. This represents business logic and could contain sensitive information passed through the API. Stored in the API Database.
- Meal Planner API Keys: Credentials used to authenticate third-party client applications. A compromise would allow an attacker to impersonate a legitimate client.
- System Availability: The overall uptime and responsiveness of the AI Nutrition-Pro service, which is critical for business operations.
- System Configuration: Administrator-managed settings that control the behavior and security of the entire platform.

## TRUST BOUNDARIES

- Internet to System: The boundary between external users/systems (Meal Planner, Administrator) and the AI Nutrition-Pro application.
- System to External Service: The boundary between the internal API Application and the external ChatGPT service.
- Application to Datastore: The boundary between compute components (Web Control Plane, API Application) and their respective databases (Control Plane Database, API Database).
- Internal Component Boundary: The boundary between the API Gateway and the backend services it protects (e.g., API Application).

## DATA FLOWS

- DF1: Meal Planner -> API Gateway (Uses for AI content generation). Crosses the "Internet to System" trust boundary.
- DF2: API Gateway -> API Application (Proxied request). Crosses the "Internal Component Boundary".
- DF3: Administrator -> Web Control Plane (Configure system properties). Crosses the "Internet to System" trust boundary.
- DF4: API Application -> ChatGPT-3.5 (LLM content creation). Crosses the "System to External Service" trust boundary.
- DF5: Web Control Plane -> Control Plane Database (Read/write tenant and config data). Crosses the "Application to Datastore" trust boundary.
- DF6: API Application -> API Database (Read/write content samples and LLM I/O). Crosses the "Application to Datastore" trust boundary.

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | API Gateway | Attacker spoofs a legitimate Meal Planner application using a stolen API key. | Spoofing | API keys are the primary authentication method for external clients. If an API key is stolen, an attacker can impersonate a client, consume their quota, and access their data. | The system uses individual API keys for authentication. | Implement secure API key storage and transmission guidance for clients. Implement monitoring for anomalous usage patterns (e.g., requests from unusual IP ranges, sudden spike in volume) and provide a mechanism for clients to revoke and rotate their keys. | Medium | The likelihood depends on the security practices of the third-party Meal Planner applications. A key leak from a client is a realistic scenario. | High | The attacker gains full access as the impersonated client, can incur costs, and access/tamper with their data. | High |
| 0002 | API Application | Attacker performs a Prompt Injection attack by crafting malicious input via a Meal Planner application. | Tampering | The application's core function is to process user-provided content (samples) and use it in prompts to an LLM. This makes it a prime target for prompt injection to manipulate the LLM's output. | The API Gateway is mentioned to perform "filtering of input", but the specifics are unknown. It is likely not sufficient for sophisticated prompt injection. | Implement a defense-in-depth approach for prompt injection. 1. At the API Application, use input validation and sanitization libraries specifically designed to detect and neutralize prompt injection payloads. 2. Structure prompts to the LLM to clearly separate instructions from user-provided data. 3. Instruct the LLM in its system prompt to disregard any instructions found within the user data portion of the prompt. | High | This is one of the most common and effective attacks against LLM-based applications. Attackers will actively try to exploit this. | High | The attacker could make the LLM reveal its system prompt, exfiltrate data from other users if context is shared, or generate malicious/inappropriate content returned to the client. | High |
| 0003 | API Application | An attacker causes resource exhaustion and high costs by sending computationally expensive prompts to the LLM. | Denial of Service | LLM requests can vary significantly in cost and processing time. An attacker could repeatedly send complex requests to incur high costs for the service operator and degrade performance for other users. | The API Gateway provides rate limiting. | Enhance the rate limiting at the API Gateway with more sophisticated, cost-based throttling. The API Application should implement logic to estimate the potential complexity/cost of a prompt before sending it to the LLM and reject overly complex requests. Set hard spending limits and alerts on the OpenAI account. | Medium | While basic rate limiting exists, a determined attacker with a valid API key could still inflict financial damage before being cut off. | Medium | The immediate impact is financial loss due to high LLM API costs. A secondary impact is service degradation or unavailability for other tenants. | Medium |
| 0004 | Web Control Plane | An attacker with Administrator credentials tampers with system configuration, affecting all tenants. | Tampering | The Administrator has high privileges to manage the system. A compromised admin account could be used to disable security features, change billing data, or disrupt service for all clients. | The system has a dedicated Web Control Plane for administrators. | Implement multi-factor authentication (MFA) for the Administrator role. All configuration changes must generate a detailed audit log entry, specifying who made what change and when. Implement change control procedures requiring review for critical modifications. | Low | Assuming a limited number of administrators and professional users, the likelihood of an external compromise is low, but the insider threat or a targeted attack remains possible. | Critical | The impact is system-wide. The attacker could cause a complete service outage, data loss, or a massive security breach affecting all tenants. | High |
| 0005 | API Database | Unauthorized access to the API database leads to exfiltration of all dietitian content and LLM interaction logs. | Information Disclosure | The database centralizes potentially sensitive and proprietary data from all tenants. A single breach point could expose all this data. | The application connects to the database over TLS. | Enforce strict, least-privilege IAM roles for database access from the API Application. Encrypt the database at rest using AWS KMS. Implement robust application-level checks to ensure one tenant cannot access another's data, even if a SQL injection or similar flaw is found. | Low | A direct attack on the database is unlikely given the AWS RDS environment, but an application-level vulnerability (e.g., SQL injection) could provide an attacker with access. | Critical | This would be a catastrophic data breach, exposing the intellectual property of all clients and potentially sensitive data contained within the prompts and responses. | High |
| 0006 | API Application | Data from one tenant's prompts or stored samples leaks into the generated content for another tenant. | Information Disclosure | If the application does not strictly isolate the data and context for each tenant when interacting with the LLM, the model might inadvertently use information from one tenant's request when generating a response for another. | No specific mitigations are mentioned in the architecture. | Ensure the API Application is stateless regarding tenant data between requests. Each request to the ChatGPT API must be self-contained and must only include data from the requesting tenant. Implement strict data access controls in the application logic to prevent cross-tenant data access. | Medium | This is a common pitfall in multi-tenant application design. A subtle bug in session management or data handling could easily lead to this issue. | High | This would be a severe breach of trust and data confidentiality, potentially leaking proprietary business information between competing clients. | High |

# DEPLOYMENT THREAT MODEL

The project is deployed using AWS Elastic Container Service (ECS) for the Golang applications and Amazon RDS for the databases, as described in the architecture document. This will be the focus of the deployment threat model.

## ASSETS

- AWS Credentials: IAM roles and policies that grant permissions to ECS tasks and other services.
- Container Images: The final Docker images for the Web Control Plane and API Application, stored in a registry like Amazon ECR.
- Application Secrets: Database credentials, API keys for ChatGPT, and other secrets required by the applications at runtime.
- Network Configuration: VPC settings, subnets, security groups, and network ACLs that control traffic flow.
- Infrastructure as Code (IaC) templates: If used, these templates (e.g., CloudFormation, Terraform) define the entire cloud environment and are a high-value target.

## TRUST BOUNDARIES

- AWS Account Boundary: The boundary between the organization's AWS account and all other accounts/the public internet.
- VPC Boundary: The perimeter of the Virtual Private Cloud where the application resources reside.
- Container Boundary: The isolation boundary between a running container and the underlying host or other containers.
- Registry to Runtime: The boundary between the container image registry (ECR) and the ECS runtime environment that pulls and runs the images.

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0007 | ECS Task | Overly permissive IAM role attached to an ECS task allows a compromised container to access unintended AWS resources. | Elevation of Privilege | If an attacker achieves remote code execution in the API Application container, they can inherit the permissions of the attached IAM role. A permissive role could allow them to access the Control Plane DB, S3 buckets, or other resources. | No specific mitigations are mentioned in the architecture. | Follow the principle of least privilege. Create a specific, fine-grained IAM role for each ECS service (API Application, Web Control Plane) that grants only the permissions absolutely necessary for its function (e.g., only access to its specific database and secrets). | Medium | Application vulnerabilities are common. If one is found, the impact is directly proportional to the permissions of the IAM role. | High | A compromised API Application container could be used to read/write data in the Control Plane Database, escalating a limited breach into a full system compromise. | High |
| 0008 | ECS Task / AWS Secrets Manager | Application secrets (e.g., ChatGPT API key, DB password) are exposed in environment variables. | Information Disclosure | Storing secrets in environment variables is a common but insecure practice. An attacker with RCE in the container can easily read all environment variables. They can also be leaked via logs or debugging endpoints. | No specific mitigations are mentioned in the architecture. | Do not store secrets in environment variables or container images. Use a dedicated secrets management service like AWS Secrets Manager or Parameter Store. The ECS task IAM role should be granted permission to fetch the specific secrets it needs at runtime. | High | This is a very common misconfiguration. Without an explicit decision to use a secrets manager, developers often default to environment variables. | High | Exposure of secrets like the database password or ChatGPT API key could lead to a complete data breach or financial abuse. | High |
| 0009 | VPC Security Group | Insecure security group configuration allows the API Application container to initiate traffic to the Control Plane Database. | Elevation of Privilege | The API Application and Control Plane are logically separate. If a security group allows traffic between them, a compromise of the public-facing API Application could be pivoted to attack the internal control plane. | No specific mitigations are mentioned in the architecture. | Configure security groups to enforce network segmentation. The API Application's security group should only allow outbound traffic to the API Database security group on the correct port, and to the internet (for ChatGPT). It should NOT be able to connect to the Control Plane Database. | Medium | Network segmentation is often overlooked. A default "allow all" within the VPC is a common insecure starting point. | High | This would allow an attacker to move laterally within the network, turning a breach of one component into a breach of the entire system. | High |
| 0010 | Amazon RDS | Control Plane or API Database is accidentally exposed to the public internet. | Information Disclosure | A misconfiguration in the RDS settings (e.g., setting `Publicly Accessible` to true) could expose the database login port to the internet, making it a target for brute-force and credential stuffing attacks. | No specific mitigations are mentioned in the architecture. | Ensure that both RDS instances are configured with `Publicly Accessible: No`. They should be located in private subnets within the VPC, with no direct route to an Internet Gateway. Access should only be possible from specific security groups within the VPC. | Low | While a critical mistake, AWS defaults and best practices make this less likely for experienced teams. However, a manual configuration error could still cause it. | Critical | A publicly exposed database is a prime target for attackers and would likely lead to a full data breach very quickly. | High |

# BUILD THREAT MODEL

This model assumes a common CI/CD process where code is stored in a Git repository (e.g., GitHub), a CI/CD service (e.g., GitHub Actions) builds a Docker image from a Dockerfile, and the resulting image is pushed to Amazon ECR.

## ASSETS

- Source Code: The Golang application code stored in the version control system.
- CI/CD Pipeline Configuration: The file defining the build, test, and deployment steps (e.g., `main.workflow`, `Jenkinsfile`).
- Third-party Dependencies: External libraries and modules (Go modules, OS packages in the base image) used by the application.
- Base Docker Image: The parent image used in the Dockerfile (e.g., `golang:1.21-alpine`).
- CI/CD Secrets: Credentials used by the pipeline to access protected resources, such as AWS credentials for pushing to ECR.

## TRUST BOUNDARIES

- Developer to SCM: The boundary between a developer's local machine and the shared source code repository.
- SCM to CI/CD System: The boundary where the CI/CD system fetches code from the repository.
- CI/CD System to Dependency Source: The boundary where the build process fetches external packages (e.g., from Go proxy, Docker Hub).
- CI/CD System to Artifact Registry: The boundary where the CI/CD system pushes the final container image to ECR.

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0011 | Build Process | A compromised third-party Go module is included in the application build (supply chain attack). | Tampering | The application relies on open-source Go modules. If an attacker compromises a popular module and publishes a malicious version, it could be automatically pulled into the build, embedding a backdoor in the final container image. | No specific mitigations are mentioned in the architecture. | Use a dependency scanning tool (e.g., `govulncheck`, Snyk, Dependabot) in the CI/CD pipeline to check for known vulnerabilities in dependencies. Use Go's checksum database via `go.sum` to ensure dependency integrity. Consider hosting a private Go proxy for vetted dependencies. | Medium | Supply chain attacks are becoming increasingly common and sophisticated. While Go's module system has some protections, it is not immune. | Critical | A malicious dependency could introduce backdoors, steal secrets at runtime, or tamper with application logic, leading to a full system compromise. | High |
| 0012 | CI/CD Pipeline | CI/CD pipeline is tricked into using a vulnerable or malicious base Docker image. | Tampering | The `FROM` instruction in a Dockerfile can pull a compromised image if a tag is hijacked (e.g., `latest`) or a typo is made (typosquatting). A vulnerable base image can also introduce exploitable flaws into the final application container. | No specific mitigations are mentioned in the architecture. | Use explicit, immutable image tags (e.g., `FROM golang:1.21.5-alpine3.18`) instead of floating tags like `latest` or `alpine`. Use a container scanning tool (e.g., Trivy, Clair) in the CI/CD pipeline to scan the final image for known OS and package vulnerabilities. | High | Using floating tags is a very common practice, and developers often forget to scan their final images for vulnerabilities inherited from the base image. | High | A vulnerable base image could provide an attacker with an easy path to getting a shell inside the container, bypassing application-level security. | High |
| 0013 | Source Code Repository | A developer accidentally commits secrets (e.g., AWS keys, API keys) to the source code repository. | Information Disclosure | Developers might hardcode a secret during testing and forget to remove it before committing. Once a secret is in the Git history, it should be considered compromised, even if it's removed later. | No specific mitigations are mentioned in the architecture. | Implement a pre-commit hook (e.g., `git-secrets`, `trufflehog`) on developer machines to scan for secrets before they can be committed. Add a similar secret scanning step to the CI/CD pipeline to act as a secondary check. Regularly scan the entire repository history for any past exposures. | High | This is one of the most common ways that credentials are leaked. It's a very easy mistake for a developer to make. | Critical | Exposed credentials can provide an attacker with direct access to cloud resources, databases, or third-party services, leading to a complete compromise. | High |
| 0014 | CI/CD Pipeline | A misconfiguration in the CI/CD pipeline (e.g., in a GitHub Action) allows an attacker to exfiltrate secrets or inject malicious code. | Tampering | CI/CD pipelines are complex and often have access to powerful secrets. A vulnerability in a third-party action or a misconfiguration could allow an attacker to run arbitrary code during the build and steal AWS credentials or modify the application binary. | No specific mitigations are mentioned in the architecture. | Pin third-party CI/CD actions/plugins to a specific commit hash, not a version tag. Regularly audit permissions granted to the CI/CD system. Limit the scope of secrets; for example, the AWS credentials used should only have permission to push to the specific ECR repository, nothing more. | Medium | As pipelines become more complex, the attack surface grows. The use of unaudited third-party components increases this risk significantly. | Critical | Compromise of the build pipeline can lead to the deployment of trojanized software, giving the attacker a persistent foothold in the production environment. | High |

# QUESTIONS & ASSUMPTIONS

## Assumptions

- The Administrator role is operated by a trusted, non-malicious user, but their credentials could be compromised.
- The underlying AWS infrastructure (physical security, hypervisor) is secure, and this model focuses on the configuration and application layers built on top of it.
- The Meal Planner applications are completely untrusted third-party clients.
- The data sent to ChatGPT is considered sensitive from a business IP perspective, but does not contain regulated data like PII or PHI unless explicitly stated otherwise.
- The described architecture is complete and there are no other hidden components or data flows.

## Questions

- Q1: How are secrets like database credentials and the ChatGPT API key managed and injected into the running containers? Are they in environment variables, or is a service like AWS Secrets Manager used?
- Q2: Is there multi-factor authentication (MFA) required for the Administrator to access the Web Control Plane?
- Q3: What specific "filtering of input" is performed by the API Gateway? Is it a simple WAF, or does it have logic to counter prompt injection?
- Q4: What is the data classification for the "dietitian's content samples"? Does it ever contain Personally Identifiable Information (PII) or Protected Health Information (PHI)?
- Q5: Is there logical or physical data separation between tenants within the API Database and Control Plane Database, or is separation handled entirely by the application logic?
- Q6: What is the process for rotating the API keys for the Meal Planner applications? Can clients do this themselves?
- Q7: Are detailed audit logs generated for all actions performed by the Administrator in the Web Control Plane?
