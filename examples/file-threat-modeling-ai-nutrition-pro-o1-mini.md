## APPLICATION THREAT MODEL

### ASSETS

| Asset Name | Description |
| --- | --- |
| API Gateway | Manages authentication, input filtering, and rate limiting for client requests. |
| Web Control Plane | Provides control and management functionalities for onboarding clients and managing configurations and billing data. |
| Control Plane Database | Stores all data related to control plane operations, tenants, and billing information. |
| API Application | Offers AI Nutrition-Pro functionalities via API, interacting with ChatGPT for content generation. |
| API Database | Stores dietitians' content samples, as well as requests and responses to the LLM. |
| Administrator Credentials | Credentials used by the Administrator to manage the AI Nutrition-Pro application. |
| API Keys for Meal Planner Applications | Individual API keys used by Meal Planner applications to authenticate with AI Nutrition-Pro. |
| Network Traffic Data | Encrypted data transmitted between Meal Planner applications and the API Gateway. |

### TRUST BOUNDARIES

| Trust Boundary Description |
| --- |
| Between Meal Planner applications and API Gateway (external vs. internal). |
| Between API Gateway and Backend API (internal services). |
| Between Administrator and Web Control Plane (internal user vs. internal system). |
| Between Backend API and ChatGPT (internal system vs. external LLM service). |
| Between Web Control Plane and Control Plane Database (internal services with secure connections). |
| Between Backend API and API Database (internal services with secure connections). |

### DATA FLOWS

| Source | Destination | Description | Crosses Trust Boundary |
| --- | --- | --- | --- |
| Meal Planner application | API Gateway | Uses REST over HTTPS for AI content generation | Yes |
| API Gateway | API Application | Uses REST over HTTPS for AI content generation | No |
| Administrator | Web Control Plane | Configures system properties | No |
| API Application | ChatGPT | Utilizes ChatGPT for LLM-featured content creation via REST over HTTPS | Yes |
| Web Control Plane | Control Plane Database | Read/write data using TLS | No |
| API Application | API Database | Read/write data using TLS | No |

### APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | API Gateway | Spoofing of API Gateway to bypass authentication | Spoofing | API Gateway handles authentication and is a critical entry point. | API Gateway uses individual API keys and TLS encryption. | Implement mutual TLS and strong API key management practices. | Medium: API gateways are common targets. | High: Bypassing authentication can lead to unauthorized access. | High |
| 0002 | Web Control Plane | Unauthorized access through compromised administrator credentials | Spoofing | Administrators have elevated privileges. | Authentication mechanisms in place, but dependent on credential security. | Enforce strong password policies, multi-factor authentication, and regular credential audits. | High: Credential compromise is a prevalent issue. | Critical: Full control over the system could be achieved. | Critical |
| 0003 | API Application | Tampering with API requests to manipulate AI content generation | Tampering | API Application processes and forwards requests to ChatGPT. | Input filtering and validation are in place at API Gateway. | Implement additional input validation and integrity checks within API Application. | Medium: Input tampering attempts are common. | High: Manipulated content can degrade service integrity. | High |
| 0004 | Control Plane Database | Unauthorized modification of billing data | Tampering | Control Plane Database stores sensitive billing information. | Access is restricted through Web Control Plane with TLS. | Implement database access controls, auditing, and integrity verification mechanisms. | Low: Access is tightly controlled. | High: Manipulation can lead to financial discrepancies and loss of trust. | High |
| 0005 | API Database | Exfiltration of dietitians' content samples | Information Disclosure | API Database contains sensitive dietitian content and LLM interactions. | Data is stored in Amazon RDS with TLS in transit. | Encrypt data at rest, implement strict access controls, and monitor for unusual access patterns. | Medium: Databases are attractive targets for data exfiltration. | Critical: Leakage of proprietary content can harm business and privacy. | Critical |
| 0006 | Backend API | Denial of Service via excessive requests to ChatGPT | Denial of Service | Backend API relies on external ChatGPT service for content generation. | Rate limiting is implemented at API Gateway. | Implement backend-specific rate limiting and request throttling. | Medium: DoS attacks are common vectors. | Medium: Service degradation affects functionality but rate limiting mitigates extent. | Medium |
| 0007 | API Gateway | Elevation of privilege through ACL misconfiguration | Elevation of Privilege | ACL rules govern which actions are allowed or denied to applications. | ACL rules are defined but may have configuration errors. | Regularly audit and test ACL rules for correctness and completeness. | Low: Properly configured ACLs reduce risk. | High: Misconfigurations can allow unauthorized actions. | High |
| 0008 | API Application | Reverse engineering of API responses to infer system logic | Information Disclosure | API responses may contain information that reveals system behavior. | API responses are intended for client usage but may expose internal logic. | Minimize sensitive information in API responses and use obfuscation where appropriate. | Low: Requires sophisticated attacker capabilities. | Medium: Can aid in developing further attacks. | Medium |

## DEPLOYMENT THREAT MODEL

### ASSETS

| Asset Name | Description |
| --- | --- |
| AWS Elastic Container Service (ECS) | Hosts Docker containers for Web Control Plane and API Application. |
| Docker Containers | Encapsulate the Web Control Plane and API Application. |
| Amazon RDS Instances | Host Control Plane Database and API Database. |
| API Gateway (Kong) | Manages external API traffic with authentication, rate limiting, and input filtering. |
| Deployment Pipelines | Processes used to deploy containers and manage infrastructure. |
| Network Configuration | Includes VPC, subnets, security groups, and firewall settings. |
| TLS Certificates | Used to encrypt network traffic between components. |

### TRUST BOUNDARIES

| Trust Boundary Description |
| --- |
| Between external internet and API Gateway (untrusted vs. trusted). |
| Between AWS ECS and Amazon RDS instances (trusted AWS infrastructure). |
| Between Docker Containers and Host Infrastructure (trusted vs. container isolation). |
| Between Deployment Pipelines and AWS resources (trusted CI/CD tools vs. infrastructure). |
| Between API Gateway and Backend API within AWS infrastructure (trusted internal communication). |
| Between AWS services and external systems like ChatGPT (trusted vs. untrusted external APIs). |

### DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | AWS ECS | Compromise of container runtime leading to container escape | Tampering | Containers are used to deploy critical applications on shared infrastructure. | Containers are isolated, but shared infrastructure may have vulnerabilities. | Use minimal base images, regular patching, and container security tools. | Low: Container escapes are rare and require specific exploits. | Critical: Compromise can lead to full infrastructure takeover. | High |
| 0002 | Amazon RDS | Unauthorized access to RDS instances via exposed endpoints | Spoofing | RDS instances store sensitive data and must be protected from unauthorized access. | RDS instances are accessed over TLS with restricted security groups. | Implement strict network access controls, use IAM roles for access, and monitor access logs. | Medium: Misconfigurations can expose RDS endpoints. | Critical: Unauthorized data access can lead to data breaches. | High |
| 0003 | Deployment Pipelines | Injection of malicious code during deployment | Tampering | Deployment pipelines handle code and configurations that are deployed to production. | Security checks may be in place but depend on pipeline configuration. | Implement code signing, secure pipeline credentials, and automated vulnerability scanning. | Medium: CI/CD pipelines are frequent targets for injection attacks. | Critical: Malicious code can compromise the entire application. | Critical |
| 0004 | Network Configuration | Eavesdropping on unencrypted internal traffic | Information Disclosure | While TLS is used for external traffic, internal traffic must also be secured. | Internal traffic is encrypted using TLS between certain components. | Ensure all internal communications are encrypted and implement network segmentation. | Low: Existing encryption reduces risk, but misconfigurations can expose traffic. | High: Eavesdropping can lead to data leakage and system insights. | High |
| 0005 | Docker Containers | Image repository compromise leading to deployment of malicious containers | Tampering | Docker images are sourced from repositories and must be trusted. | Use private, trusted image repositories with access controls. | Implement image scanning, use signed images, and restrict repository access. | Low: Trusted repositories reduce risk, but attackers may still target them. | Critical: Malicious containers can introduce vulnerabilities and backdoors. | High |
| 0006 | API Gateway | Exploitation of API Gateway vulnerabilities to disrupt service | Tampering | API Gateway is a central point for managing API traffic and is exposed to the internet. | API Gateway implements rate limiting and input filtering. | Regularly update API Gateway, conduct security assessments, and monitor for anomalies. | Medium: Public-facing gateways are attractive targets for exploitation. | High: Exploitation can lead to service disruption and unauthorized access. | High |
| 0007 | TLS Certificates | Compromise of TLS certificates allowing man-in-the-middle attacks | Spoofing | TLS certificates protect the integrity and confidentiality of data in transit. | TLS is implemented for all relevant data flows. | Use certificate pinning, regularly rotate certificates, and monitor for certificate misuse. | Low: Proper certificate management reduces risk. | Critical: Compromised TLS can lead to data interception and manipulation. | Critical |

## BUILD THREAT MODEL

### ASSETS

| Asset Name | Description |
| --- | --- |
| Build Pipeline | Automated processes that build, test, and deploy the application. |
| Source Code Repository | Stores the application's source code and configuration. |
| Build Scripts | Scripts and tools used to compile and package the application. |
| CI/CD Tools (e.g., Jenkins, GitHub Workflows) | Platforms used to automate the build and deployment processes. |
| Build Environment Credentials | Credentials and secrets used within the build process. |
| Artifact Repository | Stores built artifacts before deployment. |

### TRUST BOUNDARIES

| Trust Boundary Description |
| --- |
| Between source code repository and CI/CD tools (trusted vs. automated systems). |
| Between CI/CD tools and build environments (trusted automation vs. build environments). |
| Between build environments and artifact repositories (trusted build vs. storage). |
| Between external contributors and source code repository (untrusted users vs. trusted repository). |
| Between CI/CD tools and external dependencies (trusted build tools vs. external sources). |

### BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | CI/CD Tools | Supply chain attack through compromised dependencies | Tampering | Build processes rely on external dependencies that could be compromised. | Dependency checks may be in place but not exhaustive. | Implement dependency pinning, use trusted sources, and scan dependencies for vulnerabilities. | Medium: Supply chain attacks are increasingly common. | Critical: Compromised dependencies can introduce widespread vulnerabilities. | Critical |
| 0002 | Build Pipeline | Unauthorized access to build environment credentials | Information Disclosure | Build pipelines use credentials to access repositories and deploy artifacts. | Credentials are stored securely but depend on pipeline security. | Use secret management tools, restrict access to credentials, and rotate secrets regularly. | Medium: Credential theft attempts are frequent. | Critical: Access to credentials can lead to full pipeline compromise. | Critical |
| 0003 | Source Code Repository | Injection of malicious code by unauthorized contributors | Tampering | Source code repositories accept contributions which could be malicious. | Access controls may be in place but rely on repository management. | Implement code reviews, use pull request workflows, and enforce branch protections. | Medium: Open contributions can be a vector for injection. | High: Malicious code can be introduced into the build and production. | High |
| 0004 | Build Scripts | Exploitation of build scripts to execute arbitrary code | Tampering | Build scripts are executed in automated environments and could be manipulated. | Scripts are version-controlled but require secure handling. | Use script signing, limit script permissions, and audit scripts regularly. | Low: Secure script management reduces risk. | High: Arbitrary code execution can compromise the build environment. | High |
| 0005 | CI/CD Tools | Compromise of CI/CD tool itself to alter build processes | Tampering | CI/CD tools have high-level access to build and deployment processes. | CI/CD tools are secured but are critical targets. | Harden CI/CD infrastructure, apply least privilege principles, and monitor tool integrity. | Low: Proper security measures lower the likelihood. | Critical: Compromise can lead to complete pipeline takeover. | Critical |
| 0006 | Artifact Repository | Injection of malicious artifacts into deployment pipeline | Tampering | Artifact repositories store build outputs that are deployed. | Artifact integrity may be checked but depends on repository security. | Implement artifact signing, integrity checks, and access controls. | Low: Secured repositories reduce risk. | High: Malicious artifacts can introduce vulnerabilities into production. | High |
| 0007 | External Dependencies | Use of outdated or vulnerable external libraries | Information Disclosure | External libraries may contain known vulnerabilities. | Some vulnerability scanning may be in place. | Regularly update dependencies, use automated vulnerability scanners, and subscribe to security advisories. | High: Outdated libraries are common and easily exploitable. | High: Vulnerabilities can be exploited to compromise the application. | High |

## QUESTIONS & ASSUMPTIONS

### Questions

1. **Deployment Architectures:** Are there multiple deployment environments (e.g., staging, production), and do they follow the same architecture?
2. **Access Controls:** What specific access controls and roles are defined for administrators and other internal users?
3. **Monitoring and Logging:** What monitoring and logging mechanisms are in place for detecting and responding to threats across application, deployment, and build processes?
4. **Incident Response:** Is there an incident response plan tailored to handle potential threats identified in this model?
5. **Third-Party Integrations:** Are there any additional third-party integrations beyond Meal Planner and ChatGPT that interact with AI Nutrition-Pro?
6. **Data Backup and Recovery:** What are the backup and recovery strategies for databases and critical components?
7. **Configuration Management:** How are configurations managed and secured across different environments?
8. **User Management:** How are API keys and administrator credentials managed, rotated, and revoked as necessary?
9. **Compliance Requirements:** Are there specific compliance standards (e.g., GDPR, HIPAA) that AI Nutrition-Pro must adhere to?
10. **Automated Security Testing:** Are there automated security testing tools integrated into the build and deployment pipelines?

### Assumptions

1. **Environment Security:** It is assumed that the AWS environment is securely configured following best practices.
2. **API Security:** API Gateway properly enforces authentication, rate limiting, and input filtering as described.
3. **TLS Usage:** All TLS certificates are correctly implemented and managed to ensure encrypted traffic.
4. **Access Control:** Access to databases and internal services is restricted to necessary components only.
5. **Regular Updates:** All components, including Docker images and dependencies, are regularly updated to patch known vulnerabilities.
6. **Credential Management:** Credentials for administrators and build processes are stored securely and managed according to best practices.
7. **Build Integrity:** The build pipeline is assumed to execute only trusted and verified code from the source repository.
8. **Minimal Exposure:** Components are only exposed to necessary networks and services, minimizing attack surfaces.
9. **External Dependencies Trustworthiness:** External services like ChatGPT are assumed to be trustworthy and resilient against direct threats.

## Notes

- General best practices such as audit logging, penetration testing, and training are not included as they are outside the scope specified.
- Threats that rely on highly sophisticated and rare attack vectors, while noted, are considered less likely to be exploited.
- Certain threats do not have associated controls due to their low likelihood or because existing mitigations sufficiently address them.
