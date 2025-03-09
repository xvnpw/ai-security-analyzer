# APPLICATION THREAT MODEL

## ASSETS

- **API Gateway**: Manages authentication, rate limiting, and input filtering.
- **Web Control Plane**: Manages client onboarding, configuration, and billing data.
- **Control Plane Database**: Stores data for Web Control Plane.
- **API Application**: Provides AI Nutrition-Pro functionality via APIs.
- **API Database**: Stores dietitian's content samples and requests/responses to LLM.
- **Administrator**: Manages server configuration and resolves problems.
- **Meal Planner Application**: External system that creates diets and interacts with AI Nutrition-Pro.
- **ChatGPT-3.5**: External system used for generating content based on samples.

## TRUST BOUNDARIES

- **External Systems**: Meal Planner application, ChatGPT-3.5
- **Internal Components**: API Gateway, Web Control Plane, Control Plane Database, API Application, API Database, Administrator

## DATA FLOWS

- **Meal Planner Application** <-> **API Gateway** (HTTPS/REST, TLS)
- **API Gateway** <-> **API Application** (HTTPS/REST)
- **API Application** <-> **ChatGPT-3.5** (HTTPS/REST)
- **API Application** <-> **API Database** (TLS)
- **Web Control Plane** <-> **Control Plane Database** (TLS)

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME   | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|------------------|-------------|----------------|----------------|---------------|------------|-----------------------|-------------------|--------------|
| 0001      | API Gateway       | Credentials Exposure | Spoofing       | API Gateway handles API keys and is critical for authentication and authorization. | - | Implement strict access controls, use secrets management solutions. | High, as API keys are critical for access. | High, exposure can lead to unauthorized access. | High |
| 0002      | Web Control Plane | Data Tampering | Tampering       | Manages configuration and billing data, which is sensitive. | - | Use secure communication channels, implement data integrity checks. | Medium, configuration data can be tampered with. | High, tampering can result in financial loss and unauthorized access. | High |
| 0003      | Control Plane Database | Data Leakage | Information Disclosure | Stores sensitive data like billing information and client configurations. | - | Implement encryption at rest and in transit, use IAM roles for access. | Medium, sensitive data can be exposed. | High, exposure of billing and configuration data can lead to financial loss. | High |
| 0004      | API Database      | Data Tampering | Tampering       | Stores dietitian content samples, requests, and responses. | - | Implement data validation, use secure communication channels. | Medium, content samples can be tampered with. | Medium, tampering can result in inaccurate content. | Medium |
| 0005      | API Application   | Spoofed Requests | Spoofing       | API Application interacts with external LLMs. | - | Implement strict input validation, use rate limiting and IP whitelisting. | Medium, spoofed requests can overwhelm the system. | High, can lead to unauthorized content generation. | High |
| 0006      | API Application   | Data Disclosure | Information Disclosure | Handles sensitive data from external systems. | - | Implement encryption, secure storage for sensitive data, and use secure communication channels. | Low, data can be leaked during transmission. | High, data leakage can impact privacy and trust. | Medium |

# DEPLOYMENT THREAT MODEL

## ASSETS

- **API Gateway**: Manages authentication, rate limiting, and input filtering.
- **Web Control Plane**: Manages client onboarding, configuration, and billing data.
- **Control Plane Database**: Stores data for Web Control Plane.
- **API Application**: Provides AI Nutrition-Pro functionality via APIs.
- **API Database**: Stores dietitian's content samples and requests/responses to LLM.

## TRUST BOUNDARIES

- **External Systems**: Meal Planner application, ChatGPT-3.5
- **Internal Components**: API Gateway, Web Control Plane, Control Plane Database, API Application, API Database, Administrator

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME   | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|------------------|-------------|----------------|---------------|------------|-----------------------|-------------------|--------------|
| 0001      | API Gateway      | API Key Exposure | API keys are critical for access control. | - | Implement key rotation, use secure storage solutions. | Medium, if exposed, can lead to unauthorized access. | High, unauthorized access can result in data breaches. | High |
| 0002      | Web Control Plane | Unauthorized Access | Manages sensitive data such as client configurations and billing. | - | Implement strong authentication and authorization mechanisms. | Medium, unauthorized access can lead to data leakage. | High, can result in financial loss and data breaches. | High |
| 0003      | Control Plane Database | Data Leakage | Stores sensitive data. | - | Implement encryption at rest and in transit, use IAM roles for access. | Medium, sensitive data can be exposed. | High, exposure can lead to financial loss and data breaches. | High |
| 0004      | API Application  | Data Tampering | API Application handles sensitive data and interacts with external LLMs. | - | Implement data validation, use secure communication channels. | Medium, tampering can result in inaccurate content generation. | Medium, can impact the quality of content and user trust. | Medium |
| 0005      | API Database     | Data Leakage | Stores dietitian content samples and requests/responses. | - | Implement encryption at rest and in transit, use secure storage solutions. | Medium, data can be leaked. | High, exposure can lead to privacy concerns and loss of trust. | High |

# BUILD THREAT MODEL

## ASSETS

- **Pipeline**: CI/CD pipeline used for building and deploying the application.
- **Builder**: Component responsible for building container images.
- **Runner**: Executes build and test jobs.
- **Host**: Hosts the build and deployment processes.

## TRUST BOUNDARIES

- **External Systems**: External repositories, external build systems
- **Internal Components**: Pipeline, Builder, Runner, Host

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|-----------------------|-------------------|--------------|
| 0001      | Pipeline        | Supply Chain Attack | CI/CD pipeline can be compromised, leading to insecure builds. | - | Implement secure source code repositories, use signed images, and validate dependencies. | Medium, compromise can result in insecure builds. | High, can lead to compromised builds and deployment. | High |
| 0002      | Builder         | Compromised Build Artifacts | Can produce insecure or malicious artifacts. | - | Use secure build environments, implement build signing and validation. | Medium, can result in compromised builds. | High, can impact the integrity of the entire application. | High |
| 0003      | Runner          | Malicious Job Execution | Can execute malicious jobs that compromise the build process. | - | Use secure and isolated environments, implement job validation and sandboxing. | Medium, can result in compromised build process. | High, can compromise the integrity of the build and deployment process. | High |
| 0004      | Host            | Host Compromise | Can be compromised, leading to insecure builds and deployments. | - | Implement secure host configurations, use host-level security measures, and monitor for anomalies. | Medium, can result in compromised builds and deployments. | High, can impact the integrity of the entire application. | High |

# QUESTIONS & ASSUMPTIONS

- **Questions**:
  - Are there any existing security measures in place for the CI/CD pipeline?
  - Are there any existing measures for securing the database backups?
  - How are API keys and secrets managed in the build process?

- **Assumptions**:
  - The current architecture does not have detailed security controls for the build and deployment process.
  - The system assumes that all internal components are trusted.
  - The environment uses TLS and HTTPS for encrypted communication, but there are no specific details on how credentials and sensitive data are managed.
