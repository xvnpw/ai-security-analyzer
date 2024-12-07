# APPLICATION THREAT MODEL

## ASSETS

1. **API Keys**: Sensitive keys for accessing LLM providers like OpenAI, OpenRouter, and Anthropic.
2. **Input and Output Files**: Files containing instructions and results of the Fabric Agent Action.
3. **Fabric Patterns**: Intellectual property in the form of patterns used by the Fabric Agent Action.
4. **GitHub Repository**: The source code and configuration files for the Fabric Agent Action.

## TRUST BOUNDARIES

1. **GitHub Actions Environment**: Boundary between the GitHub-hosted runner and the external environment.
2. **LLM Providers**: Boundary between the application and external LLM services (OpenAI, OpenRouter, Anthropic).
3. **User Input**: Boundary between user-provided input and the application processing it.

## DATA FLOWS

1. **User Input to GitHub Action**: User provides input files and configuration to the GitHub Action.
2. **GitHub Action to LLM Providers**: The action sends requests to LLM providers using API keys.
3. **LLM Providers to GitHub Action**: LLM providers return responses to the GitHub Action.
4. **GitHub Action to Output Files**: The action writes results to specified output files.

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | STRIDE CATEGORY | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|-----------------|----------------|---------------|------------|------------------------|-------------------|---------------|
| 0001 | GitHub Action | Unauthorized Access to API Keys | Information Disclosure | API keys are stored in GitHub secrets and used in workflows. | API keys are stored in GitHub secrets, which are not exposed in logs. | Use environment variables and limit access to secrets. Rotate keys regularly. | Medium likelihood due to potential misconfiguration. | High impact if keys are leaked, leading to unauthorized API usage. | High |
| 0002 | GitHub Action | Malicious Input Execution | Tampering | User input is processed by the action, which could be manipulated. | Input validation is not explicitly mentioned. | Implement strict input validation and sanitization. | Medium likelihood due to potential lack of input validation. | High impact if malicious input leads to unauthorized actions. | High |
| 0003 | LLM Providers | API Abuse | Denial of Service | Unlimited API calls could lead to service abuse. | API usage is controlled by API keys. | Implement rate limiting and monitoring of API usage. | Low likelihood with proper API key management. | Medium impact due to potential service disruption. | Medium |
| 0004 | Output Files | Data Leakage | Information Disclosure | Output files may contain sensitive information. | Output files are written to specified paths. | Ensure output files are stored securely and access is restricted. | Medium likelihood if file permissions are misconfigured. | Medium impact if sensitive data is exposed. | Medium |

# DEPLOYMENT THREAT MODEL

## ASSETS

1. **Docker Image**: The containerized version of the Fabric Agent Action.
2. **GitHub Runner**: The environment where the action is executed.
3. **Network Configuration**: Network settings for accessing LLM providers.

## TRUST BOUNDARIES

1. **Docker Container**: Boundary between the containerized application and the host system.
2. **Network Perimeter**: Boundary between the GitHub runner and external networks.

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------------------|-------------------|---------------|
| 0001 | Docker Image | Image Tampering | Docker images can be modified if not properly secured. | Images are built and pushed to a registry. | Use signed images and verify integrity before deployment. | Medium likelihood if registry security is weak. | High impact if a tampered image is deployed. | High |
| 0002 | GitHub Runner | Unauthorized Access | Unauthorized access to the runner could lead to data exposure. | Access is controlled by GitHub permissions. | Implement strict access controls and audit logs. | Low likelihood with proper access controls. | High impact if unauthorized access occurs. | Medium |
| 0003 | Network Configuration | Man-in-the-Middle Attack | Network traffic to LLM providers could be intercepted. | Use HTTPS for secure communication. | Implement network monitoring and intrusion detection. | Low likelihood with HTTPS. | High impact if sensitive data is intercepted. | Medium |

# BUILD THREAT MODEL

## ASSETS

1. **Build Scripts**: Scripts used to automate the build process.
2. **CI/CD Pipeline**: The continuous integration and deployment pipeline.

## TRUST BOUNDARIES

1. **CI/CD Environment**: Boundary between the CI/CD system and the source code repository.

## BUILD THREATS

| THREAT ID | COMPONENT NAME | THREAT NAME | WHY APPLICABLE | HOW MITIGATED | MITIGATION | LIKELIHOOD EXPLANATION | IMPACT EXPLANATION | RISK SEVERITY |
|-----------|----------------|-------------|----------------|---------------|------------|------------------------|-------------------|---------------|
| 0001 | Build Scripts | Script Injection | Build scripts could be modified to include malicious code. | Scripts are stored in the repository. | Implement code reviews and use version control. | Medium likelihood if access controls are weak. | High impact if malicious code is executed. | High |
| 0002 | CI/CD Pipeline | Supply Chain Attack | Dependencies could be compromised during the build process. | Dependencies are managed by Poetry. | Use dependency scanning tools and lock file verification. | Medium likelihood due to third-party dependencies. | High impact if a compromised dependency is used. | High |

# QUESTIONS & ASSUMPTIONS

1. **Questions**:
   - Are there any additional security measures in place for handling API keys?
   - How is input validation currently implemented in the application?
   - Are there any monitoring tools in place for API usage and network traffic?

2. **Assumptions**:
   - API keys are stored securely in GitHub secrets.
   - The application relies on HTTPS for secure communication with LLM providers.
   - The CI/CD pipeline is configured to use secure practices for dependency management.
