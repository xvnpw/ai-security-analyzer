# Mitigation Strategies

## Strategy 1: Input Validation and Sanitization

- **Description**:
  - Enhance current validation and sanitization procedures within the API Gateway and API application by validating and sanitizing all received input from external Meal Planner applications.
  - Implement strict schema validation for the inputs, setting explicit allowable formats and fields.
  - Reject any input that does not strictly conform to the defined schema to avoid unexpected input handling downstream.
  - Include validation logic at two levels:
    1. API Gateway (basic structural validation and input sanitization)
    2. API Application (domain-specific validation logic, preventing unwanted commands or injection attempts toward LLM integration)

- **Threats Mitigated**:
  - Input injection and prompt injection attacks via external Meal Planner systems (Severity: High)
  - Malicious payload uploads which could harm or compromise the backend system or database integrity (Severity: Medium)

- **Impact**:
  - Significantly reduces the risk of prompt injection or input-based attacks toward AI components and backend services, ensuring backend and AI integrations are protected from attack vectors leveraging input manipulation.

- **Currently Implemented**:
  - Currently implemented partially and generically as "filtering of input" at the API Gateway level (Kong).

- **Missing Implementation**:
  - API Application itself does not explicitly mention input validation and sanitization of requests passed to ChatGPT or stored in database. Additional detailed validation measures must be implemented within the API Application logic layer.

## Strategy 2: Secure Handling and Validation of LLM Integration (ChatGPT-3.5)

- **Description**:
  - The backend API Application should strictly control and sanitize data sent in requests to the external ChatGPT-3.5 LLM system.
  - Apply validation on data responses received from ChatGPT API to avoid indirectly propagating AI-generated malicious or harmful content downstream.
  - Establish clear policies regarding acceptable AI-generated content as outputs and automate content moderation mechanisms to detect potentially harmful responses from the LLM before returning to the end-user.

- **Threats Mitigated**:
  - Risk of AI-generated harmful, inappropriate, biased or malicious outputs to end-users (Severity: High)
  - Risk of propagating injected or malicious commands as a result of LLM processing (Severity: Medium)

- **Impact**:
  - Reduces significantly the real-world risk associated with AI content moderation and ensures toxic or dangerous AI-generated outcomes are mitigated proactively.

- **Currently Implemented**:
  - Not currently explicitly implemented.

- **Missing Implementation**:
  - Missing entirely in the backend API application logic, no explicit mention of LLM-integration input sanitization or output validation from external ChatGPT API calls.

## Strategy 3: Principle of Least Privilege and Access Control Integration for Databases

- **Description**:
  - Ensure fine-grained, restricted, and limited permissions for backend applications accessing the "API database" and "Control Plane Database".
  - Clearly separate permissions and roles, granting only necessary read/write permission per container, application or API based on the strictest minimal requirement.

- **Threats Mitigated**:
  - Unrestricted database access or unauthorized access to sensitive client-related and billing data through compromised application instances or containers. (Severity: High)
  - Data tampering, unauthorized modification or malicious data queries (Severity: Medium)

- **Impact**:
  - Strongly minimizes potential damage and collateral/security impact in the event an internal system or container becomes compromised, by restricting attacker capability and limiting their lateral movement potential.

- **Currently Implemented**:
  - No explicit mention of current granular database permissions or defined roles.

- **Missing Implementation**:
  - Entire mitigation missing. Should be explicitly documented, verified, and implemented in the database access specifications and AWS RDS IAM policies.

## Strategy 4: Enhanced Rate Limiting and Throttling Rules on API Gateway

- **Description**:
  - Strengthen current rate limiting rules at the API Gateway to detect and mitigate abuse or Denial-of-Service (DoS) attempts targeted at the API endpoints.
  - Set rate-limiting policies that bound acceptable usage according to normal application patterns, to prevent intentional or accidental excessive API usage.

- **Threats Mitigated**:
  - Abuse of API Gateway or backend API endpoints causing degradation or denial of service affecting other valid applications (Severity: Medium).

- **Impact**:
  - Explicitly reduces the chance of availability or performance degradation by ensuring abnormal applications or malicious actors cannot impact system stability through excessive usage.

- **Currently Implemented**:
  - Kong API Gateway currently implements a basic rate-limiting policy but the exact policies and rules are not defined clearly.

- **Missing Implementation**:
  - Clearly documented policies, thresholds and configurable limits should be established and explicitly declared to tighten and enhance current generic implementation.

## Strategy 5: Secure Storage of Sensitive Information (API Keys, credentials)

- **Description**:
  - Store sensitive information such as API keys, ChatGPT API access credentials, and secrets in secure methods (AWS Secrets Manager, Parameter Store, or encrypted secure storage services).
  - Access sensitive data via IAM roles and policies, utilizing AWS native features to prevent leakage or unauthorized access.

- **Threats Mitigated**:
  - Credential exposure, API Key leakage and unauthorized access (Severity: High)

- **Impact**:
  - Greatly reduces the risk of unauthorized access to application and external systems, predominantly ChatGPT LLM and backend systems, in the case of security incidents or breaches.

- **Currently Implemented**:
  - Currently not documented or explicitly implemented.

- **Missing Implementation**:
  - Must verify that all secret credentials management is secure and uses AWS native or equivalent secure credential management systems.

## Strategy 6: API Authentication and Authorization (API Gateway ACL)

- **Description**:
  - Continue ensuring explicit ACL rules and API Key–based authentication to validate external Meal Planner requests' authenticity and authorization clearly.
  - Periodic review of ACL and API keys validity, ensuring rotation policies to reduce risk of compromised client credentials.

- **Threats Mitigated**:
  - Unauthorized API access, unauthorized client systems or applications using AI Nutrition-Pro functionality (Severity: High)

- **Impact**:
  - Strongly minimizes unauthorized access or use of system through valid, regularly rotated credentials reducing impact in cases of credential leakage.

- **Currently Implemented**:
  - Auth/authz are partially implemented at the API Gateway with API keys and current ACL rules, explicitly documented in architecture.

- **Missing Implementation**:
  - Clear rotation and lifecycle policies of API keys and ACL rules are currently not in place or documented.

## Strategy 7: Encryption of Data at Rest (Amazon RDS Storage)

- **Description**:
  - Ensure encryption at rest is enabled for database data storage services (Amazon RDS) used for Control Plane Database and API Database.

- **Threat Mitigated**:
  - Unauthorized data access or exfiltration in the event of a compromise of physical data layers or accidental AWS misconfiguration (Severity: Medium)

- **Impact**:
  - Significantly mitigates the risk associated with accidental exposure or unauthorized data access through AWS-level breaches or physical storage layer exploits.

- **Currently Implemented**:
  - Not explicitly implemented or assured in the defined architecture documentation.

- **Missing Implementation**:
  - Database encryption-at-rest configuration must be explicitly validated and documented.

---

The provided mitigation strategies detail specific actions tailored explicitly to the identified architectural threats to the AI Nutrition-Pro Application while avoiding overly generic or irrelevant solutions.
