## Mitigation Strategies

### 1. Enhanced Prompt Sanitization and Input Validation
**Description**
1. Implement server-side checks (in the backend API) that scan incoming text from the Meal Planner application.
2. Filter out script tags, SQL injection patterns, or known malicious sequences that might manipulate the LLM prompt.
3. Use a strict schema validator (e.g., JSON schema validation) to ensure uploaded dietitian content adheres to expected formats before the API Application forwards it to ChatGPT.
4. Reject or sanitize (e.g., remove disallowed characters, escape HTML) any input that fails validation.

**List of Threats Mitigated**
- Prompt injection attacks (High severity): Attackers could craft prompts that force ChatGPT to leak sensitive info or generate harmful content.
- Malicious content injection (Medium severity): Malicious scripts or hidden commands inserted into requests.

**Impact**
- Significantly lowers the risk of LLM exploitation by prompt manipulation (from “high” to “low”).
- Reduces chance of feeding malicious data into ChatGPT (from “medium” to “low”).

**Currently Implemented**
- Basic input filtering is performed at the API Gateway.

**Missing Implementation**
- Detailed schema validation and advanced sanitization rules in the backend API layer.
- Logging of filtered data to detect repeated malicious attempts.

---

### 2. Data Minimization and Redaction Before Sending to ChatGPT
**Description**
1. Introduce a preprocessing step in the backend API to remove or mask personally identifiable information (PII) and other sensitive data from dietitian content.
2. Maintain a clear set of rules indicating which data fields are allowed to leave the system for ChatGPT processing.
3. Implement selective encryption or hashing for data fields that are not necessary for content generation.

**List of Threats Mitigated**
- Data leakage to external LLM (High severity): Prevents exposing sensitive internal or user-specific data through ChatGPT queries.

**Impact**
- Greatly reduces the chance of accidental data disclosure (from “high” to “low”).

**Currently Implemented**
- Not mentioned in existing architecture.

**Missing Implementation**
- A dedicated data scrubber/redactor module or function within the backend API.
- Configuration in the API Application specifying exactly which fields can or cannot be passed on to ChatGPT.

---

### 3. Per-Tenant Usage Throttling and Billing Cap
**Description**
1. Expand existing rate-limiting in the API Gateway to include per-tenant usage caps (e.g., monthly request limit or cost threshold).
2. Trigger automated alerts when a threshold is approached (e.g., 80% of monthly allotment).
3. Pause or reject requests once the tenant reaches the maximum usage or billing cap.

**List of Threats Mitigated**
- Excessive usage by compromised tenant credentials (Medium severity): Prevents huge unexpected bills or denial of service to other tenants.
- Resource exhaustion (Medium severity): Protects overall system performance.

**Impact**
- Substantially reduces financial risk and system overload risk (from “medium” to “low”).

**Currently Implemented**
- Basic rate limiting at the API Gateway.

**Missing Implementation**
- Per-tenant resource/billing cap configuration within the Control Plane.
- Automated alerts and enforcement logic.

---

### 4. Strict ACL and Role-Based Access in the Control Plane
**Description**
1. Define roles and permissions clearly for Administrator, App Onboarding Manager, and Meal Planner managers.
2. Use role-based policies to restrict database accesses, e.g., the Control Plane Database only accessible to authorized roles.
3. Provide an admin interface to view and manage role assignments, including auditing changes for accountability.

**List of Threats Mitigated**
- Unauthorized configuration changes (High severity): Prevent a compromised administrative account from altering global settings.
- Data tampering (Medium severity): Ensures only designated roles can modify critical billing or tenant data.

**Impact**
- Significantly lowers the risk of insider or compromised account misuse (from “high” to “low”).

**Currently Implemented**
- Basic ACL at the API Gateway for external clients.

**Missing Implementation**
- Fine-grained, role-based permissions in the Control Plane web application.
- Auditable logs of role changes in the Control Plane Database.

---

### 5. Granular Logging and Anomaly Detection for LLM Usage
**Description**
1. For each request to the ChatGPT API, log the anonymized prompt details (or unique identifiers if data is redacted).
2. Maintain usage metrics per tenant (e.g., volume of calls, average content length) in the Control Plane Database.
3. Implement automated anomaly detection rules—if usage spikes or out-of-pattern behavior is detected, alert administrators or temporarily suspend the tenant’s API key.

**List of Threats Mitigated**
- Compromised API key abuse (High severity): Detects suspicious usage patterns early.
- Fraudulent usage to generate malicious content (Medium severity).

**Impact**
- Substantially improves detection and response time to compromised credentials or malicious scripts (from “high” to “low”).

**Currently Implemented**
- Basic logs at the API Gateway level, but not detailed LLM request logs.

**Missing Implementation**
- Detailed per-request ChatGPT logging and centralized anomaly detection engine.
- Custom metrics dashboards integrating real-time alerts for usage anomalies.

---

### 6. Controlled Data Retention for AI Content
**Description**
1. Define a retention policy (e.g., 90 days) for storing content samples, LLM requests, and responses in the API database.
2. Automatically purge or archive older records to avoid storing unnecessary or sensitive data.
3. Provide an audit trail indicating how and when content was purged.

**List of Threats Mitigated**
- Long-term data exposure (Medium severity): Limits potential data breaches to recent content.
- Privacy regulations non-compliance (Medium severity): Reduces risk of holding data longer than necessary.

**Impact**
- Moderately reduces the scope of data an attacker might access (from “medium” to “low”).

**Currently Implemented**
- Not stated in existing documentation.

**Missing Implementation**
- Automated pruning scripts or scheduled jobs in the API Application.
- Policy definitions for required retention periods in project documentation.

---

### 7. Secure Configuration Management for API Gateway and Backend Services
**Description**
1. Store Kong API Gateway configuration (routing rules, ACLs, rate-limit settings) under version control.
2. Implement a CI/CD process that tests configuration changes for security regressions (e.g., removing or weakening ACL inadvertently).
3. Maintain environment-specific configuration for staging/production, with strict approvals before deployment.

**List of Threats Mitigated**
- Risk of misconfiguration in the Gateway (High severity): Could allow unauthorized endpoints or remove security filters by accident.
- Unauthorized changes to routing rules (Medium severity): Could redirect traffic to rogue endpoints or bypass filters.

**Impact**
- High reduction in accidental or malicious config changes (from “high” to “low”).

**Currently Implemented**
- Basic Kong settings manually applied.

**Missing Implementation**
- Version-controlled configuration with automated checks.
- Strict governance (approval workflows) for changes to API Gateway and backend service configuration.
