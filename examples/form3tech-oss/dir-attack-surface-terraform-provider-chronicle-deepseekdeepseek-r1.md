### Updated Attack Surface Analysis for Terraform Provider for Chronicle

#### 1. Sensitive Credential Exposure in Terraform State
- **Description**: Credentials (AWS secrets, client secrets, API tokens) are stored in Terraform state files. If state is unencrypted or improperly shared, attackers could extract these credentials.
- **Contribution to Attack Surface**: Direct exposure of cloud/service credentials leading to unauthorized access.
- **Example**: Newly added feeds (AWS S3/SQS, Azure Blobstore, Office 365) store AWS access keys, shared keys, and client secrets in state files.
- **Impact**: Full compromise of integrated services (AWS, Azure, Okta, etc.).
- **Severity**: Critical
- **Current Mitigations**: Sensitive fields marked as `Sensitive: true` in schema. Relies on users securing state files.
- **Missing Mitigations**: Provider cannot enforce state encryption. Users must encrypt state via remote backend with encryption.

#### 2. Insecure Custom Endpoints Without Validation
- **Description**: Hostnames and endpoints (e.g., Okta `hostname`, Qualys VM hostname) may point to malicious or HTTP-only endpoints if improperly configured.
- **Contribution to Attack Surface**: MITM attacks or data exfiltration via endpoint hijacking.
- **Example**: Attacker modifies `hostname` to `http://malicious-qualys.com` in Qualys VM feed configuration.
- **Impact**: Sensitive vulnerability data sent to attacker-controlled systems.
- **Severity**: High
- **Current Mitigations**: Thinkst Canary enforces `.canary.tools` domain suffix. No HTTPS validation for Office 365, Okta, or Qualys feeds.
- **Missing Mitigations**: Enforce HTTPS for all API endpoints. Add domain validation for Okta (`*.okta.com`) and Qualys (`qualysapi.qualys.com`).

#### 3. RBAC Role Assignment Without Validation
- **Description**: `chronicle_rbac_subject` allows assigning arbitrary role strings like `"Editor"`, which may not exist or be overly permissive.
- **Contribution to Attack Surface**: Privilege escalation via incorrect role assignments.
- **Example**: Assigning a deprecated role `"Auditor"` might grant unintended permissions.
- **Impact**: Unauthorized access to Chronicle detection rules or reference lists.
- **Severity**: High
- **Current Mitigations**: Documentation lists valid roles, but provider doesn’t validate them during resource creation.
- **Missing Mitigations**: Validate roles against Chronicle’s API during Terraform plan/apply.

#### 4. Environment Variable Credential Precedence Risks
- **Description**: Environment variables (e.g., `CHRONICLE_BACKSTORY_CREDENTIALS`) override Terraform configs, risking credential misuse in automation pipelines.
- **Contribution to Attack Surface**: Accidental use of credentials from shared environments (CI/CD).
- **Example**: Terraform config for Office 365 feed uses `client_secret`, but CI environment variable overrides it with dev credentials.
- **Impact**: Production logs ingested into dev environment or vice versa.
- **Severity**: Medium
- **Current Mitigations**: `ConflictsWith` checks in schema prevent simultaneous use of config and env vars.
- **Missing Mitigations**: Explicit warnings in `terraform plan` when env vars are detected.

---

### Analysis of New Project Files
The newly added feed configurations **reinforce existing risks** but do not introduce new critical/high attack surfaces:
1. **Credential Patterns**: All new feeds (AWS SQS, Azure Blobstore, etc.) follow the same sensitive field handling, maintaining consistent state file exposure risks.
2. **Endpoint Diversity**: Multiple new API endpoints (Okta, Qualys) lack domain validation beyond Thinkst Canary, expanding the attack surface for endpoint hijacking.
3. **RBAC Consistency**: The `chronicle_rbac_subject` example continues to use unvalidated role strings, unchanged from prior implementations.

No additional medium/high/critical severity issues were identified in the new configurations.
