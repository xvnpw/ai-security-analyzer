- **Mitigation Strategy**: Use environment variables or secure references for credentials instead of embedding them in Terraform code
  - **Description**:
    1. Avoid placing plaintext credentials in `.tf` files. Instead, set environment variables (e.g., `CHRONICLE_BACKSTORY_CREDENTIALS`) with base64-encoded keys or store credentials in a secure secrets manager.
    2. Reference these environment variables in the provider block so that Terraform reads credentials without writing them into state or logs in plaintext.
    3. Ensure any local file path that contains credentials is excluded from version control to reduce accidental leaks.
  - **Threats Mitigated**:
    - Credential exposure in source control (High severity)
    - Leaked secrets in Terraform logs or state files (High severity)
  - **Impact**:
    - Significantly reduces unauthorized access risk by preventing accidental publication of secrets in repositories or logs.
  - **Currently Implemented**:
    - The provider supports environment variables and file paths for credentials.
  - **Missing Implementation**:
    - No built-in enforcement to mask or forbid plaintext secrets. Users must proactively choose environment variables or secret managers.

---

- **Mitigation Strategy**: Restrict or disable custom endpoints to prevent misuse
  - **Description**:
    1. By default, the provider allows overriding Chronicle or feed endpoints (e.g., `ioc_custom_endpoint`). An attacker could set a malicious endpoint to perform unintended requests.
    2. Restrict usage of custom endpoints: only supply them if you fully trust the target domain and have a legitimate reason to point to a custom environment.
    3. Implement an allowlist approach at deployment time, or disable user-defined custom endpoints at the Terraform layer if not needed.
  - **Threats Mitigated**:
    - Potential SSRF or data exfiltration by pointing to rogue endpoints (Medium severity)
  - **Impact**:
    - Minimizes the risk that feed or rule queries can be hijacked or diverted.
  - **Currently Implemented**:
    - Basic validation (the provider checks for valid URI format).
  - **Missing Implementation**:
    - No domain-based restriction or deeper SSRF protection. No built-in mechanism to enforce a trusted domain list for custom endpoints.

---

- **Mitigation Strategy**: Use least-privileged / read-only credentials for ingestion
  - **Description**:
    1. Create or use dedicated IAM keys with minimal read privileges to S3, GCS, or Azure Blob Storage. For example, do not grant deletion or write if ingestion is the only requirement.
    2. For other APIs (Okta, Microsoft 365, Proofpoint, etc.), generate service accounts or tokens with only the necessary read permissions for log retrieval.
    3. Update Terraform configurations so that they reference these restricted credentials, preventing broad actions if keys are compromised.
  - **Threats Mitigated**:
    - Excessive privileges enabling attackers to modify or delete resources if credentials are stolen (High severity)
  - **Impact**:
    - Reduces lateral movement and damage scope from compromised credentials; attackers can only read logs rather than manipulate resources.
  - **Currently Implemented**:
    - The provider permits specifying any credentials but does not enforce scope.
  - **Missing Implementation**:
    - No checks to ensure minimal privileges; relies on user to assign correct policies.

---

- **Mitigation Strategy**: Carefully configure “source_delete_options” to avoid accidental or malicious data removal
  - **Description**:
    1. Many feed resources (e.g., S3, SQS, GCS, Azure) allow `source_delete_options = "SOURCE_DELETION_ON_SUCCESS"`, removing data from the source after successful ingestion.
    2. Only enable this if absolutely needed, because an attacker or mistake in Terraform code could lead to unintended data loss by toggling source deletion.
    3. Keep `SOURCE_DELETION_NEVER` or read-only settings for most scenarios to ensure data persists.
  - **Threats Mitigated**:
    - Data destruction or sabotage if feeds auto-delete source files (Medium severity)
  - **Impact**:
    - Prevents irreversible data loss from feed misconfiguration or malicious feed updates.
  - **Currently Implemented**:
    - Users can choose the deletion mode but the provider does not warn or block destructive settings.
  - **Missing Implementation**:
    - No built-in confirmation or alert if a user selects the destructive option. Users must manually verify or enforce guardrails.
