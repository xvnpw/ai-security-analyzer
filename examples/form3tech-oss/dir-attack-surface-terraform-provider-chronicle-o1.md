- **Sensitive credentials stored in Terraform state**
  **Description**: Multiple resource implementations in this provider (for example, `chronicle_feed_amazon_s3`, `chronicle_feed_okta_system_log`, etc.) require specifying secrets or tokens in the Terraform configuration. While some fields are marked as sensitive, Terraform itself persists all configuration data (including secrets) in the `.tfstate` file, potentially exposing credentials in plaintext.
  **How the project contributes**: The provider’s schema design collects secret information (e.g., `secret_access_key`, `client_secret`, and `value`) as normal strings. These values end up in Terraform state by default, unless actively secured or rotated externally.
  **Example**: A user sets `chronicle_feed_amazon_s3.details[0].authentication[0].secret_access_key` to a real credential. That plain text string is then written to `terraform.tfstate`.
  **Impact**: If attackers (or malicious insiders) gain read access to the state file (local or remote), they can harvest valid credentials for Chronicle or third-party services, allowing unauthorized data ingestion or resource manipulation.
  **Severity**: High
  **Current Mitigations**:
  - Certain fields are marked as `Sensitive: true`, preventing them from being displayed in plan/apply logs, but they still exist unencrypted in state.
  - Users can use remote state backends with encryption-at-rest and restricted access control.
  **Missing Mitigations**:
  - Further minimize the plaintext exposure in Terraform state by ensuring secrets are not stored if not strictly necessary for resource lifecycle.
  - Provide explicit documentation or warnings about storing secrets in state, emphasizing secure backend usage and least-privilege access to Terraform administrative users.

- **Custom endpoint potential for SSRF-like attacks**
  **Description**: The provider configuration allows setting custom endpoints (e.g. `events_custom_endpoint`, `alert_custom_endpoint`, `artifact_custom_endpoint`, etc.). If an attacker can alter these fields, the underlying Terraform runs could connect to arbitrary or internal hosts.
  **How the project contributes**: The provider exposes these custom endpoints without enforcing domain restrictions or strong validation, enabling traffic redirection to non-official or malicious servers.
  **Example**: A malicious user sets `rule_custom_endpoint` to `http://169.254.169.254/` or another internal system, leading the provider to leak metadata or trigger unwanted connections from the Terraform runner.
  **Impact**: This can facilitate SSRF-like behavior, letting an attacker pivot into internal networks, retrieve sensitive metadata, or exploit local services on the host running Terraform.
  **Severity**: Medium
  **Current Mitigations**:
  - Basic validation ensures the endpoint is a well-formed URL, but no additional checks exist.
  **Missing Mitigations**:
  - Domain allow-listing or limiting endpoint overrides to recognized official Chronicle URLs.
  - User-facing guidance on restricting who can modify these endpoint configurations.
