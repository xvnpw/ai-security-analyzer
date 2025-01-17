## Threat Model for Applications Using Terraform Chronicle

This document outlines potential security threats introduced by using the `terraform-provider-chronicle`. It focuses on vulnerabilities specific to the provider and excludes general web application security concerns.

### Threat List

- **Threat:** Exposure of Chronicle API Credentials through Terraform State
  - **Description:**  Chronicle provider configuration allows specifying API credentials (e.g., `backstoryapi_credentials`, `ingestionapi_credentials`, `bigqueryapi_credentials`, `forwarderapi_credentials`) directly in the Terraform configuration files, through environment variables, or via file paths as seen in `client\util.go`. If the Terraform state file is not properly secured (e.g., stored in an unencrypted location, accessible to unauthorized users), these credentials could be exposed. An attacker gaining access to the state file could extract these credentials and use them to directly access and manipulate Chronicle APIs, potentially reading sensitive data, modifying configurations, or ingesting malicious data.
  - **Impact:** Critical
  - **Affected Component:** Provider Configuration, Terraform State Management, `client\util.go`
  - **Risk Severity:** Critical
  - **Mitigation Strategies:**
    - Store Terraform state files in secure, encrypted backends with access controls.
    - Avoid storing credentials directly in Terraform configuration files.
    - Utilize secret management tools (e.g., HashiCorp Vault, AWS Secrets Manager) to manage and inject credentials at runtime.
    - Implement proper access control and auditing for the Terraform state backend.
    - Regularly rotate API keys and credentials.
    - If using file paths for credentials, ensure the files are stored securely with appropriate permissions.

- **Threat:** Exposure of AWS/Azure/Okta/Proofpoint/Qualys/Thinkst Canary/Microsoft Office 365 Credentials in Feed Configurations
  - **Description:** Several feed resources (e.g., `chronicle_feed_amazon_s3`, `chronicle_feed_amazon_sqs`, `chronicle_feed_azure_blobstore`, `chronicle_feed_okta_system_log`, `chronicle_feed_proofpoint_siem`, `chronicle_feed_qualys_vm`, `chronicle_feed_thinkst_canary`, `chronicle_feed_microsoft_office_365_management_activity`, `chronicle_google_cloud_storage_bucket`) require credentials for external services to pull logs. These credentials (e.g., `access_key_id`, `secret_access_key` for AWS, `shared_key`, `sas_token` for Azure, API tokens (`value`) for Okta, `user`, `secret` for Proofpoint and Qualys, API tokens for Thinkst Canary, `client_id`, `client_secret` for Microsoft Office 365) are often specified directly in the Terraform configuration. If the Terraform state is compromised, these credentials could be exposed, allowing an attacker to access the external services. The `chronicle_feed_amazon_sqs` resource allows for separate SQS and S3 credentials, increasing the number of secrets that need to be managed. The `chronicle_feed_azure_blobstore` resource uses `shared_key` or `sas_token` for authentication. The `chronicle_feed_microsoft_office_365_management_activity` resource uses `client_id` and `client_secret`. The `chronicle_feed_okta_system_log` and `chronicle_feed_okta_users` resources use `key` and `value` for authentication. The `chronicle_feed_proofpoint_siem` and `chronicle_feed_qualys_vm` resources use `user` and `secret` for authentication. The `chronicle_feed_thinkst_canary` resource uses an API token (`value`) for authentication. The `chronicle_google_cloud_storage_bucket` resource does not require explicit credentials in the Terraform configuration, relying on the underlying infrastructure's authentication mechanisms, but misconfigurations could still lead to exposure.
  - **Impact:** High
  - **Affected Component:** Feed Resources (Amazon S3, Amazon SQS, Azure Blobstore, Okta System Log, Okta Users, Proofpoint SIEM, Qualys VM, Thinkst Canary, Google Cloud Storage Bucket, Microsoft Office 365 Management Activity)
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Avoid storing credentials directly in Terraform configuration for feed resources.
    - Utilize secret management tools to manage and inject credentials for external services.
    - Implement the principle of least privilege when granting permissions to the credentials used by the feeds.
    - Regularly rotate API keys and credentials for external services.
    - Consider using instance profiles or managed identities where applicable to avoid storing credentials.

- **Threat:** Insecure Handling of Sensitive Data in Transit
  - **Description:** The provider interacts with various APIs (Chronicle, AWS, Azure, Okta, etc.) to manage resources and ingest data. If these connections are not properly secured using HTTPS/TLS, sensitive data like credentials and log data could be intercepted in transit by a man-in-the-middle attacker.
  - **Impact:** High
  - **Affected Component:** All API interactions
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Ensure the provider and the underlying libraries enforce HTTPS/TLS for all API communication.
    - Verify the TLS certificates of the API endpoints to prevent impersonation.
    - Avoid using custom or insecure API endpoints (`*_custom_endpoint` options) unless absolutely necessary and with thorough security vetting.

- **Threat:**  Accidental Deletion or Modification of Chronicle Resources
  - **Description:**  Terraform's declarative nature means that changes to the configuration will be applied to the infrastructure. If a user with sufficient permissions makes unintended changes to the Terraform configuration (e.g., modifies a feed configuration, deletes a rule, or revokes RBAC roles), it can lead to accidental deletion or modification of critical Chronicle resources, potentially disrupting security monitoring and incident response capabilities.
  - **Impact:** High
  - **Affected Component:** All Resource Types (Feeds, Rules, RBAC Subjects, Reference Lists)
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Implement code review processes for Terraform configurations.
    - Utilize version control for Terraform configurations to track changes and enable rollback.
    - Apply the principle of least privilege when granting Terraform state access and provider configuration permissions.
    - Use Terraform Cloud or similar tools for remote state management, collaboration, and policy enforcement.
    - Implement destroy protection on critical resources where supported.

- **Threat:**  Injection Vulnerabilities in Rule Text
  - **Description:** The `chronicle_rule` resource allows defining YARA-L rules through the `rule_text` attribute. If the input for `rule_text` is not properly sanitized or validated, an attacker could potentially inject malicious YARA-L code. While the direct impact is within the Chronicle environment, this could lead to unexpected rule behavior, potentially bypassing detection mechanisms or causing performance issues within Chronicle. The `examples\resources\detection\rule\main.tf` shows an example of loading the rule text from a file, which could introduce vulnerabilities if the file's content is not trusted.
  - **Impact:** Medium
  - **Affected Component:** `chronicle_rule` resource
  - **Risk Severity:** Medium
  - **Mitigation Strategies:**
    - Implement robust input validation and sanitization for the `rule_text` attribute.
    - Provide clear guidelines and training to users on secure YARA-L rule development practices.
    - Regularly review and audit existing rules for potential malicious content.
    - When loading rule text from a file, ensure the file's integrity and source are trustworthy.

- **Threat:**  Manipulation of Ingestion Feeds Leading to Data Poisoning
  - **Description:** Attackers who gain unauthorized access to the Terraform state or provider configurations could modify feed configurations (e.g., change the source of logs, alter parsing rules if configurable in the future). This could lead to the ingestion of malicious or incorrect data into Chronicle, potentially misleading security analysis and hindering accurate threat detection. The ability to configure separate S3 credentials for `chronicle_feed_amazon_sqs` and separate authentication methods (`shared_key`, `sas_token`) for `chronicle_feed_azure_blobstore` adds more potential points of manipulation.
  - **Impact:** High
  - **Affected Component:** Feed Resources (Amazon S3, Amazon SQS, Azure Blobstore, Microsoft Office 365 Management Activity, Okta System Log, Okta Users, Proofpoint SIEM, Qualys VM, Thinkst Canary, Google Cloud Storage Bucket)
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Secure Terraform state and provider configurations as described in previous threats.
    - Implement monitoring and alerting for changes to feed configurations.
    - Regularly audit feed configurations to ensure they are pointing to legitimate and trusted sources.
    - Implement data validation and anomaly detection within Chronicle to identify potentially poisoned data.

- **Threat:**  Abuse of Custom Endpoints
  - **Description:** The provider allows specifying custom endpoints for various Chronicle APIs (e.g., `alert_custom_endpoint`, `feed_custom_endpoint`, `events_custom_endpoint`, `artifact_custom_endpoint`, `alias_custom_endpoint`, `asset_custom_endpoint`, `ioc_custom_endpoint`, `rule_custom_endpoint`, `subjects_custom_endpoint`). If these custom endpoints are not properly validated or point to malicious servers, attackers could potentially intercept API requests, steal credentials, or manipulate API responses.
  - **Impact:** High
  - **Affected Component:** Provider Configuration
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Avoid using custom endpoints unless absolutely necessary.
    - Thoroughly vet the security of any custom endpoint before using it.
    - Ensure that custom endpoints use HTTPS and have valid TLS certificates.
    - Implement strict input validation for custom endpoint URLs.

- **Threat:**  Exposure of Secrets in Debug Logs
  - **Description:** The `debug.sh` script enables debugging for the provider. Depending on the debugging level and the provider's logging implementation, sensitive information like API keys or access tokens might be logged, potentially exposing them to anyone with access to the debug logs.
  - **Impact:** Medium
  - **Affected Component:** Debugging Tools and Logging
  - **Risk Severity:** Medium
  - **Mitigation Strategies:**
    - Avoid using debug mode in production environments.
    - If debugging is necessary, ensure that debug logs are stored securely and access is restricted.
    - Review the provider's logging configuration to avoid logging sensitive information.
    - Sanitize or redact sensitive information from debug logs before sharing them.

- **Threat:** Inconsistent Credential Handling
  - **Description:** The provider allows specifying API credentials through various methods: direct input in Terraform configuration, local file paths (as seen in `client\util.go` and examples), or environment variables (sometimes base64 encoded). This inconsistency can lead to confusion and increase the risk of accidental exposure. For example, developers might mistakenly commit a file containing credentials or fail to properly secure environment variables. The `client.go` file shows that credentials can be provided as a file path, a direct JSON string, or through environment variables. The `GetCredentials` function in `client.go` attempts to decode base64 encoded credentials from environment variables. The `pathOrContents` function in `client\util.go` handles reading credentials from a specified file path.
  - **Impact:** High
  - **Affected Component:** Provider Configuration (authentication parameters), `client.go`, `client\util.go`
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Standardize credential management practices across the organization.
    - Strongly recommend and document the use of secret management tools over direct configuration, environment variables, or local files.
    - Implement checks (e.g., linters, static analysis) to detect hardcoded credentials in configuration files.
    - Clearly document the expected format and security implications of each credential input method.
    - If using file paths for credentials, enforce secure storage and access controls for those files.

- **Threat:**  Incorrect Configuration of Source Deletion Options Leading to Data Loss or Unintended Retention
  - **Description:** The `chronicle_feed_amazon_s3`, `chronicle_feed_amazon_sqs`, and `chronicle_feed_google_cloud_storage_bucket` resources offer options for deleting source files after ingestion (`source_delete_options`). Incorrect configuration of these options could lead to unintended data loss if files are deleted prematurely or, conversely, to increased storage costs and potential security risks if data is retained unnecessarily. The `chronicle_feed_google_cloud_storage_bucket` offers more granular options for deletion. The `validation.go` file contains validation functions (`validateFeedS3SourceDeleteOption`, `validateFeedGCSSourceDeleteOption`, `validateFeedAzureBlobStoreSourceDeleteOption`) for these options, highlighting the importance of correct configuration.
  - **Impact:** Medium
  - **Affected Component:** `chronicle_feed_amazon_s3`, `chronicle_feed_amazon_sqs`, `chronicle_feed_google_cloud_storage_bucket` resources, `validation.go`
  - **Risk Severity:** Medium
  - **Mitigation Strategies:**
    - Clearly document the implications of each `source_delete_options` value.
    - Implement code reviews to ensure the chosen option aligns with data retention policies.
    - Consider implementing safeguards or backups before enabling source deletion.
    - Regularly review and audit feed configurations to verify the `source_delete_options` are correctly set.

- **Threat:** Potential for Malicious Content Injection via Reference Lists
  - **Description:** The `chronicle_reference_list` resource allows users to define lists of strings, which can be used in Chronicle rules. If an attacker gains the ability to modify these reference lists (through compromised Terraform state or provider configuration), they could inject malicious content. This is especially concerning when the `content_type` is set to `REGEX`, as it allows for the introduction of potentially harmful regular expressions that could cause performance issues or unexpected behavior within Chronicle's rule processing engine. Even with `CONTENT_TYPE_DEFAULT_STRING` or `CIDR`, adding misleading or malicious entries could negatively impact security analysis. The `validation.go` file includes `validateReferenceListContentType` which validates the allowed content types.
  - **Impact:** Medium
  - **Affected Component:** `chronicle_reference_list` resource, `validation.go`
  - **Risk Severity:** Medium
  - **Mitigation Strategies:**
    - Secure Terraform state and provider configurations as described in previous threats.
    - Implement change control and auditing for modifications to reference lists.
    - Regularly review the content of reference lists for unexpected or malicious entries.
    - If using `REGEX` content type, ensure that the regular expressions are carefully vetted and do not introduce security vulnerabilities (e.g., ReDoS).

- **Threat:** Potential Regular Expression Denial of Service (ReDoS) in Reference Lists
  - **Description:** When the `chronicle_reference_list` resource's `content_type` is set to `REGEX`, users can define regular expressions. If an attacker gains control over the content of a reference list, they could inject complex, inefficient regular expressions. When these reference lists are used in Chronicle rules, the processing of these malicious regular expressions could lead to excessive CPU consumption and a denial of service within the Chronicle environment. The `validation.go` file includes `validateRegexp` which is used for validating various string formats, but might not prevent all ReDoS scenarios.
  - **Impact:** High
  - **Affected Component:** `chronicle_reference_list` resource, Chronicle Rule Processing Engine
  - **Risk Severity:** High
  - **Mitigation Strategies:**
    - Implement safeguards to prevent the injection of overly complex regular expressions in reference lists.
    - Consider using static analysis tools to evaluate the complexity and potential performance impact of regular expressions before they are applied.
    - Implement resource limits or timeouts for regular expression processing within Chronicle.
    - Educate users on the risks of ReDoS and best practices for writing efficient regular expressions.

- **Threat:** Credential Exposure through Verbose Logging
  - **Description:** While the `debug.sh` script was previously identified as a potential source of secret exposure, the underlying logging mechanism used by the provider could also inadvertently log sensitive information. The `client\transport.go` file shows the use of `log.Printf` for debugging retry attempts. Depending on the verbosity of the logging configuration and the content of the messages, API keys or other secrets could be logged, potentially exposing them if these logs are not properly secured.
  - **Impact:** Medium
  - **Affected Component:** Logging mechanism, `client\transport.go`
  - **Risk Severity:** Medium
  - **Mitigation Strategies:**
    - Carefully review the provider's logging implementation and configuration to identify and prevent the logging of sensitive information.
    - Ensure that logging levels are appropriately configured, especially in production environments, to minimize the risk of exposing secrets.
    - Secure access to log files and implement mechanisms for log rotation and secure storage.
    - Sanitize or redact sensitive information from logs before storing or sharing them.
