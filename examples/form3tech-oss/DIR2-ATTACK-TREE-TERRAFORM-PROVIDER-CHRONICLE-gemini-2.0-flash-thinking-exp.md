Attacker Goal: Compromise application by exploiting the Terraform Chronicle provider

Root: Compromise application using Terraform Chronicle provider

  ├── Exploit Misconfigured Provider Credentials
  │   ├── Description: Attacker gains access to Chronicle by exploiting credentials stored insecurely in Terraform configuration, state files, or environment variables. This includes `bigqueryapi_credentials`, `bigqueryapi_access_token`, `backstoryapi_credentials`, `backstoryapi_access_token`, `ingestionapi_credentials`, `ingestionapi_access_token`, `forwarderapi_credentials`, `forwarderapi_access_token`, and their corresponding environment variables (e.g., `CHRONICLE_BIGQUERY_CREDENTIALS`).
  │   ├── Actionable Insights: Avoid storing credentials directly in Terraform configurations or state files. Use environment variables cautiously and ensure the environment where Terraform runs is securely managed. Prefer secrets management solutions. Ensure Terraform state files are securely stored and access is restricted.
  │   ├── Likelihood: High
  │   ├── Impact: Critical
  │   ├── Effort: Low
  │   ├── Skill Level: Low
  │   ├── Detection Difficulty: Medium
  │
  ├── Exploit Misconfigured Feed Resources
  │   ├── Description: Attacker manipulates feed configurations to gain unauthorized access to data sources or inject malicious data into Chronicle.
  │   ├── Actionable Insights: Implement strict validation and review processes for feed configurations. Follow the principle of least privilege when configuring access to data sources.
  │   ├── Likelihood: Medium
  │   ├── Impact: High
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Compromise AWS S3 Feed
  │   │   ├── Description: Attacker exploits misconfigured S3 feed credentials (`access_key_id`, `secret_access_key`) to access the S3 bucket.
  │   │   ├── Actionable Insights: Rotate AWS keys regularly. Use IAM roles instead of long-term credentials where possible. Ensure the S3 bucket policy adheres to the principle of least privilege.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Compromise AWS SQS Feed
  │   │   ├── Description: Attacker exploits misconfigured SQS feed credentials (`sqs_access_key_id`, `sqs_secret_access_key`) to access the SQS queue and potentially the associated S3 bucket.
  │   │   ├── Actionable Insights: Rotate AWS keys regularly. Use IAM roles instead of long-term credentials where possible. Ensure the SQS queue policy adheres to the principle of least privilege.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Compromise Azure Blobstore Feed
  │   │   ├── Description: Attacker exploits misconfigured Azure Blobstore feed credentials (`sas_token` or `shared_key`) to access the Azure storage account.
  │   │   ├── Actionable Insights: Rotate SAS tokens and shared keys regularly. Use Azure AD authentication instead of shared keys where possible. Ensure the storage account access policies adhere to the principle of least privilege.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Compromise Google Cloud Storage Bucket Feed
  │   │   ├── Description: Attacker exploits misconfigured GCS bucket feed settings (though authentication is not directly managed by the provider for GCS, misconfigurations in the bucket policy can be exploited).
  │   │   ├── Actionable Insights: Ensure GCS bucket policies adhere to the principle of least privilege. Regularly review and audit bucket permissions.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Exploit API Feed Credentials
  │   │   ├── Description: Attacker exploits misconfigured API feed credentials to access the external service. This includes but is not limited to Okta API token, Proofpoint secret, Microsoft Office 365 Management Activity API client secret and Qualys VM password.
  │   │   ├── Actionable Insights: Rotate API keys and tokens regularly. Store API keys securely using secrets management.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │   │
  │   │   ├── Sub-sub-node: Exploit Misconfigured Okta System Log Feed Credentials
  │   │   │   ├── Description: Attacker exploits misconfigured Okta System Log feed credentials (`key`, `value`) to access the Okta API.
  │   │   │   ├── Actionable Insights: Rotate Okta API tokens regularly. Store the token securely using secrets management. Ensure the principle of least privilege is applied to the API token.
  │   │   │   ├── Likelihood: Medium
  │   │   │   ├── Impact: High
  │   │   │   ├── Effort: Medium
  │   │   │   ├── Skill Level: Medium
  │   │   │   ├── Detection Difficulty: Medium
  │   │   │
  │   │   ├── Sub-sub-node: Exploit Misconfigured Okta Users Feed Credentials
  │   │   │   ├── Description: Attacker exploits misconfigured Okta Users feed credentials (`key`, `value`) to access the Okta API.
  │   │   │   ├── Actionable Insights: Rotate Okta API tokens regularly. Store the token securely using secrets management. Ensure the principle of least privilege is applied to the API token.
  │   │   │   ├── Likelihood: Medium
  │   │   │   ├── Impact: High
  │   │   │   ├── Effort: Medium
  │   │   │   ├── Skill Level: Medium
  │   │   │   ├── Detection Difficulty: Medium
  │   │   │
  │   │   ├── Sub-sub-node: Exploit Misconfigured Proofpoint SIEM Feed Credentials
  │   │   │   ├── Description: Attacker exploits misconfigured Proofpoint SIEM feed credentials (`user`, `secret`) to access the Proofpoint API.
  │   │   │   ├── Actionable Insights: Rotate Proofpoint secrets regularly. Store the secret securely using secrets management. Ensure the principle of least privilege is applied to the API credentials.
  │   │   │   ├── Likelihood: Medium
  │   │   │   ├── Impact: High
  │   │   │   ├── Effort: Medium
  │   │   │   ├── Skill Level: Medium
  │   │   │   ├── Detection Difficulty: Medium
  │   │   │
  │   │   ├── Sub-sub-node: Exploit Misconfigured Microsoft Office 365 Management Activity Feed Credentials
  │   │   │   ├── Description: Attacker exploits misconfigured Microsoft Office 365 Management Activity feed credentials (`client_id`, `client_secret`) to access the Office 365 Management Activity API.
  │   │   │   ├── Actionable Insights: Rotate OAuth client secrets regularly. Store secrets securely using secrets management. Ensure the principle of least privilege is applied to the associated Azure AD application.
  │   │   │   ├── Likelihood: Medium
  │   │   │   ├── Impact: High
  │   │   │   ├── Effort: Medium
  │   │   │   ├── Skill Level: Medium
  │   │   │   ├── Detection Difficulty: Medium
  │   │   │
  │   │   ├── Sub-sub-node: Exploit Misconfigured Qualys VM Feed Credentials
  │   │   │   ├── Description: Attacker exploits misconfigured Qualys VM feed credentials (`user`, `secret`) to access the Qualys API.
  │   │   │   ├── Actionable Insights: Rotate Qualys passwords regularly. Store the password securely using secrets management. Ensure the principle of least privilege is applied to the API credentials.
  │   │   │   ├── Likelihood: Medium
  │   │   │   ├── Impact: High
  │   │   │   ├── Effort: Medium
  │   │   │   ├── Skill Level: Medium
  │   │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Compromise Separate S3 Authentication in SQS Feed
  │   │   ├── Description: Attacker exploits misconfigured S3 authentication details (`access_key_id`, `secret_access_key` within the `s3_authentication` block) within an AWS SQS feed configuration, granting access to the associated S3 bucket.
  │   │   ├── Actionable Insights: Rotate AWS keys regularly. Use IAM roles instead of long-term credentials where possible. Ensure the S3 bucket policy adheres to the principle of least privilege, even when accessed via SQS feeds.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │   │
  │   ├── Sub-node: Exploit Misconfigured Thinkst Canary Feed Credentials
  │   │   ├── Description: Attacker exploits misconfigured Thinkst Canary feed credentials (`value` within the `authentication` block) to access the Thinkst Canary API.
  │   │   ├── Actionable Insights: Rotate Thinkst Canary API keys regularly. Store the API key securely using secrets management. Ensure the principle of least privilege is applied to the API key.
  │   │   ├── Likelihood: Medium
  │   │   ├── Impact: High
  │   │   ├── Effort: Medium
  │   │   ├── Skill Level: Medium
  │   │   ├── Detection Difficulty: Medium
  │
  ├── Man-in-the-Middle Attack on Custom Endpoints
  │   ├── Description: Attacker intercepts communication between the Terraform provider and Chronicle's API by exploiting the ability to configure custom endpoints over non-HTTPS. The `validateCustomEndpoint` function only validates the URL format, not the use of HTTPS. This affects custom endpoints for events, alerts, artifacts, alias, assets, ioc, rule and subjects APIs.
  │   ├── Actionable Insights: Enforce the use of HTTPS for all Chronicle API endpoints within the provider. Avoid using custom endpoints unless absolutely necessary and ensure they are secured with TLS.
  │   ├── Likelihood: Medium
  │   ├── Impact: High
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Low (if proper monitoring is in place)
  │
  ├── Unauthorized Modification of RBAC Roles
  │   ├── Description: Attacker gains the ability to modify RBAC roles through the `chronicle_rbac_subject` resource, leading to privilege escalation within Chronicle.
  │   ├── Actionable Insights: Restrict access to modify `chronicle_rbac_subject` resources. Implement strong authorization controls for Terraform operations.
  │   ├── Likelihood: Low (depends on access control to Terraform)
  │   ├── Impact: Critical
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Medium
  │
  ├── Unauthorized Modification of Reference Lists
  │   ├── Description: Attacker gains the ability to modify reference lists through the `chronicle_reference_list` resource, allowing them to add malicious entries.
  │   ├── Actionable Insights: Restrict access to modify `chronicle_reference_list` resources. Implement change control and auditing for reference list modifications.
  │   ├── Likelihood: Low (depends on access control to Terraform)
  │   ├── Impact: Medium
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Medium
  │
  ├── Unauthorized Modification of Detection Rules
  │   ├── Description: Attacker gains the ability to modify detection rules through the `chronicle_rule` resource, potentially disabling critical alerts or introducing malicious rules.
  │   ├── Actionable Insights: Restrict access to modify `chronicle_rule` resources. Implement a review process for changes to detection rules.
  │   ├── Likelihood: Low (depends on access control to Terraform)
  │   ├── Impact: Critical
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Medium
  │
  ├── Exfiltration via Misconfigured Feed Deletion Options
  │   ├── Description: Attacker with control over feed resources sets `source_delete_options` to delete data after ingestion, causing data loss or hiding malicious activity. While not direct exfiltration, it impacts data availability and integrity.
  │   ├── Actionable Insights: Implement strict controls and auditing for modifications to feed resources, especially the `source_delete_options`.
  │   ├── Likelihood: Low (requires prior compromise)
  │   ├── Impact: Medium
  │   ├── Effort: Low
  │   ├── Skill Level: Low
  │   ├── Detection Difficulty: Medium
  │
  ├── Local File Inclusion via `rule_text`
  │   ├── Description: Attacker leverages the `file()` function within the `rule_text` argument of the `chronicle_rule` resource to read arbitrary local files on the system where Terraform is executed. This is possible if the attacker can control the path provided to the `file()` function.
  │   ├── Actionable Insights: Restrict access to modify `chronicle_rule` resources and the files they reference. Implement strict input validation and sanitization for file paths used in Terraform configurations. Store YARA rules in a dedicated, protected location.
  │   ├── Likelihood: Medium
  │   ├── Impact: High
  │   ├── Effort: Medium
  │   ├── Skill Level: Medium
  │   ├── Detection Difficulty: Medium
