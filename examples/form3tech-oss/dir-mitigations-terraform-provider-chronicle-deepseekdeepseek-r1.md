Here's the updated mitigation strategies list integrating findings from the new PROJECT FILES:

### Mitigation Strategies

1. **Enforce HTTPS for Custom Endpoints**
   - **Description**: Validate that all custom endpoints (e.g., Azure Blobstore URI, Okta hostnames) use HTTPS. Modify schema validation to reject HTTP URLs across all feed types.
   - **Threats Mitigated**:
     - MITM attacks intercepting credentials/data (Severity: High)
   - **Impact**: Ensures 100% encrypted communication for all external connections
   - **Currently Implemented**: Partial - Azure Blobstore example uses HTTPS URI
   - **Missing Implementation**: Add HTTPS validation for Okta (`hostname`), Office 365 (`hostname`), and Thinkst Canary (`hostname`) fields in respective resource schemas

2. **Validate RBAC Role Existence**
   - **Description**: Add real-time validation for `chronicle_rbac_subject` roles against Chronicle's API during plan/apply
   - **Threats Mitigated**:
     - Assignment of invalid roles leading to broken access controls (Severity: Medium)
   - **Impact**: Prevents 100% of invalid role assignments
   - **Currently Implemented**: No - Example shows static "Editor" role without validation
   - **Missing Implementation**: Add API integration in [`resource_rbac_subject.go`](#rbac_subject.md)

3. **Support AWS STS Temporary Credentials**
   - **Description**: Implement `aws_session_token` field for S3/SQS authentication blocks to enable temporary credentials
   - **Threats Mitigated**:
     - Compromise of long-lived AWS credentials (Severity: High)
   - **Impact**: Reduces credential exposure window from indefinite to 1-12 hours
   - **Currently Implemented**: No - Examples show static access keys
   - **Missing Implementation**: Update [S3](#resource_feed_amazon_s3.md) and [SQS](#resource_feed_amazon_sqs.md) authentication schemas

4. **Sensitive Field Audit and Enforcement**
   - **Description**: Ensure all credential fields are marked `Sensitive: true` including:
     - Azure Blobstore `shared_key`
     - Office 365 `client_secret`
     - Okta System Log/Users `authentication.value`
     - Proofpoint `secret`
   - **Threats Mitigated**:
     - Credential exposure in Terraform logs/state (Severity: Medium)
   - **Impact**: Eliminates plaintext leakage of 100% sensitive credentials
   - **Currently Implemented**: Partial - Proofpoint/Qualys secrets marked
   - **Missing Implementation**: Mark Azure `shared_key` and Okta `authentication.value` as sensitive in schema definitions

5. **Credential Rotation Enforcement**
   - **Description**: Implement expiration tracking for:
     - Okta API tokens (authentication values)
     - Azure Shared Keys
     - Office 365 Client Secrets
   - **Threats Mitigated**:
     - Stale credential compromise (Severity: Medium)
   - **Impact**: Reduces credential lifetime from indefinite to policy-compliant durations
   - **Currently Implemented**: No - All examples show static credentials
   - **Missing Implementation**: Add metadata fields for credential creation/expiration dates

---

### Implementation Status Summary

- **HTTPS Enforcement**: Partially implemented - Azure uses HTTPS but other feeds lack validation
- **RBAC Validation**: Not implemented - Role existence checks missing
- **AWS STS Support**: Not implemented - Schema lacks temporary credential fields
- **Sensitivity Audit**: 50% implemented - Critical fields like Azure shared_key still exposed
- **Credential Rotation**: Not implemented - No lifecycle management for any credentials

These updates address risks observed in new feed implementations (Azure Blobstore, Okta Users/System Log, Office 365) while maintaining focus on credential protection and access control validation.
