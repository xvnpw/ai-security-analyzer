## APPLICATION THREAT MODEL

### ASSETS
- Cloud Service Credentials: AWS access keys, Azure shared keys/SAS tokens, GCP credentials used in feed configurations
- API Tokens: Chronicle API access tokens for Backstory, BigQuery, Ingestion, and Forwarder services
- External Service Credentials: Okta API tokens, Proofpoint secrets, Qualys VM credentials, Thinkst Canary authentication values, Microsoft 365 client secrets
- Azure Shared Keys: Storage account access keys for Azure Blobstore integration
- Sensitive Data Ingested: Log data ingested into Chronicle which may contain sensitive information
- RBAC Configuration: Role assignments and subject definitions controlling access within Chronicle
- Reference Lists: Security-related data (IPs, regex patterns, CIDRs) used for threat detection

### TRUST BOUNDARIES
1. Between user's local environment/Terraform CLI and Chronicle API endpoints
2. Between Terraform state storage and execution environment
3. Between CI/CD systems (GitHub Actions) and Chronicle services
4. Between provider and external APIs (Okta, Proofpoint, Qualys, Thinkst Canary, Microsoft 365)
5. Between cloud storage services (AWS S3, Azure Blob, GCS) and Chronicle ingestion components

### DATA FLOWS
1. Terraform configuration -> Chronicle API (crosses trust boundary)
2. Cloud storage services (S3, Azure Blob, GCS) -> Chronicle ingestion (crosses trust boundary)
3. Secret management systems (Vault, AWS Secrets Manager) -> Terraform variables (crosses trust boundary)
4. External services (Okta/Proofpoint/Qualys/Microsoft 365) -> Chronicle feed ingestion (crosses trust boundary)
5. Azure Blobstore authentication -> Chronicle provider (crosses trust boundary via shared key)
6. Microsoft 365 client credentials -> Office 365 Management API (crosses trust boundary)

### APPLICATION THREATS
1. External Service Credential Exposure
   - Description: Secrets for external services (Okta tokens, Proofpoint secrets) stored in plaintext in Terraform state
   - Impact: Compromise of connected external security systems
   - Component: All feed authentication configurations
   - Current Mitigations: Sensitive fields marked as `sensitive` in schema
   - Missing Mitigations: State file encryption enforcement documentation
   - Risk Severity: High

2. Insecure Credential Transmission to External Services
   - Description: Authentication data transmitted to external APIs without certificate validation
   - Impact: Credential interception through MITM attacks
   - Component: API client implementations for Okta/Proofpoint/Qualys
   - Current Mitigations: No evidence of TLS enforcement in provided code
   - Missing Mitigations: Hostname verification and certificate pinning
   - Risk Severity: Critical

3. Improper RBAC Configuration
   - Description: Incorrect role assignments through subject resources granting excessive privileges
   - Impact: Privilege escalation within Chronicle environment
   - Component: RBAC subject resource operations
   - Current Mitigations: Server-side role validation
   - Missing Mitigations: Terraform pre-execution role validation
   - Risk Severity: High

4. Invalid Reference List Entries
   - Description: Malformed regex patterns or CIDR ranges stored in reference lists
   - Impact: Broken detection rules or false positives
   - Component: Reference list resource validators
   - Current Mitigations: Content-type specification
   - Missing Mitigations: Syntax validation during apply
   - Risk Severity: Medium

5. Insecure YARA-L Rule Updates
   - Description: Unvalidated rule text modifications leading to detection pipeline failures
   - Impact: Missed security alerts or rule engine outages
   - Component: Rule resource compilation
   - Current Mitigations: Server-side compilation checks
   - Missing Mitigations: Pre-submission validation in provider
   - Risk Severity: Medium

6. Missing Cloud Feed Authentication
   - Description: Example configurations showing GCS feed without authentication details
   - Impact: Potential misconfiguration leading to failed ingestion or unauthorized access
   - Component: Google Cloud Storage feed resource
   - Current Mitigations: No authentication block shown in example
   - Missing Mitigations: Example hardening with auth requirements documentation
   - Risk Severity: Medium

## DEPLOYMENT THREAT MODEL

### ASSETS
- CI/CD Secrets: GitHub Actions secrets containing Chronicle and external service credentials
- Terraform State Files: Contains sensitive configuration for all integrated services
- Build Artifacts: Compiled provider binaries distributed via GitHub Releases

### DEPLOYMENT THREATS
1. External Credential Leakage in CI/CD
   - Description: Exposure of Okta/Proofpoint secrets through CI/CD logs
   - Impact: Compromise of external security systems
   - Component: Release workflows handling multiple credential types
   - Current Mitigations: Use of GitHub Secrets
   - Missing Mitigations: Automated secret scanning in pipelines
   - Risk Severity: High

## BUILD THREAT MODEL

### BUILD THREATS
1. Third-Party Dependency Compromise
   - Description: Malicious code in external libraries (Okta SDK, Proofpoint clients)
   - Impact: Supply chain attack affecting all users
   - Component: Go dependency chain
   - Current Mitigations: Pinned dependency versions
   - Missing Mitigations: Software Bill of Materials (SBOM) verification
   - Risk Severity: Medium

2. Build Script Manipulation
   - Description: Malicious modifications to GNUmakefile altering build/install process
   - Impact: Compromised provider binaries installed to local environments
   - Component: Makefile targets (install/build)
   - Current Mitigations: No integrity checks for build scripts
   - Missing Mitigations: Cryptographic verification of build artifacts
   - Risk Severity: Medium

## QUESTIONS & ASSUMPTIONS
1. Assumed all external APIs (Okta, Proofpoint) enforce TLS 1.2+ by default
2. Presumed reference list content validation occurs server-side
3. No visibility into external service credential rotation policies
4. Assumed Terraform users follow secret management best practices for multiple credential types
5. No data provided about external API rate limiting protections
6. Assumed YARA-L rule validation includes syntax checking beyond basic compilation
7. Presumed GCS feed authentication is required but not shown in example
8. Assumed placeholder credentials ("XXXX") in examples are replaced before deployment
9. No visibility into Chronicle API endpoint authentication mechanisms
10. Assumed Microsoft 365 client secret rotation aligns with feed configuration updates
