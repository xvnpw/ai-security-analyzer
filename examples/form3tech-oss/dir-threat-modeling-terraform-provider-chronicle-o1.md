## APPLICATION THREAT MODEL

### ASSETS
- **User Credentials**: The access tokens and credential files used by the provider (BigQuery, Backstory, Ingestion, Forwarder).
- **Terraform Configuration**: The `.tf` files where users define Chronicle resources (feeds, RBAC subjects, rules, reference lists).
- **Terraform State**: State can contain references to resources and may also contain sensitive data if misconfigured.
- **Provider Source Code**: The Go code (e.g., `provider.go`, resource implementations) that implements logic to create, update, and delete Chronicle resources.
- **Runtime Memory**: In-memory secrets or tokens that are used to authenticate requests to Chronicle APIs.

### TRUST BOUNDARIES
- Boundary between **Terraform CLI** and **Terraform Provider** (the provider is a separate binary that Terraform calls over RPC).
- Boundary between **User’s Local Environment** (where credentials may be in environment variables or local files) and the **Provider** (which reads them for API calls).
- Boundary between the **Provider** and **Chronicle API** (outgoing HTTP calls using credentials).

### DATA FLOWS
- User writes Terraform config locally → Terraform CLI → Terraform Provider.  (Crosses the boundary between user environment and provider.)
- Provider loads credentials (env vars, files) → Provider sends them in requests to Chronicle.  (Crosses the boundary between local environment and external Chronicle API.)
- Provider registers or updates resources → Chronicle endpoints.  (Crosses the boundary between provider and Chronicle’s backend.)

### APPLICATION THREATS
- **Threat**: Accidental exposure of Chronicle credentials in Terraform logs or state.
  - Description: If user sets credentials in clear text or if debugging logs inadvertently capture secrets, an attacker with read access to logs or state could steal them.
  - Impact: Compromise of Chronicle account, allowing unauthorized resource access and potential data exfiltration.
  - Affected Component: Provider code handling credentials and Terraform state handling.
  - Current Mitigations: Some environment variable and file-based separation (optionally). Terraform’s rule to not log sensitive attributes by default.
  - Missing Mitigations: Further code checks to ensure sensitive fields are always marked sensitive and not stored in plaintext states or logs.
  - Risk Severity: High

- **Threat**: Maliciously crafted resource fields (e.g., in feed definitions) leading to misconfiguration or partial injection.
  - Description: An attacker with control over certain feed parameters might attempt to inject unexpected characters or misuse fields (e.g., suspicious URIs, malicious S3 credentials).
  - Impact: Could cause erroneous data ingestion or unauthorized read/write if Chronicle API misinterprets these fields.
  - Affected Component: Resource feed code (e.g., resource_feed_*), which sends user-controlled fields directly to Chronicle.
  - Current Mitigations: Some parameter validation (e.g., region, URIs) in the provider.
  - Missing Mitigations: Additional strict validation on endpoints and credentials to reduce injection or misconfiguration risk.
  - Risk Severity: Medium

- **Threat**: Insufficient checks on rule text for YARA-based resources.
  - Description: Users can submit arbitrary YARA-L rule text (e.g., for `chronicle_rule`). If the code or Chronicle API doesn’t handle it safely, it could lead to denial-of-service or exploit attempts.
  - Impact: Potential resource disruption within the Chronicle platform or nonfunctional rules.
  - Affected Component: YARA rule parsing code and the backend call (`VerifyYARARule`).
  - Current Mitigations: The provider calls `VerifyYARARule` in Chronicle’s API to check syntax.
  - Missing Mitigations: The provider relies entirely on the Chronicle backend to reject malicious input; no local sanitization.
  - Risk Severity: Medium

- **Threat**: Misuse of environment variables containing secrets.
  - Description: If environment variables are misconfigured or accidentally committed, credentials become compromised.
  - Impact: Attacker can manage Chronicle resources.
  - Affected Component: Provider environment variable usage.
  - Current Mitigations: Documentation encouraging secure environment variable handling.
  - Missing Mitigations: Additional warnings or checks in code (e.g., detection of default placeholder strings).
  - Risk Severity: High

## DEPLOYMENT THREAT MODEL

### ASSETS
- **Deployed Provider Binary**: The compiled plugin binary that runs with Terraform on a user’s workstation or CI environment.
- **Workstation / CI Environment**: The environment that executes Terraform and the provider, holding credentials in memory and local config.

### TRUST BOUNDARIES
- Boundary between the **Local Machine / CI** and **Terraform Provider** (the plugin runs as an external process).
- Boundary between the **Provider** and **Chronicle Cloud** (network calls containing secrets).

### DEPLOYMENT THREATS
- **Threat**: Untrusted CI environment revealing credentials.
  - Description: If a CI pipeline logs environment variables or if ephemeral storage is publicly readable, an attacker could read Chronicle credentials.
  - Impact: Full compromise of Chronicle API.
  - Affected Component: Deployment environment that handles environment variables, the provider binary.
  - Current Mitigations: Typical secure CI/CD best practices are recommended, but not enforced by the code.
  - Missing Mitigations: Additional encryption or secrets-management solutions recommended in sensitive pipelines.
  - Risk Severity: High

- **Threat**: Unsigned or tampered provider binaries in local deployment.
  - Description: If the user runs a provider binary from an untrusted source, an attacker could embed malicious logic.
  - Impact: Potential code execution, credential theft, or resource manipulation.
  - Affected Component: The distributed provider binary.
  - Current Mitigations: Provider is typically fetched from official releases.
  - Missing Mitigations: No direct signature verification built into the code.
  - Risk Severity: Medium

## BUILD THREAT MODEL

### ASSETS
- **Source Code**: The Go code in this repository.
- **Build Pipeline**: Tools like `make`, `go`, and `goreleaser` that produce release binaries.
- **Release Artifacts**: The binaries published via GitHub Actions for use in Terraform.

### TRUST BOUNDARIES
- Boundary between the **Source Repository** (GitHub) and the **Build System** (GitHub Actions, local machine).
- Boundary between the **Build System** (which compiles code) and the **Release Channels** (GitHub Releases).

### BUILD THREATS
- **Threat**: Unauthorized commit or malicious PR merges injecting backdoors.
  - Description: An attacker modifies the code to steal secrets or cause resource manipulation at runtime.
  - Impact: End users of the provider unknowingly run malicious code.
  - Affected Component: Source repository.
  - Current Mitigations: Standard GitHub permissions and code review.
  - Missing Mitigations: Additional gating or build pipeline security checks (e.g., mandatory code review, restricted merges).
  - Risk Severity: High

- **Threat**: Compromise of automation secrets (like GITHUB_TOKEN) in release workflows.
  - Description: Attacker modifies `release.yaml` or uses stolen tokens to publish Trojaned binaries.
  - Impact: Provides a corrupted provider to unsuspecting users.
  - Affected Component: GitHub Action secrets, goreleaser context.
  - Current Mitigations: Minimal default GitHub security.
  - Missing Mitigations: Fine-grained separation of duties for release tokens, extra checks on release artifacts.
  - Risk Severity: Medium

## QUESTIONS & ASSUMPTIONS
- It is assumed the user keeps environment variables or credential files private and secure.
- It is assumed the user verifies the authenticity of provider binaries from official releases.
- It is assumed that Chronicle’s API will reject malicious or malformed requests beyond basic provider validations.
- Are there plans to further mark credentials as sensitive in Terraform to avoid them ending in state files?
- Are there additional upstream pipeline security measures or code signing for official releases?
