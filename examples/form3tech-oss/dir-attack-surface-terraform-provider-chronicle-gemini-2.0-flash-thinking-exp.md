# Attack Surface Analysis for Terraform Chronicle Provider

- Attack Surface: **Credential Exposure in Terraform Configuration Files**
  - Description: Terraform configuration files, which are often stored in version control systems, can contain sensitive credentials in plaintext if users directly embed secrets within the configuration.
  - How `terraform-provider-chronicle` contributes to the attack surface: The provider's documentation examples continue to show credentials being directly embedded in the Terraform configuration for simplicity, as seen in the updated resource documentation and examples for `chronicle_feed_qualys_vm` and `chronicle_feed_thinkst_canary`.  The resource definition and test files (`resource_feed_qualys_vm.go`, `resource_feed_thinkst_canary.go`, `*_test.go`) confirm the use of `user`, `secret`, `value`, `key` attributes for authentication, which are potential candidates for hardcoding in configurations.
  - Example:
    ```terraform
    provider "chronicle" {
      backstoryapi_credentials = "YOUR_BACKSTORY_CREDENTIALS_JSON_STRING"
      region                   = "europe"
    }

    resource "chronicle_feed_qualys_vm" "qualys_vm" {
      details {
        authentication {
          user   = "YOUR_QUALYS_USER"
          secret = "YOUR_QUALYS_SECRET"
        }
      }
    }

    resource "chronicle_feed_thinkst_canary" "thinkst_canary" {
      details {
        authentication {
          value = "YOUR_THINKST_CANARY_TOKEN"
        }
      }
    }
    ```
  - Impact: High. If configuration files are compromised, attackers can gain access to Chronicle APIs and potentially connected systems (Qualys, Thinkst Canary, etc.). This could lead to data breaches, unauthorized data ingestion, or disruption of security monitoring, and now extends to potentially compromising Qualys VM and Thinkst Canary assets if their respective credentials are exposed.
  - Risk Severity: High
  - Current Mitigations: Partially mitigated. Documentation still mentions environment variables and credential files as alternatives. However, direct embedding examples persist, and the provider doesn't enforce secure credential management. The newly added resources for Qualys VM and Thinkst Canary feeds also rely on similar authentication patterns, inheriting the same risks.
  - Missing Mitigations:
    - **Stronger emphasis in documentation on secure credential management practices**:  Documentation for new resources like `chronicle_feed_qualys_vm` and `chronicle_feed_thinkst_canary` must also prominently warn against direct credential embedding and reinforce secure alternatives.
    - **Consider adding input validation or warnings within the provider**:  Extend potential warnings to resource attributes like `details.authentication.user`, `details.authentication.secret`, and `details.authentication.value` in resources like `chronicle_feed_qualys_vm` and `chronicle_feed_thinkst_canary`.

- Attack Surface: **Credential Exposure through Environment Variables**
  - Description: Using environment variables for credentials, while better than direct embedding, remains a risk if not managed securely. Environment variables can be logged, exposed in process listings, or accessed by unauthorized entities.
  - How `terraform-provider-chronicle` contributes to the attack surface: The provider continues to support environment variables for API credentials. The new resources don't change this aspect, and environment variables remain a documented configuration method.
  - Example: Setting `CHRONICLE_BACKSTORY_CREDENTIALS`, `CHRONICLE_QUALYSVM_USER`, `CHRONICLE_THINKSTCANARY_TOKEN` environment variables.
  - Impact: Medium. Compromised Terraform execution environments or exposed environment variables can lead to unauthorized Chronicle API access. The impact now includes potential access to Qualys VM and Thinkst Canary data and systems.
  - Risk Severity: Medium
  - Current Mitigations: Partially mitigated. Documentation mentions environment variables. Base64 encoding is mentioned but is weak obfuscation. No provider enforcement of secure environment variable management. This applies equally to credentials for new resources.
  - Missing Mitigations:
    - **Documentation should include best practices for environment variable security**:  Specifically mention securing environment variables when used for Qualys VM and Thinkst Canary credentials.
    - **Consider recommending credential files or external secret stores over environment variables in many scenarios**:  This recommendation is still valid and should be reinforced for all resource types, including the newly added ones.

- Attack Surface: **Insecure Storage of Sensitive Data in Terraform State Files**
  - Description: Terraform state files store resource configurations in plaintext, potentially including sensitive data like API credentials.
  - How `terraform-provider-chronicle` contributes to the attack surface: The provider manages resources that require credentials, and these credentials, even if passed via variables or environment variables, might be stored in the state file. The new resources for Qualys VM and Thinkst Canary also handle credentials that could end up in state. Test files (`*_test.go`) show examples of ignoring `details.0.authentication.0.user`, `details.0.authentication.0.secret`, `details.0.authentication.0.value`, `details.0.authentication.0.key` during state import verification, suggesting these are treated as sensitive, but the underlying risk of state file exposure remains.
  - Example: Terraform state file might contain attributes related to `chronicle_feed_qualys_vm` or `chronicle_feed_thinkst_canary` resources, potentially including authentication details if not properly marked as sensitive.
  - Impact: Medium. Compromised state files can expose sensitive information, including credentials for Chronicle, Qualys VM, and Thinkst Canary, even if not directly in configuration.
  - Risk Severity: Medium
  - Current Mitigations: Partially mitigated. Terraform SDK's `Sensitive: true` attribute marking is used. Test files indicate sensitivity of authentication attributes. However, state file encryption depends on the backend and is not guaranteed secrecy.
  - Missing Mitigations:
    - **Documentation should warn about state file security**:  Emphasize state file security for all resources, including new feed types and RBAC subject and reference list resources, as state files can store configurations related to these.
    - **Review provider code to ensure sensitive attributes are correctly marked**:  Verify that `Sensitive: true` is correctly applied to all credential-related attributes in `chronicle_feed_qualys_vm`, `chronicle_feed_thinkst_canary`, and potentially other resources if they handle sensitive data.

- Attack Surface: **Man-in-the-Middle Attacks via Custom Endpoints**
  - Description: The provider allows custom endpoints for Chronicle APIs, risking MITM attacks if HTTP is used or endpoints are compromised.
  - How `terraform-provider-chronicle` contributes to the attack surface: Custom endpoint configuration options persist. No changes in new files to mitigate this.
  - Example: Configuring `events_custom_endpoint` to `http://example.com/events`.
  - Impact: Medium. Insecure custom endpoints can lead to intercepted communications and compromised API interactions. Impact remains limited to the specific API with a custom endpoint.
  - Risk Severity: Medium
  - Current Mitigations: No direct provider mitigation. Documentation mentions custom endpoints but lacks explicit HTTPS warnings.
  - Missing Mitigations:
    - **Documentation should strongly recommend HTTPS for custom endpoints**:  This recommendation is still crucial and should be highlighted in the general provider documentation and any resource-specific documentation where custom endpoints might be relevant (though less likely for feed resources).
    - **Input validation for custom endpoints**:  Provider could validate `https://` for custom endpoint URLs and warn on HTTP usage.

- Attack Surface: **Debug Port Exposure**
  - Description: `debug.sh` script exposes a debug port, risking unauthorized remote debugging access if exposed to a network.
  - How `terraform-provider-chronicle` contributes to the attack surface: `debug.sh` script remains in the project. No changes in new files to mitigate this.
  - Example: Running `debug.sh` on a publicly accessible development server.
  - Impact: Medium. Exposed debug port can allow attackers to inspect provider internals and potentially extract sensitive information or manipulate behavior. Risk primarily in development/testing if debugging is not secured.
  - Risk Severity: Medium
  - Current Mitigations: Implicit mitigation by debuggers being for development, not production. `debug.sh` not for normal operation.
  - Missing Mitigations:
    - **Documentation for `debug.sh` should include security warnings**:  Warnings about debug port exposure risks should be maintained and potentially reinforced in `README.md` or comments in `debug.sh`.
    - **Consider removing or securing `debug.sh` further**:  Restricting `debug.sh` to `localhost` by default or requiring a flag for network listening remains a valid mitigation consideration.

These attack surfaces remain relevant and are not significantly changed by the newly added resources. The focus should be on implementing the missing mitigations, particularly enhancing documentation around secure credential management and state file security, and considering input validation for custom endpoints and debug port security.
