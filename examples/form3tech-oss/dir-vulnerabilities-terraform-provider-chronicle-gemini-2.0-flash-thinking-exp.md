### Vulnerability List

- Vulnerability Name: Potential Credential Exposure through Terraform State and Configuration Files
- Description:
    1.  A user configures the Terraform Chronicle provider, including sensitive credentials like AWS `secret_access_key`, Azure `shared_key`/`sas_token`, Okta API token, Proofpoint secret, or Microsoft Office 365 `client_secret`. These secrets are provided as plain text strings within the Terraform configuration files (e.g., `.tf` files) or as environment variables that might be logged or exposed.
    2.  Terraform stores the configuration and state of the infrastructure. Although sensitive attributes are marked as sensitive in the provider schema, the Terraform state file, and potentially the configuration files themselves, could be accessed by an attacker if proper access control is not in place.
    3.  An external attacker gains unauthorized access to the Terraform state file (e.g., through a compromised CI/CD pipeline, misconfigured storage backend for Terraform state, or insider threat) or to the Terraform configuration files stored in version control or backups.
    4.  The attacker extracts the sensitive credentials from the state or configuration files.
    5.  With these extracted credentials, the attacker can potentially gain unauthorized access to the integrated services (AWS, Azure, Okta, Proofpoint, Microsoft Office 365) or to the Chronicle instance itself, depending on the scope of the compromised credentials.
- Impact:
    Compromise of sensitive credentials can lead to:
    *   Unauthorized access to integrated cloud services (AWS, Azure, Okta, Proofpoint, Microsoft Office 365), potentially leading to data breaches, resource manipulation, or further attacks on those platforms.
    *   Unauthorized access to the Chronicle platform itself if Chronicle API credentials are compromised, allowing attackers to view logs, alerts, rules, and potentially manipulate security configurations within Chronicle.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    *   The Terraform provider schema marks sensitive fields (like `secret_access_key`, `shared_key`, `client_secret`, `value`, `secret`) as `Sensitive: true`. This instructs Terraform to redact these values in console output during `plan` and `apply` operations, and to mark them as sensitive in the state file.
    *   The `flattenDetailsFromReadOperation` functions in resource implementations (e.g., `resource_feed_amazon_s3.go`, `resource_feed_thinkst_canary.go`) are designed to replace authentication blocks with original values during read operations. This prevents the provider from inadvertently logging or displaying the secret values retrieved from the API during state refresh.
- Missing Mitigations:
    *   **Secret Management Integration:** The provider lacks integration with dedicated secret management solutions like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Secret Manager. This would allow users to reference secrets stored and managed securely outside of Terraform configuration and state files, instead of embedding them directly as plain text.
    *   **Guidance on Secure Secret Handling:** The documentation could be enhanced to provide explicit guidance to users on best practices for handling sensitive credentials when using the provider. This should include recommendations to avoid storing secrets directly in Terraform configuration files, to use secure state backends, and to implement robust access control for state files and configuration repositories.
- Preconditions:
    *   The user must configure the Terraform Chronicle provider to manage resources that require sensitive credentials.
    *   An attacker must gain unauthorized access to the Terraform state file or Terraform configuration files where these credentials are stored.
- Source Code Analysis:
    1.  **Schema Definition:** Resource schema definitions throughout the provider, such as in `chronicle/resource_feed_amazon_s3.go`, `chronicle/resource_feed_thinkst_canary.go`, and others, consistently define sensitive fields with `Sensitive: true`. For example, in `chronicle/resource_feed_amazon_s3.go`:
        ```go
        "secret_access_key": {
            Type:             schema.TypeString,
            Required:         true,
            Sensitive:        true,
            ValidateDiagFunc: validateAWSSecretAccessKey,
            Description:      `This is the 40 character access key associated with your Amazon IAM account.`,
        },
        ```
        Similar definitions are present for `secret` in `chronicle/resource_feed_qualys_vm.go`, `value` in `chronicle/resource_feed_thinkst_canary.go`, and other resources that handle credentials.

    2.  **Credential Handling in Provider Configuration and Client Initialization:** The `provider.go` file (not provided in PROJECT FILES, but assumed from previous analysis) and `client/client.go` show how credentials are handled. The `NewClient` function in `client/client.go` and related `With*Credentials` Options (e.g., `WithBigQueryAPICredentials`, `WithBackstoryAPICredentials`) configure the client using credentials passed either directly as strings, via files, or environment variables. The `GetCredentials` function in `client/client.go` details the logic for loading credentials from these different sources, including reading file contents using `pathOrContents` from `client/util.go`. This function is central to how the provider authenticates with Chronicle APIs.

    3.  **State Flattening:** The `flattenDetailsFromReadOperation` functions (e.g., in `chronicle/resource_feed_amazon_s3.go`, `chronicle/resource_feed_thinkst_canary.go`) aim to prevent accidental exposure of secrets during state refresh operations. They replace the authentication blocks in the read state with the original values from the configuration, as illustrated in `chronicle/resource_feed_thinkst_canary.go`:
        ```go
        // Default Case
        return []map[string]interface{}{{
            "hostname": readCanaryConf.Hostname,
            // replace authentication block with original values because they are not returned within a read request
            "authentication": []map[string]interface{}{{
                "key":   originalCanary.Authentication.HeaderKeyValues[0].Key,
                "value": originalCanary.Authentication.HeaderKeyValues[0].Value,
            },
            }},
        }
        ```

    4.  **Feed Configurations:** Files like `client/feed_amazon_s3.go`, `client/feed_azure_blobstore.go`, `client/feed_microsoft_office_365_management_activity.go`, `client/feed_okta_system_log.go`, `client/feed_proofpoint_siem.go`, `client/feed_qualys_vm.go`, and `client/feed_thinkst_canary.go` define the structure of various feed configurations. These files demonstrate how sensitive data like `SecretAccessKey`, `sharedKey`, `clientSecret`, and `secret` are part of the configuration schema and are intended to be passed to the Chronicle API for feed setup. This highlights the points where secrets are handled within the provider's code and could potentially be exposed if not managed carefully by the user.

    5.  **Limitations:** As previously noted, while `Sensitive: true` and state flattening offer some protection, they do not fully mitigate the risk of credential exposure if state files or configuration files are compromised. The configuration examples in `examples/resources/feed/amazon_s3/main.tf`, `examples/resources/feed/api/microsoft_office_365_management_activity/main.tf`, etc., clearly show secrets being embedded in plain text within Terraform configuration, illustrating the user-facing aspect of this vulnerability.

- Security Test Case:
    1.  **Setup:**
        *   Create a Terraform configuration file (e.g., `test.tf`) using the `chronicle_feed_amazon_s3` resource or `chronicle_feed_thinkst_canary` resource.
        *   Include valid, but **test/non-production** AWS `access_key_id` and `secret_access_key` or Thinkst Canary `value` in the configuration file as plain text strings.
        ```terraform
        # Example for chronicle_feed_amazon_s3
        resource "chronicle_feed_amazon_s3" "test_s3_feed" {
          display_name = "test-s3-feed"
          log_type     = "TEST_LOG_TYPE"
          enabled      = true
          details {
            s3_uri                = "s3://your-test-bucket/"
            s3_source_type        = "FOLDERS_RECURSIVE"
            source_delete_options = "SOURCE_DELETION_NEVER"
            authentication {
              region            = "eu-west-1"
              access_key_id     = "YOUR_TEST_ACCESS_KEY_ID"
              secret_access_key = "YOUR_TEST_SECRET_ACCESS_KEY"
            }
          }
        }

        # Example for chronicle_feed_thinkst_canary
        resource "chronicle_feed_thinkst_canary" "test_canary_feed" {
          display_name = "test-canary-feed"
          enabled      = true
          namespace    = "test"
          labels = {}
          details {
            hostname = "your-canary.tools"
            authentication {
              key   = "auth_token"
              value = "YOUR_TEST_THINKST_CANARY_TOKEN"
            }
          }
        }
        ```
        *   Initialize Terraform (`terraform init`) and apply the configuration (`terraform apply`).
    2.  **Capture State:**
        *   After successful application, retrieve the Terraform state file (e.g., `terraform state pull > terraform.tfstate` for local state, or retrieve from your configured remote backend).
    3.  **Analyze State File:**
        *   Open the state file (`terraform.tfstate`) in a text editor.
        *   Search for the relevant resource (e.g., `chronicle_feed_amazon_s3.test_s3_feed` or `chronicle_feed_thinkst_canary.test_canary_feed`).
        *   Within the attributes of this resource, locate the sensitive attribute (e.g., `details.0.authentication.0.secret_access_key` or `details.0.authentication.0.value`).
        *   Observe that while the value might be marked as sensitive, it is still present in the state file in some form (potentially obfuscated, but not securely encrypted in all cases, and in some cases, it might still be in plain text).
    4.  **Configuration File Analysis:**
        *   Open the Terraform configuration file (`test.tf`).
        *   Observe that the sensitive credential (e.g., `secret_access_key` or `value`) is present in plain text within the configuration file.
    5.  **Cleanup:**
        *   Destroy the Terraform infrastructure (`terraform destroy`).
    6.  **Expected Result:**
        *   The test confirms that secrets, although marked as sensitive by the Terraform provider, are initially stored in plain text in configuration and persist in the state file. Unauthorized access to either the configuration or the state file can lead to credential exposure. This test highlights the ongoing risk of managing secrets in IaC and underscores the need for secret management integration and improved user guidance.
