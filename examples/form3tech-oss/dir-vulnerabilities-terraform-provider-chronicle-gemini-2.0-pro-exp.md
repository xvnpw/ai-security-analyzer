# Chronicle Terraform Provider Vulnerabilities

## Vulnerability: Sensitive Data Exposure in Terraform State (AWS Secret Access Key)

- **Description:** The `chronicle_feed_amazon_s3` and `chronicle_feed_amazon_sqs` resources store the AWS `secret_access_key` in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing this sensitive information to unauthorized users who have access to the state file or console output.
- **Impact:** High. Exposure of the AWS secret access key could allow an attacker to gain unauthorized access to the AWS account, potentially leading to data breaches, data modification, or service disruption.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - The `secret_access_key` attribute is marked as `Sensitive: true` in the schema. This instructs Terraform to redact the value from most outputs.
- **Missing Mitigations:**
  - Changes to `secret_access_key` are still displayed in the plan output.
  - The state file itself is not encrypted.
  - There is no mechanism to rotate the secret access key automatically.
- **Preconditions:**
    - An attacker needs access to the Terraform state file or the console output of `terraform plan`.
- **Source Code Analysis:**
  - The `resource_feed_amazon_s3.go` and `resource_feed_amazon_sqs.go` files define the schema for the resources.
  - Both resources include a `secret_access_key` field within the `authentication` block:
  ```go
  "secret_access_key": {
      Type:             schema.TypeString,
      Required:         true,
      Sensitive:        true,
      ValidateDiagFunc: validateAWSSecretAccessKey,
      Description:      `This is the 40 character access key associated with your Amazon IAM account.`,
  },
  ```
  - The `flattenDetailsFromReadOperation` function in both files retrieves the `secret_access_key` from the API response and sets it in the state.
  - The `TestAccChronicleFeedAmazonS3_UpdateAuth` and `TestAccChronicleFeedAmazonSQS_UpdateAuth` functions in test files demonstrate that the `secret_access_key` is updated in the plan and apply and it will be shown in plan output as a diff.
- **Security Test Case:**
    1.  Configure the `chronicle_feed_amazon_s3` or `chronicle_feed_amazon_sqs` resource with valid AWS credentials.
    2.  Run `terraform apply` to create the resource.
    3.  Modify the `secret_access_key` value in the Terraform configuration.
    4.  Run `terraform plan`.
    5.  **Observe:** The plan output will show a diff that includes the old and new `secret_access_key`, although marked as `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Azure Credentials)

- **Description:** The `chronicle_feed_azure_blobstore` resource stores either `shared_key` or `sas_token` in plain text within the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing this sensitive information to unauthorized users.
- **Impact:** High. Exposure of the Azure shared key or SAS token could allow an attacker to gain unauthorized access to the Azure Blob Storage account, potentially leading to data breaches, data modification, or service disruption.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The `shared_key` and `sas_token` attributes are marked as `Sensitive: true` in the schema. This instructs Terraform to redact the value from most output.
- **Missing Mitigations:**
  - Changes to `shared_key` or `sas_token` are still displayed in plan output.
  - The state file itself is not encrypted.
  - There is no mechanism to rotate the shared key or SAS token automatically.
- **Preconditions:**
    - An attacker needs access to the Terraform state file or console output of `terraform plan`.
- **Source Code Analysis:**
    - The `resource_feed_azure_blobstore.go` file defines the schema for the resource.
    - The resource includes a `shared_key` or `sas_token` field within the `authentication` block.
    ```go
        "authentication": {
            Type:        schema.TypeList,
            Required:    true,
            MaxItems:    1,
            Description: `Azure authentication details.`,
            Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                    "shared_key": {
                        Type:        schema.TypeString,
                        Optional:    true,
                        Sensitive:   true,
                        Description: `A shared key, a 512-bit random string in base64 encoding, authorized to access Azure Blob Storage. Required if not specifying an SAS Token.`,
                    },
                    "sas_token": {
                        Type:        schema.TypeString,
                        Optional:    true,
                        Sensitive:   true,
                        Description: `A Shared Access Signature authorized to access the Azure Blob Storage container.`,
                    },
                },
            },
        },
    ```
  - The `flattenDetailsFromReadOperation` function retrieves the credential and sets it in state.
  - The `TestAccChronicleFeedAzureBlobStore_UpdateAuth` function in test file demonstrates that the `shared_key` is updated in plan and apply and it will be shown in plan output as diff.
- **Security Test Case:**
    1. Configure the `chronicle_feed_azure_blobstore` resource with valid Azure credentials (either `shared_key` or `sas_token`).
    2. Run `terraform apply` to create the resource.
    3. Modify the credential value in the Terraform configuration.
    4. Run `terraform plan`.
    5. **Observe:** The plan output will show a diff that includes the old and new credential, although marked as `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Microsoft Office 365 Client Secret)

- **Description:** The `chronicle_feed_microsoft_office_365_management_activity` resource stores the `client_secret` in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing this sensitive information to unauthorized users.
- **Impact:** High. Exposure of the client secret could allow an attacker to gain unauthorized access to the Microsoft Office 365 Management Activity API, potentially leading to data breaches or unauthorized actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - The `client_secret` attribute is marked as `Sensitive: true` in the schema.
- **Missing Mitigations:**
  - Changes to `client_secret` are still displayed in plan output.
  - The state file itself is not encrypted.
  - There is no mechanism for automatic rotation of the client secret.
- **Preconditions:**
    - An attacker needs access to the Terraform state file or the console output of `terraform plan`.
- **Source Code Analysis:**
    - The `resource_feed_microsoft_office_365_management_activity.go` file defines the schema for the resource.
    - The resource includes a `client_secret` field within the `authentication` block:

    ```go
    "client_secret": {
        Type:        schema.TypeString,
        Required:    true,
        Sensitive:   true,
        Description: `OAuth client secret.`,
    },
    ```
    - The `flattenDetailsFromReadOperation` function retrieves the `client_secret` from the API response (or original configuration) and sets it in the state.
    - The `TestAccChronicleFeedMicrosoftOffice365ManagementActivity_UpdateAuth` function in test file demonstrates that the `client_secret` is updated in plan and apply, and it will be shown in plan output as a diff.

- **Security Test Case:**
    1. Configure the `chronicle_feed_microsoft_office_365_management_activity` resource with a valid `client_secret`.
    2. Run `terraform apply` to create the resource.
    3. Modify the `client_secret` value in the Terraform configuration.
    4. Run `terraform plan`.
    5.  **Observe:** The plan output will show a diff including the old and new `client_secret`, although marked as `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Okta API Token)

- **Description:** The `chronicle_feed_okta_system_log` and `chronicle_feed_okta_users` resources store the Okta API `value` (token) in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing it to unauthorized users.
- **Impact:** High - Exposure of the Okta API token could grant an attacker unauthorized access to the Okta API, leading to potential data breaches, user impersonation, or configuration changes.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - The `value` attribute (representing the Okta API token) is marked as `Sensitive: true` in the schema.
- **Missing Mitigations:**
  - Changes to `value` are still displayed in plan output.
  - The state file is not encrypted.
  - No mechanism exists for automatic token rotation.
- **Preconditions:**
  - Attacker needs access to the Terraform state file or the console output of `terraform plan`.
- **Source Code Analysis:**
  - `resource_feed_okta_system_log.go` and `resource_feed_okta_users.go` define the schemas for the resources.
  - Both resources include a `value` field within the `authentication` block, representing the API token:

  ```go
  "value": {
      Type:        schema.TypeString,
      Required:    true,
      Sensitive:   true,
      Description: `Okta API token.`,
  },
  ```
  - The `flattenDetailsFromReadOperation` function in both files retrieves the `value` and stores it in state.
  - The `TestAccChronicleFeedOktaSystemLog_UpdateAuth` and `TestAccChronicleFeedOktaUsers_UpdateAuth` functions in test files demonstrate that the `value` is updated in plan and apply, and it will be shown in plan output as diff.
- **Security Test Case:**
  1. Configure either `chronicle_feed_okta_system_log` or `chronicle_feed_okta_users` with a valid Okta API token.
  2. Run `terraform apply`.
  3. Modify the `value` (API token) in the configuration.
  4. Run `terraform plan`.
  5. **Observe:** The plan output displays a diff including the old and new token values, although marked as `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Proofpoint Credentials)

- **Description:** The `chronicle_feed_proofpoint_siem` resource stores the Proofpoint `secret` in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing it to unauthorized users.
- **Impact:** High - Exposure of the Proofpoint secret could grant an attacker unauthorized access to the Proofpoint SIEM API, leading to potential data breaches or unauthorized actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The `secret` attribute is marked as `Sensitive: true` in the schema.
- **Missing Mitigations:**
  - Changes to `secret` are still displayed in plan output.
    - The state file is not encrypted.
    - No mechanism exists for automatic secret rotation.
- **Preconditions:**
    - Attacker needs access to the Terraform state file or console output of `terraform plan`.
- **Source Code Analysis:**
    -  `resource_feed_proofpoint_siem.go` defines the schema.
    -  The resource includes a `secret` field within the `authentication` block:
    ```go
    "secret": {
        Type:        schema.TypeString,
        Required:    true,
        Sensitive:   true,
        Description: `Proofpoint secret.`,
    },
    ```
    - The `flattenDetailsFromReadOperation` function retrieves and stores the `secret` in the state.
   - The `TestAccChronicleProofpointSIEM_UpdateAuth` function in test file demonstrates that the `secret` is updated in plan and apply, and it will be shown in plan output as a diff.
- **Security Test Case:**
    1. Configure `chronicle_feed_proofpoint_siem` with valid Proofpoint credentials.
    2. Run `terraform apply`.
    3. Modify the `secret` value in the configuration.
    4. Run `terraform plan`.
    5. **Observe:** The plan output will show a diff including the old and new `secret`, although marked `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Qualys VM Credentials)

- **Description:** The `chronicle_feed_qualys_vm` resource stores the Qualys VM `secret` (password) in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing this sensitive information to unauthorized users.
- **Impact:** High. Exposure of the Qualys VM password could allow an attacker to gain unauthorized access to the Qualys VM API, potentially leading to data breaches or unauthorized actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The `secret` attribute is marked as `Sensitive: true` in the schema.
- **Missing Mitigations:**
  - Changes to `secret` are still displayed in plan output.
    - The state file itself is not encrypted.
    - There is no mechanism for automatic rotation of the Qualys VM password.
- **Preconditions:**
    - An attacker needs access to the Terraform state file or the console output of `terraform plan`.
- **Source Code Analysis:**
    - The `resource_feed_qualys_vm.go` file defines the schema for the `chronicle_feed_qualys_vm` resource.
    - The resource includes a `secret` (password) field within the `authentication` block:

    ```go
    "secret": {
        Type:        schema.TypeString,
        Required:    true,
        Sensitive:   true,
        Description: `Password.`,
    },
    ```
    - The `flattenDetailsFromReadOperation` function retrieves the `secret` and stores it in the state.
    - The `TestAccChronicleFeedQualysVM_UpdateAuth` function in `resource_feed_qualys_vm_test.go` demonstrates that updating authentication will expose the secret in plan output.
- **Security Test Case:**
    1. Configure the `chronicle_feed_qualys_vm` resource with a valid Qualys VM username and password.
    2. Run `terraform apply` to create the resource.
    3. Modify the `secret` (password) value in the Terraform configuration.
    4. Run `terraform plan`.
    5. **Observe:** The plan output displays a diff, including the old and new `secret` values, although marked `<sensitive>`, the context reveals it is a secret.

## Vulnerability: Sensitive Data Exposure in Terraform State (Thinkst Canary Token)

- **Description:** The `chronicle_feed_thinkst_canary` resource stores the Thinkst Canary authentication `value` (token) in the Terraform state file. While marked as sensitive, changes to this value will be displayed in terraform plan output, potentially exposing this sensitive information to unauthorized users.
- **Impact:** High. Exposure of the Thinkst Canary token could allow an attacker to gain unauthorized access to the Thinkst Canary API, potentially leading to data breaches, configuration changes, or disruption of the Canary service.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The `value` attribute is marked as `Sensitive: true` in the schema.
- **Missing Mitigations:**
  - Changes to `value` are still displayed in plan output.
    - The state file itself is not encrypted.
    - There is no mechanism for automatic rotation of the Thinkst Canary token.
- **Preconditions:**
    - An attacker needs access to the Terraform state file or the console output of `terraform plan`.
- **Source Code Analysis:**
    - The `resource_feed_thinkst_canary.go` file defines the schema for the `chronicle_feed_thinkst_canary` resource.
    - The resource includes a `value` (token) field within the `authentication` block:

    ```go
     "value": {
         Type:        schema.TypeString,
         Required:    true,
         Sensitive:   true,
         Description: `Thinkst Canary authentication value.`,
     },
    ```

    - The `flattenDetailsFromReadOperation` function retrieves the `value` and stores it in the state.
    - The `TestAccChronicleFeedThinkstCanary_UpdateAuth` function in `resource_feed_thinkst_canary_test.go` demonstrates that updating the authentication `value` will expose secret in plan output.
- **Security Test Case:**
    1. Configure the `chronicle_feed_thinkst_canary` resource with a valid Thinkst Canary token.
    2. Run `terraform apply` to create the resource.
    3. Modify the `value` (token) in the Terraform configuration.
    4. Run `terraform plan`.
    5. **Observe:** The plan output displays a diff, including the old and new `value` token, although marked `<sensitive>`, the context reveals it is a secret.
