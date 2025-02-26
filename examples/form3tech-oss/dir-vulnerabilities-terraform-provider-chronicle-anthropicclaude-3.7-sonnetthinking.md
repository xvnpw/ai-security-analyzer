# VULNERABILITIES

## Sensitive Credentials Stored in Terraform State

### Vulnerability name
Unencrypted Storage of Sensitive Credentials in Terraform State

### Description
The Chronicle Terraform provider stores sensitive credentials (such as AWS access keys, Azure shared keys, Okta API tokens, Office 365 client secrets, etc.) directly in the Terraform state file in plaintext. While these fields are marked as "sensitive" to prevent display in logs and plan outputs, they are still stored unencrypted in the state file itself.

To trigger this vulnerability:
1. Configure any Chronicle feed resource that requires authentication credentials (e.g., chronicle_feed_amazon_s3, chronicle_feed_azure_blobstore, chronicle_feed_okta_system_log)
2. Apply the Terraform configuration
3. The provider will store the sensitive credentials in the Terraform state file
4. Anyone with access to the state file can extract the plaintext credentials

### Impact
An attacker who gains access to the Terraform state file can extract credentials for multiple cloud services, including:
- AWS access keys and secret keys
- Azure storage shared keys and SAS tokens
- Office 365 client secrets
- Okta API tokens
- Proofpoint authentication secrets
- Qualys VM credentials
- Thinkst Canary authentication tokens

With these credentials, an attacker could gain unauthorized access to these services, potentially exfiltrating data or compromising the security of the entire infrastructure. The impact is particularly severe because these credentials typically have broad permissions to the services they authenticate with.

### Vulnerability rank
High

### Currently implemented mitigations
The provider marks sensitive fields with `Sensitive: true`, which prevents these values from being displayed in logs and plan outputs. For example:

```go
"secret_access_key": {
    Type:        schema.TypeString,
    Required:    true,
    Sensitive:   true,
    ValidateDiagFunc: validateAWSSecretAccessKey,
    Description: `This is the 40 character access key associated with your Amazon IAM account.`,
},
```

However, this only prevents display in logs and doesn't encrypt or protect the values in the state file itself.

### Missing mitigations
1. The provider should use Terraform's built-in mechanisms for handling sensitive data more securely
2. For AWS credentials, the provider could support AssumeRole functionality to use temporary credentials
3. The provider should clearly document the risks of storing credentials in state and provide guidance on securing state files
4. The provider could support retrieving credentials from secure external sources (like HashiCorp Vault) at runtime
5. The provider could support authentication methods that don't require long-lived credentials where possible

### Preconditions
- The attacker must have access to the Terraform state file
- The state file must contain resources that use sensitive credentials
- The state file could be exposed through:
  - Insecure storage of state files in version control
  - Unsecured remote state (e.g., S3 bucket without proper access controls)
  - Access to shared file systems or CI/CD systems where state is managed

### Source code analysis
The Chronicle provider defines multiple resources that accept sensitive credentials:

In `resource_feed_amazon_s3.go`, AWS credentials are defined:
```go
"authentication": {
    Type:        schema.TypeList,
    Required:    true,
    MaxItems:    1,
    Description: `AWS authentication details.`,
    Elem: &schema.Resource{
        Schema: map[string]*schema.Schema{
            "region": {
                Type:        schema.TypeString,
                Required:    true,
                Description: `The region where the S3 bucket resides...`,
            },
            "access_key_id": {
                Type:             schema.TypeString,
                Required:         true,
                ValidateDiagFunc: validateAWSAccessKeyID,
                Description:      `This is the 20 character ID associated with your Amazon IAM account.`,
            },
            "secret_access_key": {
                Type:             schema.TypeString,
                Required:         true,
                Sensitive:        true,
                ValidateDiagFunc: validateAWSSecretAccessKey,
                Description:      `This is the 40 character access key associated with your Amazon IAM account.`,
            },
        },
    },
},
```

In the newly provided files, we see similar patterns in:

`resource_feed_thinkst_canary.go`:
```go
"value": {
    Type:        schema.TypeString,
    Required:    true,
    Sensitive:   true,
    Description: `Thinkst Canary authentication value.`,
},
```

And in `resource_feed_qualys_vm_test.go`, we can see the testing code handling credentials that would be stored in state:
```go
testAccCheckChronicleFeedQualysVMAuthUpdated(t, rootRef, user1, secret1),
```

When a user runs `terraform apply`, these credentials are stored in the `terraform.tfstate` file. While not directly visible in the code, we can see in test files like `resource_feed_amazon_s3_test.go` that the provider is storing credentials in state:

```go
resource.TestCheckResourceAttr(rootRef, "details.0.authentication.0.access_key_id", sqsAccesKeyID),
resource.TestCheckResourceAttr(rootRef, "details.0.authentication.0.secret_access_key", sqsSecretAccessKey),
```

In `flattenDetailsFromReadOperation` functions across the provider's code, credentials are included in the map that gets stored in state, for example in `resource_feed_amazon_s3.go`:

```go
return []map[string]interface{}{{
    "s3_uri":                readS3Conf.URI,
    "s3_source_type":        readS3Conf.SourceType,
    "source_delete_options": originalS3Conf.SourceDeleteOptions,
    "authentication": []map[string]interface{}{{
        "region":            originalS3Conf.Authentication.Region,
        "access_key_id":     originalS3Conf.Authentication.AccessKeyID,
        "secret_access_key": originalS3Conf.Authentication.SecretAccessKey,
    }},
}}
```

### Security test case
To test this vulnerability:

1. Create a Terraform configuration using the Chronicle provider with credentials:
```hcl
provider "chronicle" {
  region = "europe"
  backstoryapi_credentials = "your_credential_json"
}

resource "chronicle_feed_amazon_s3" "test" {
  display_name = "test_feed"
  log_type     = "GITHUB"
  enabled      = true
  namespace    = "test"
  details {
    s3_uri                = "s3://test-bucket/"
    s3_source_type        = "FOLDERS_RECURSIVE"
    source_delete_options = "SOURCE_DELETION_NEVER"
    authentication {
      region            = "EU_WEST_1"
      access_key_id     = "AKIAIOSFODNN7EXAMPLE"
      secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
```

2. Run `terraform init` and `terraform apply` to create the resource

3. Examine the state file:
```bash
terraform show -json | grep -A 10 secret_access_key
```

4. Verify that the AWS secret access key is stored in plaintext in the state file

5. An external attacker with access to the state file could then extract these credentials:
```bash
cat terraform.tfstate | jq '.resources[] | select(.type=="chronicle_feed_amazon_s3") | .instances[].attributes.details[0].authentication[0].secret_access_key'
```

6. The attacker could then use these credentials to access the AWS account with the permissions granted to that key.

This test confirms that sensitive credentials are stored in plaintext in the Terraform state, representing a significant security risk if state files are not properly secured.
