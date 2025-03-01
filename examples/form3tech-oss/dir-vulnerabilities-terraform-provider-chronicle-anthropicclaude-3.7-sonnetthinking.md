# Vulnerabilities

Based on my analysis of the terraform-provider-chronicle code, I've identified the following high-severity vulnerabilities:

## 1. Insecure Custom Endpoint Configuration

**Vulnerability name**: Insecure Custom Endpoint Configuration

**Description**:
The provider allows users to configure custom endpoints for various APIs through configuration parameters like `alert_custom_endpoint`, `artifact_custom_endpoint`, etc. The validation function `validateCustomEndpoint` in `chronicle/validation.go` only verifies that the URI can be parsed, but doesn't enforce HTTPS:

```go
func validateCustomEndpoint(v interface{}, k cty.Path) diag.Diagnostics {
    u := v.(string)
    _, err := url.ParseRequestURI(u)
    if err != nil {
        return diag.FromErr(fmt.Errorf("%q cannot be validated", u))
    }
    return nil
}
```

Step-by-step exploitation:
1. An attacker with access to the Terraform configuration could modify a custom endpoint to use HTTP instead of HTTPS
2. The validation will accept the HTTP URL since it only checks if the URL can be parsed
3. The provider would then send sensitive credentials and data over an unencrypted connection
4. The attacker could capture this traffic through network sniffing

**Impact**:
If custom endpoints can be configured with HTTP instead of HTTPS, credentials (including AWS access keys, Azure storage keys, and other service credentials) would be transmitted in plaintext. This could lead to credential theft, unauthorized access to cloud resources, and data breaches. Given the provider handles authentication for multiple sensitive cloud services, the impact is severe.

**Vulnerability rank**: High

**Currently implemented mitigations**:
The code does have a validation function (`validateCustomEndpoint`), but it only checks if the URL can be parsed and doesn't enforce HTTPS.

**Missing mitigations**:
The validation function should enforce that all custom endpoints use HTTPS protocol and reject any HTTP URLs. Additionally, TLS certificate validation should be explicitly enforced to prevent man-in-the-middle attacks.

**Preconditions**:
- The user must have the ability to modify the Terraform configuration
- The validation function must not properly enforce HTTPS (confirmed)

**Source code analysis**:
In `provider.go`, custom endpoints are being configured:

```go
if endpoint, isCustom := customEndpoint(d, "events_custom_endpoint"); isCustom {
    client.WithEventsBasePath(endpoint)
}
if endpoint, isCustom := customEndpoint(d, "alert_custom_endpoint"); isCustom {
    client.WithAlertBasePath(endpoint)
}
// ... more similar code for other endpoints ...
```

The provider schema allows these custom endpoints to be configured with the validation function:

```go
"alert_custom_endpoint": {
    Type:             schema.TypeString,
    Optional:         true,
    Description:      `Custom URL to alert endpoint.`,
    ValidateDiagFunc: validateCustomEndpoint,
    DefaultFunc: schema.MultiEnvDefaultFunc([]string{
        "CHRONICLE_ALERT_CUSTOM_ENDPOINT",
    }, nil),
},
```

In `chronicle/validation.go`, we see the validation function only checks if the URL can be parsed:

```go
func validateCustomEndpoint(v interface{}, k cty.Path) diag.Diagnostics {
    u := v.(string)
    _, err := url.ParseRequestURI(u)
    if err != nil {
        return diag.FromErr(fmt.Errorf("%q cannot be validated", u))
    }
    return nil
}
```

There is no check to ensure the URL uses HTTPS.

**Security test case**:
1. Create a Terraform configuration using the Chronicle provider
2. Configure a custom endpoint using HTTP instead of HTTPS, e.g.:
   ```hcl
   provider "chronicle" {
     alert_custom_endpoint = "http://malicious-endpoint.com/api"
     # other required configuration
   }
   ```
3. Run `terraform plan` and observe if the configuration is accepted without errors
4. If accepted, run `terraform apply` and use a network traffic analyzer like Wireshark to monitor the traffic
5. Verify if sensitive data is being transmitted in plaintext over HTTP

## 2. Sensitive Credential Exposure in Authentication Handlers

**Vulnerability name**: Sensitive Credential Exposure in Authentication Handlers

**Description**:
The provider handles sensitive credentials for various cloud services (AWS, Azure, Google Cloud, etc.) and APIs. While these credentials are marked as sensitive in the Terraform schema, there appears to be limited protection against their exposure in logs, error messages, or during transmission.

Step-by-step exploitation:
1. An attacker with access to logs or error output from Terraform operations could identify instances where credentials are leaked
2. If credentials are included in error messages or debug output, they could be captured from logs
3. These captured credentials could then be used to access the underlying cloud services

**Impact**:
Exposure of cloud service credentials could lead to unauthorized access to S3 buckets, Azure storage accounts, and other sensitive cloud resources. This could result in data breaches, resource manipulation, or infrastructure compromise.

**Vulnerability rank**: High

**Currently implemented mitigations**:
The code does mark sensitive fields with `Sensitive: true` in the schema definition, which helps prevent exposure in Terraform state files and normal output. For example:

```go
"secret_access_key": {
    Type:             schema.TypeString,
    Required:         true,
    Sensitive:        true,
    ValidateDiagFunc: validateAWSSecretAccessKey,
    Description:      `This is the 40 character access key associated with your Amazon IAM account.`,
},
```

And in Thinkst Canary feed configuration (`resource_feed_thinkst_canary.go`):

```go
"value": {
    Type:        schema.TypeString,
    Required:    true,
    Sensitive:   true,
    Description: `Thinkst Canary authentication value.`,
},
```

**Missing mitigations**:
- Comprehensive error handling that prevents credential values from being included in error messages
- Explicit sanitization of log messages to remove sensitive data
- Encryption of credentials in memory when not in use

**Preconditions**:
- Error messages or debug logs must include credential values
- The attacker must have access to these logs or error outputs

**Source code analysis**:
While the code marks fields as sensitive, there's no systematic approach visible for preventing credential exposure in error messages. For example, in error handling functions like `HandleNotFoundError` in `chronicle/util.go`:

```go
func handleNotFoundError(err error, d *schema.ResourceData, resource string) error {
    if isGoogleAPIErrorWithCode(err, 404) {
        log.Printf("[WARN] Removing %s because it's gone", resource)
        // The resource doesn't exist anymore.
        d.SetId("")

        return nil
    }

    return fmt.Errorf(
        fmt.Sprintf("Error when reading or editing %s: {{err}}", resource), err)
}
```

If the underlying error contains credential information, it could potentially be exposed in logs.

In multiple feed resource implementations (such as Qualys VM, Thinkst Canary, AWS S3), sensitive credentials are handled through direct string assignments:

```go
func testAccCheckChronicleFeedQualysVM(displayName, enabled, namespace, labels, hostname, user, secret string) string {
    return fmt.Sprintf(
        `resource "chronicle_feed_qualys_vm" "test" {
            display_name = "%s"
            enabled = %s
            namespace = "%s"
            labels = {
                %s
            }
            details {
                hostname = "%s"
                authentication {
                    user = "%s"
                    secret = "%s"
                }
            }
            }`, displayName, enabled, namespace, labels, hostname, user, secret)
}
```

**Security test case**:
1. Create a Terraform configuration with incorrect credentials for an AWS S3 feed
```hcl
resource "chronicle_feed_amazon_s3" "test" {
  display_name = "test-s3-feed"
  log_type     = "GITHUB"
  enabled      = true
  namespace    = "test"
  details {
    s3_uri = "s3://invalid-bucket/"
    s3_source_type = "FOLDERS_RECURSIVE"
    source_delete_options = "SOURCE_DELETION_NEVER"
    authentication {
      region = "US_EAST_1"
      access_key_id = "AKIAIOSFODNN7EXAMPLE"  # test key
      secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # test secret
    }
  }
}
```
2. Run `terraform apply` with debugging enabled: `TF_LOG=DEBUG terraform apply`
3. Examine the debug output and error messages
4. Check if AWS credentials or other sensitive values appear in the logs or error output

These vulnerabilities require immediate attention due to their high impact and the sensitive nature of the credentials being handled by the provider.
