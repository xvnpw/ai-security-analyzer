- **Vulnerability Name**: Command Injection via `phpCommand` Configuration
  **Description**:
  1. The extension allows users to configure the `phpCommand` setting, which is used to execute PHP code via shell commands.
  2. An attacker can provide a malicious repository with a `.vscode/settings.json` that sets `LaravelExtraIntellisense.phpCommand` to a malicious template (e.g., `sh -c "{code}; rm -rf /"`).
  3. When the extension executes `runPhp()`, it interpolates the user-provided `{code}` into the command, but the surrounding template can execute arbitrary shell commands before or after the PHP code.
  4. The malicious command is executed with the permissions of the user running VSCode, leading to RCE.

  **Impact**: An attacker can execute arbitrary shell commands on the victim's machine with the privileges of the VSCode process. This allows full system compromise, including data theft, crypto mining, or persistent access.

  **Vulnerability Rank**: Critical

  **Currently Implemented Mitigations**: None. The `phpCommand` is used as-is without validation or sanitization.

  **Missing Mitigations**:
  - Input validation to ensure the `phpCommand` template does not contain shell metacharacters or unsafe constructs.
  - Restricting the allowed command formats to prevent arbitrary code execution.

  **Preconditions**:
  - The victim must open a malicious repository containing a `.vscode/settings.json` with a malicious `phpCommand` configuration.
  - The extension must be configured to use the attacker's `phpCommand` setting.

  **Source Code Analysis**:
  - The `runPhp()` function in `helpers.ts` uses the `phpCommand` directly without validation:
    ```typescript
    let command = commandTemplate.replace("{code}", code);
    ```
  - The `phpCommand` is sourced from user configuration:
    ```typescript
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    ```

  **Security Test Case**:
  1. Create a malicious repository with `.vscode/settings.json` containing:
    ```json
    "LaravelExtraIntellisense.phpCommand": "sh -c 'echo Exploited > /tmp/exploit.txt && {code}'"
    ```
  2. Open the repository in VSCode and enable the extension.
  3. Trigger an operation that runs PHP code (e.g., view autocomplete).
  4. Verify that `/tmp/exploit.txt` is created, proving the injection worked.

---

- **Vulnerability Name**: Arbitrary File Inclusion via `basePathForCode` Configuration
  **Description**:
  1. The `projectPath()` function uses the `basePathForCode` configuration to construct paths to Laravel files.
  2. An attacker can set `basePathForCode` to a malicious directory (e.g., `/tmp/malicious`) via a malicious `.vscode/settings.json`.
  3. When the extension calls `runLaravel()`, it loads files like `vendor/autoload.php` from the attacker-controlled path.
  4. By placing a malicious `vendor/autoload.php` in the target directory, the attacker can execute arbitrary PHP code when the extension boots the Laravel app.

  **Impact**: The attacker can execute arbitrary PHP code in the context of the extension, leading to RCE or data exfiltration.

  **Vulnerability Rank**: High

  **Currently Implemented Mitigations**: None. The path is used directly without verification.

  **Missing Mitigations**:
  - Path validation to ensure `basePathForCode` points to a legitimate Laravel project directory.
  - Sandboxing or read-only access to restricted directories.

  **Preconditions**:
  - The victim must open a malicious repository with a `.vscode/settings.json` setting `basePathForCode` to a path under the attacker's control.
  - The malicious directory must contain a PHP payload in `vendor/autoload.php`.

  **Source Code Analysis**:
  - The `projectPath()` function uses `basePathForCode` directly:
    ```typescript
    let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
    // ...
    return basePathForCode + path;
    ```
  - The `runLaravel()` function includes paths like `vendor/autoload.php` built from this configuration:
    ```typescript
    require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';
    ```

  **Security Test Case**:
  1. Create a malicious repository with `.vscode/settings.json`:
    ```json
    "LaravelExtraIntellisense.basePathForCode": "/tmp/malicious"
    ```
  2. Place a malicious `vendor/autoload.php` in `/tmp/malicious` that writes to a file (e.g., `file_put_contents('/tmp/exploit.txt', "Exploited");`).
  3. Open the repo in VSCode and trigger a Laravel operation (e.g., route autocomplete).
  4. Check for `/tmp/exploit.txt` to confirm PHP code execution.
