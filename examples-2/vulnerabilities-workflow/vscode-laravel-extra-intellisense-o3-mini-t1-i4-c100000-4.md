# Vulnerabilities List

---

## 1. Vulnerability: Arbitrary PHP Command Injection via Workspace Configuration Override

**Description:**
- The extension retrieves the command template for running PHP code from the workspace configuration key `LaravelExtraIntellisense.phpCommand`.
- A malicious repository can include a `.vscode/settings.json` file that overrides this value with a manipulated command template.
- When the extension calls the helper method (in `Helpers.runPhp`), it replaces the `{code}` placeholder with generated PHP code. If the template has been modified to append shell commands (for example, by inserting an extra command delimiter such as a semicolon), these extra commands will be executed on the local system.
- **Triggering scenario:** The attacker provides a repository with a modified settings file (or forces the user to use a malicious workspace) so that when an auto‐completion action is initiated, the altered configuration is read and the resulting command injected into the shell gets executed.

**Impact:**
- An attacker may gain arbitrary command execution on the victim’s machine with the privileges of the user running VSCode.
- The attacker can perform system-level actions, exfiltrate data, or even modify/delete files.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension simply reads the configuration value using the VSCode API without validating or sanitizing the value.
- There is only a reminder in the README to review configuration but no automatic check to ensure the command template is safe.

**Missing Mitigations:**
- No input or format validation is performed on the user‐overridable `phpCommand` string.
- The extension does not enforce a whitelist of allowed command templates or require additional user confirmation when using workspace settings from an untrusted source.
- Sanitization of the command string before using it in a shell call via `cp.exec` is missing.

**Preconditions:**
- The victim opens a repository that contains a malicious `.vscode/settings.json` file (or equivalent workspace configuration) that overwrites the default `phpCommand` with an injected payload.

**Source Code Analysis:**
- In `Helpers.runPhp`, the command template is retrieved via:
  ```js
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  ```
- No sanitization or validation is applied to the retrieved value.
- The placeholder `{code}` is replaced with generated PHP code (after minimal escaping), resulting in a command that is passed directly to `cp.exec`.
- **Example:** If an attacker supplies a template such as:
  ```
  php -r "{code}"; rm -rf /
  ```
  the substitution causes the additional command (`rm -rf /`) to be executed.

**Security Test Case:**
1. Create a test repository with a `.vscode/settings.json` file containing an override:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo MALICIOUS_EXECUTED"
   }
   ```
2. Open this repository in VSCode with the extension enabled.
3. Trigger an action that causes the extension to run PHP code (for example, by invoking auto-completion in a PHP or Blade file that calls one of the functions such as `route` or `config`).
4. Check the output channel and/or command output for the text “MALICIOUS_EXECUTED”.
5. The presence of this output will demonstrate that the injected command is executed, proving the vulnerability.

---

## 2. Vulnerability: Remote Code Execution via Inclusion of Manipulated Laravel Application Files

**Description:**
- To provide extended autocomplete features, the extension automatically runs Laravel application code by “booting” the project.
- It does so by constructing a PHP code snippet that requires files such as `vendor/autoload.php` and `bootstrap/app.php` using paths derived by the helper function `Helpers.projectPath()`.
- A malicious repository can include tampered or crafted versions of these essential Laravel files.
- When the extension runs the PHP code (via `Helpers.runLaravel`), it will include and execute these manipulated files.
- **Triggering scenario:** A threat actor uploads a repository with compromised Laravel core files (or even modified service provider code) so that when the extension automatically boots the project, the altered files execute a malicious payload.

**Impact:**
- Arbitrary PHP code is executed in the context of the victim’s system as soon as the extension boots the Laravel project.
- This may result in full system compromise, data exfiltration, or persistent backdoors.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The extension assumes that the Laravel project structure (and its files) is trusted.
- A warning in the README advises users to disable the extension when working on sensitive code, but no active code integrity checks are implemented.

**Missing Mitigations:**
- There is no verification (e.g., integrity/hash checking) for critical files (such as `vendor/autoload.php` or `bootstrap/app.php`) before they are included.
- The extension does not warn the user when opening a repository that may be untrusted or has altered core project files.
- No sandboxing or isolation is implemented for executing the Laravel application code.

**Preconditions:**
- The victim must open a repository where key Laravel files (e.g., `bootstrap/app.php`, `vendor/autoload.php`) have been replaced or modified with an attacker’s payload.

**Source Code Analysis:**
- In `Helpers.runLaravel`, the PHP command is constructed by concatenating several strings. For example:
  ```js
  "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
  "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
  ```
- The file paths are obtained using `Helpers.projectPath`, which computes paths based on workspace settings and local directory structure without any signature or integrity verification.
- When the command is passed to PHP (via `php -r …`), the malicious code inside the altered Laravel files is executed.

**Security Test Case:**
1. Create a test repository that simulates a Laravel project with a tampered `bootstrap/app.php`. For example, insert a command such as:
   ```php
   <?php system('echo COMPROMISED'); exit;
   ```
   at the very beginning of the file.
2. Open the repository in VSCode and allow the extension to auto-detect the Laravel project (the extension checks for the presence of an `artisan` file).
3. Trigger an action that causes the extension to run Laravel (for instance, by invoking an autocomplete feature that calls `Helpers.runLaravel`).
4. Observe the extension’s output channel for the message “COMPROMISED”.
5. Successful output indicates that the manipulated PHP file was included and executed, confirming the vulnerability.
