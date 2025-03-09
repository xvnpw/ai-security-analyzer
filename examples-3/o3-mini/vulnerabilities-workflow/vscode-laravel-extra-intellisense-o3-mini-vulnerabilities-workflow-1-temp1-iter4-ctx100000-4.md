# Vulnerabilities

---

## Vulnerability Name: Arbitrary Code Execution via Malicious Laravel Project Execution

**Description:**
The extension calls a helper function that “boots” the Laravel application by requiring the project’s vendor and bootstrap files. In particular, the function `Helpers.runLaravel` builds a PHP command string that first does a `require_once` on the project’s
`vendor/autoload.php` and `bootstrap/app.php` files. An attacker who supplies a malicious repository can manipulate these files (or include extra malicious PHP code in them) so that when the extension runs them, arbitrary PHP code is executed.

**Step by Step Trigger:**
1. The attacker prepares a Laravel repository in which the attacker has modified the critical bootstrap files (for example, injecting system calls or writing files) in the project’s root folder.
2. When the victim opens the workspace in VSCode, the extension uses `Helpers.projectPath` to locate the project’s vendor and bootstrap files.
3. The extension then calls `Helpers.runLaravel` which builds a command that includes:
   - `require_once '…/vendor/autoload.php';`
   - `$app = require_once '…/bootstrap/app.php';`
4. Because these files come from the (malicious) repository, the attacker’s injected payload executes—even though the extension code itself uses fixed PHP strings for data gathering.

**Impact:**
This flaw may allow an attacker to run arbitrary PHP code on the victim’s machine. An attacker could execute system commands, compromise user data, or escalate privileges—all with the rights of the PHP interpreter that the extension spawns.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The README’s “Security Note” warns users that the extension executes their Laravel application automatically and recommends disabling the extension if sensitive code is written in service providers.
- The extension only attempts to run Laravel code if it detects the expected files (e.g., `vendor/autoload.php` and `bootstrap/app.php`) in the workspace.

**Missing Mitigations:**
- There is no sandboxing or isolation of the executed PHP code, and no validation is performed on the project files before loading them.
- No explicit security wrapper is used to restrict operations when booting the Laravel application context.

**Preconditions:**
- The victim opens a workspace containing a Laravel project that has been maliciously manipulated (in particular, with altered bootstrap or autoload files).
- The extension finds the expected files (based on its configuration or default workspace detection) and proceeds to “boot” the Laravel app automatically.

**Source Code Analysis:**
- In `Helpers.runLaravel`, the code checks for the existence of `vendor/autoload.php` and `bootstrap/app.php` using `Helpers.projectPath()`.
- It then creates a PHP command as a concatenated string that starts with:
  ```php
  define('LARAVEL_START', microtime(true));
  require_once '…/vendor/autoload.php';
  $app = require_once '…/bootstrap/app.php';
  // (further registration of an internal provider and kernel booting)
  ```
- Because the command string simply embeds the paths and then processes the injected code (provided via the extension’s operation), any malicious payload inside the required files is executed immediately.

**Security Test Case:**
1. Create a test Laravel repository that mimics a real project yet contains a modified file — for example, in `bootstrap/app.php` add PHP code that writes a marker file (or executes a harmless system command) upon inclusion.
2. Open this repository in VSCode so that the extension “Laravel Extra Intellisense” is triggered.
3. Observe that the marker file is created on the victim’s machine (or that the system command is executed).
4. Confirm that the attacker-controlled payload ran with the privileges of the PHP process invoked by the extension.

---

## Vulnerability Name: Command Injection via Manipulated Workspace Configuration (phpCommand)

**Description:**
The extension constructs the command used to execute PHP code by reading the configuration parameter `LaravelExtraIntellisense.phpCommand`. In the helper function `Helpers.runPhp`, it retrieves this value from the workspace settings and performs a simple string replacement (replacing `{code}` with the generated PHP code). Because there is no sanitization or validation on the configuration value, an attacker who supplies a malicious workspace settings file (via a repository’s `.vscode/settings.json`) can inject additional shell commands into the command template.

**Step by Step Trigger:**
1. The attacker creates (or modifies) a `.vscode/settings.json` file in the repository with a malicious value for the key `LaravelExtraIntellisense.phpCommand`. For example, the attacker sets it to:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('touch /tmp/injected');\""
   ```
2. When a victim opens this repository in VSCode, the extension calls `Helpers.runPhp`.
3. The function fetches the (malicious) `phpCommand` value and substitutes `{code}` with its own generated PHP code.
4. The resulting shell command now contains an extra `system('touch /tmp/injected')` call that causes the attacker’s command to run on the victim’s machine.

**Impact:**
An attacker may cause arbitrary shell commands to be executed within the context of the victim’s machine. This could lead to privilege escalation, file manipulation, or other severe system compromise actions.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- No explicit runtime validation is performed on the value returned by `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
- The extension relies solely on the default value (`"php -r \"{code}\""`) if the configuration is not set; it does not check whether this key was overridden in a workspace setting.

**Missing Mitigations:**
- Input sanitization or validation on the workspace configuration values, especially for the command template.
- Isolation or sandboxing of the executed command to prevent injection of unintended commands.

**Preconditions:**
- The attacker must supply a malicious `.vscode/settings.json` file through the repository that is automatically loaded by VSCode as part of the workspace settings.
- The victim opens the repository in VSCode with these settings in effect.

**Source Code Analysis:**
- In `Helpers.runPhp`, the code retrieves the command template via:
  ```javascript
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  ```
- It then performs a simple replacement:
  ```javascript
  let command = commandTemplate.replace("{code}", code);
  ```
- Finally, it executes the command with `cp.exec(command, …)`. There is no additional sanitizing of the configuration value or the code.

**Security Test Case:**
1. Create a test repository with a `.vscode/settings.json` file that deliberately overrides the `phpCommand` setting with a malicious payload—for example, appending an extra shell command as shown above.
2. Open this repository in VSCode so that the extension loads these settings automatically.
3. Trigger one of the extension functions (for example, by invoking autocompletion that calls `Helpers.runPhp`) and monitor for the execution of the injected command (e.g., the creation of the file `/tmp/injected`).
4. Verify that the additional command is executed, confirming that command injection is possible.
