# Vulnerabilities

---

## Vulnerability: Remote Code Execution via Untrusted Laravel Project Code Execution

**Description:**
The extension routinely executes PHP code using the project’s own files in order to fetch autocomplete data via the `Helpers.runLaravel()` routine. In doing so, it constructs a PHP command that includes the files from the project (for example, by requiring `"vendor/autoload.php"` and `"bootstrap/app.php"` via the `Helpers.projectPath()` function). An attacker can trigger this vulnerability by supplying a malicious repository containing modified critical Laravel files (such as a tampered `bootstrap/app.php` or service provider code). When the victim opens the repository in VSCode, the extension detects the Laravel project (e.g., via the presence of the `artisan` file) and proceeds to run `Helpers.runLaravel()`, which leads to the execution of the attacker's malicious PHP code.

**Impact:**
An attacker may achieve arbitrary code execution on the victim’s machine. This could lead to full system compromise including data exfiltration, privilege escalation, or persistent control of the system.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- The extension’s documentation includes a security note warning users that sensitive service provider code may be executed automatically.
- No code‑level isolation or sandboxing is performed before including project files.

**Missing Mitigations:**
- Isolation (sandboxing) of the PHP execution environment to prevent untrusted project code from running in the user’s main environment.
- Integrity or signature verification of critical files such as `"vendor/autoload.php"` and `"bootstrap/app.php"`.
- Runtime validation of the Laravel project’s files before executing them.

**Preconditions:**
- The victim opens a repository that is controlled (or manipulated) by an attacker with malicious modifications in critical Laravel project files.
- The Laravel project is detected (e.g., by the presence of the `artisan` file), causing the extension to "boot" the project and run its PHP code.

**Source Code Analysis:**
1. In the `Helpers.runLaravel()` function, the extension constructs a PHP command by concatenating strings that include:
   - `require_once Helpers.projectPath("vendor/autoload.php", true);`
   - `require_once Helpers.projectPath("bootstrap/app.php", true);`
2. The `Helpers.projectPath()` function resolves file paths based solely on the workspace without verifying the integrity or authenticity of these files.
3. The constructed command is then executed via `cp.exec()` in the `Helpers.runPhp()` function.
4. Since there is no sandboxing or isolation, any malicious code embedded into these project files will be executed in the context of the extension, effectively triggering Remote Code Execution.

**Security Test Case:**
1. **Repository Setup:** Create a test Laravel repository where you deliberately modify `bootstrap/app.php` to include a payload (for example, a PHP snippet that writes a file named `pwned.txt` with a known content).
2. **Open Repository:** Open the malicious repository in VSCode so that the extension identifies it as a Laravel project.
3. **Trigger Execution:** Wait for or trigger the execution of `Helpers.runLaravel()` (this may occur during autocompletion or another internal call).
4. **Verify Payload Execution:** Check that the payload runs by verifying the presence and content of `pwned.txt` or another observable artifact (such as log entries).
5. **Documentation:** Record the complete path from file inclusion via `Helpers.runLaravel()` to the execution of the payload to validate the arbitrary code execution vector.

---

## Vulnerability: Command Injection via Malicious Workspace Configuration

**Description:**
The extension reads a PHP command template from the workspace configuration setting `LaravelExtraIntellisense.phpCommand` (defaulting to `php -r "{code}"`). This value can be overridden by a repository’s local `.vscode/settings.json`. An attacker can trigger this vulnerability by providing a manipulated repository that contains a `.vscode/settings.json` file with a crafted `phpCommand` value. For example, by appending extra shell command separators and commands (e.g., `php -r "{code}"; echo 'Injection Successful'`), the extension will execute the malicious command when it performs a simple string replacement in the `Helpers.runPhp()` function, resulting in command injection.

**Impact:**
An attacker may inject arbitrary shell commands into the PHP command executed by the extension. This can lead to full command injection, allowing arbitrary code execution at the operating system level and complete compromise of the victim’s machine.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- In the `Helpers.runPhp()` function, some basic escaping is performed: quotes are escaped and, on Unix platforms, the `$` symbol is escaped.
- However, this escaping was designed solely for preventing accidental misinterpretation of the PHP code string and is not sufficient when the command template is completely controlled by the workspace configuration.

**Missing Mitigations:**
- Proper validation and sanitization of the `phpCommand` configuration value to ensure it adheres to an expected safe pattern.
- Restrictions on allowing workspace-specific settings (e.g., those in a repository’s `.vscode` folder) to override secure defaults without explicit user confirmation.
- Execution of PHP commands in a sandboxed environment that would limit the impact of any injected shell commands.

**Preconditions:**
- The attacker supplies a repository with a malicious `.vscode/settings.json` that overrides `LaravelExtraIntellisense.phpCommand` with a dangerous command template.
- The victim opens the repository in VSCode so that the manipulated workspace configuration is applied.
- The extension builds and executes the command string using the attacker-controlled template in the `Helpers.runPhp()` function.

**Source Code Analysis:**
1. In the `Helpers.runPhp()` function, the command template is fetched via:
   ```js
   let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
   ```
2. The extension then performs a simple string replacement:
   ```js
   let command = commandTemplate.replace("{code}", code);
   ```
3. No further sanitization or validation of the `commandTemplate` is performed, which allows an attacker to supply additional shell commands.
4. By controlling the entire command template, an attacker can inject extra shell commands (for instance, appending a command separator like `;` followed by a malicious shell command) that are executed by the operating system.

**Security Test Case:**
1. **Repository Setup:** Create a test repository that includes a `.vscode/settings.json` file with the following configuration:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo 'Injection Successful'"
   }
   ```
2. **Open Repository:** Open the repository in VSCode so that the workspace configuration is loaded and applied.
3. **Trigger Execution:** Initiate an action (such as triggering an autocomplete request) that causes the extension to call `Helpers.runPhp()`.
4. **Observe Behavior:** Monitor the output of the PHP process or observe system logs to verify that the injected shell command (e.g., `echo 'Injection Successful'`) is executed.
5. **Confirm Vulnerability:** Document the chain from the malicious workspace configuration, through the simple string replacement in `Helpers.runPhp()`, to the execution of additional shell commands, thereby proving the command injection.

---
