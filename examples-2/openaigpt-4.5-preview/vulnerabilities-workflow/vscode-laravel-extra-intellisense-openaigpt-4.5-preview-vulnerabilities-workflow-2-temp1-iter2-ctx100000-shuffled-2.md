# Vulnerabilities

## Vulnerability 1: Arbitrary PHP Code Execution via `phpCommand` Configuration

**Description:**
A malicious actor who has gained the ability to modify a user's VSCode workspace settings file (`settings.json`) could exploit the `LaravelExtraIntellisense.phpCommand` setting. This setting defines the command used by the extension to execute dynamically generated PHP code. Because this command is user-configurable and directly executes PHP code inserted by substitution (`{code}` placeholder), an attacker who tricks or forces a developer to configure this setting improperly could cause arbitrary PHP code execution within the developer's working environment.

Example exploit scenario:
- Attacker sends malicious configuration instructions (through social engineering or compromised documentation/tutorial).
- The developer updates `settings.json` with a dangerous command string provided by the attacker.
- Upon autocompletion trigger (e.g., when developer types code triggering Laravel autocomplete), the extension executes attacker-provided arbitrary PHP commands.

**Impact:**
- Remote or local arbitrary PHP code execution on the developer's machine or within a Docker/VM environment.
- Possible compromise or exfiltration of sensitive source code, credentials, or secrets.
- Complete environment takeover.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- A "Security Note" in the extension documentation warns users of potential risks associated with running the Laravel application automatically for autocompletion purposes.

**Missing Mitigations:**
- No built-in sanitation, validation, or restriction of the allowed command strings.
- Absence of strict default settings to limit dangerous user configurations.
- No runtime checking of the configured command for risky or unsafe constructs.

**Preconditions:**
- The attacker successfully manipulates the user's `settings.json` VSCode workspace configuration file or tricks developer into unsafe configurations.

**Source Code Analysis:**
- Location: `src/helpers.ts`
- The method `runPhp()` directly constructs a shell command from user-configurable settings:
  ```typescript
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  let command = commandTemplate.replace("{code}", code);

  cp.exec(command, { cwd: workspaceFolder }, function (err, stdout, stderr) {
      // command execution without validation
  });
  ```
- The command generated from configuration and code replacement (`commandTemplate.replace("{code}", code)`) is executed directly without validation or restrictions, enabling arbitrary command injection if set improperly.

**Security Test Case:**
1. Modify `settings.json` with a malicious or improper PHP command:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; php -r \"file_put_contents('/tmp/payload_executed.txt', 'malicious execution confirmed');\""
   ```

2. Restart VSCode workspace to ensure the new configuration is loaded.

3. Trigger Laravel extra IntelliSense functionality by typing code in a Laravel project until autocompletion runs.

4. Verify if file `/tmp/payload_executed.txt` has been created. If it exists, arbitrary PHP code execution succeeded.

---

## Vulnerability 2: PHP Injection via Laravel Model Loading Mechanism

**Description:**
The extension dynamically includes Laravel model files (`.php`) directly via PHP's `include_once` construct during autocompletion logic. This behavior opens a significant risk: if an attacker or compromised dependency manages to insert malicious PHP code into standard Laravel model directories (`app/`, `app/Models`), the extension inadvertently executes it every time autocompletion is triggered.

Attack scenario example:
- Developer installs manipulated or compromised third-party PHP packages or dependencies.
- Malicious PHP code is added unnoticed to Laravel model paths.
- When IntelliSense triggers loading Laravel models for autocompletion, it executes malicious PHP directly through inclusion.

**Impact:**
- Arbitrary PHP code execution inside the developer's workspace (locally or Dockerized).
- An attacker could achieve local privilege escalation, data exfiltration, or full system compromise in the developer's context.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- None visible in current source code analysis.

**Missing Mitigations:**
- Absence of validation, sandboxing, or whitelisting before including PHP model files.
- No integrity checks or restrictions on dynamically included files and directories.

**Preconditions:**
- An attacker must have the capability to write or introduce malicious PHP files into Laravel application directories (`app/`, `app/Models`) used by the extension for autocomplete.

**Source Code Analysis:**
- Location: `src/EloquentProvider.ts`
- Vulnerable snippet:
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
- Risk arises because the extension blindly includes PHP files found in user-controlled directories without checks.

**Security Test Case:**
1. Place a malicious payload into Laravel `app/Models` directory (`MaliciousPayload.php`):
   ```php
   <?php
   file_put_contents('/tmp/malicious_intellisense_test.txt', 'Malicious include executed');
   ?>
   ```

2. Trigger IntelliSense autocomplete execution by interacting with Laravel model classes inside VSCode.

3. Check the file `/tmp/malicious_intellisense_test.txt`. Its existence confirms PHP code execution due to file inclusion.

---

## Overall Recommendations for Mitigation:

The above vulnerabilities pose a direct, realistic threat of remote and local PHP command execution. To address these issues, the following mitigations and improvements should be considered:

1. **Configuration Security Validation**
   - Restrict allowable commands in the `phpCommand` configuration via a preset of secure templates.
   - Provide safe defaults that restrict possible injection points—avoid direct pass-through commands.
   - Runtime validation and command filtering before execution.

2. **PHP File Inclusion Safety**
   - Implement whitelist mechanisms to only allow inclusion of files that match approved signatures or explicitly declared models.
   - Prevent blind execution of model files through integrity checks, code checksum validations, or trusted-directory file checks.
   - Document explicit developer guidance on verifying third-party packages and dependencies for tampering.

3. **Sandboxing and Isolation**
   - Advise users explicitly to configure environments such as Docker or virtual machines with minimal privileges in documentation.
   - Provide recommendations for running IntelliSense operations within isolated contexts (Docker with resource and permissions minimalism) to limit exploitation risks further.

By following these recommendations, the risk and exploitation opportunities for identified vulnerabilities could be significantly mitigated.
