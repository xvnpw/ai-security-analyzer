# Combined List of Vulnerabilities

## Vulnerability name: Command Injection via configurable phpCommand setting
**Description**:
The extension allows users to configure the `phpCommand` setting, which is used to execute arbitrary PHP code. This setting can be set through a maliciously crafted `.vscode/settings.json` file in a project or directly via the extension's configuration. By default, `phpCommand` uses `php -r "{code}"` to execute PHP snippets. However, attackers can manipulate this value to inject malicious shell commands. For example, setting `phpCommand` to `php -r "{code}"; malicious_shell_command` appends arbitrary commands to the execution chain. The extension replaces the `{code}` placeholder in the provided command without proper validation or escaping of shell metacharacters, enabling command injection. This vulnerability is triggered when the extension runs PHP code, such as during Laravel command executions (e.g., fetching routes/models).

**Impact**:
Attackers can execute arbitrary shell commands with the privileges of the user running VSCode. This includes deleting files, accessing sensitive data, installing malware, or gaining full system control.

**Vulnerability rank**: Critical

**Currently implemented mitigations**:
None. The extension does not validate or sanitize the `phpCommand` configuration value.

**Missing mitigations**:
- Enforce a strict format for `phpCommand` (e.g., `php -r "%s"` template).
- Restrict modifications to the default `phpCommand` value unless validated.
- Sanitize shell metacharacters in the `{code}` placeholder.
- Provide warnings for configurations that deviate from the expected format.

**Preconditions**:
The victim must either:
1. Open a malicious repository containing a `.vscode/settings.json` file with a manipulated `phpCommand` setting.
2. Directly configure the extension's settings to include a malicious `phpCommand` value.

**Source code analysis**:
1. The `phpCommand` setting is read from user configuration in `extension.ts`.
2. In `Helpers.ts`, the `runPhp` function constructs the command using `commandTemplate.replace("{code}", code)`, where `commandTemplate` is the user-provided `phpCommand`.
3. The `runPhp` function does not validate or escape shell metacharacters in the `commandTemplate`, allowing injection of malicious commands (e.g., `; rm -rf /`).
4. Functions like `loadRoutes` and `loadModels` in providers (e.g., `EloquentProvider.ts`, line 59) call `runLaravel`, which invokes `runPhp`, executing the malicious command.
5. The `README.md` documentation shows users how to configure `phpCommand` but lacks warnings about input validation.

**Security test case**:
1. Create a malicious repository with a `.vscode/settings.json` containing:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo 'ATTACK SUCCESSFUL' > /tmp/attack_result"
   }
   ```
2. Open the repository in VSCode with the extension installed.
3. Trigger any action that executes PHP code (e.g., opening a Blade template or routes file).
4. Verify the command execution by checking `/tmp/attack_result` for the echoed string.

---

## Vulnerability name: Code Injection via Model File Inclusion
**Description**:
The `ModelProvider` loads PHP files from paths specified in the `modelsPaths` configuration. Attackers can configure this setting to include malicious `.php` files located outside the workspace (e.g., `/tmp/attack/EvilModel.php`). The `loadModels()` function in `Helpers.ts` uses `include_once` on unvalidated paths, executing any PHP code in the included files. This allows arbitrary code execution within the extension's context.

**Impact**:
Attackers can execute arbitrary PHP code in the context of the extension, potentially accessing sensitive data or compromising the system.

**Vulnerability rank**: High

**Currently implemented mitigations**:
None. The `modelsPaths` setting is user-configurable without validation.

**Missing mitigations**:
- Validate that paths in `modelsPaths` are within workspace directories.
- Restrict `include_once` operations to trusted files (e.g., Eloquent model files).

**Preconditions**:
The victim must configure the `modelsPaths` setting to include a malicious directory.

**Source code analysis**:
1. The `EloquentProvider` constructor loads models from configured paths (e.g., line 59 in `EloquentProvider.ts`).
2. The `loadModels()` function in `Helpers.ts` uses `include_once` on paths provided via `modelsPaths`, without checking if they belong to the workspace.
3. This allows malicious files (e.g., `/tmp/attack/EvilModel.php`) to execute arbitrary PHP code when the extension parses models.

**Security test case**:
1. Create `/tmp/attack/EvilModel.php` with the following content:
   ```php
   <?php system('touch /tmp/exploit'); ?>
   ```
2. Configure the extension's settings to include the malicious path:
   ```json
   {
     "LaravelExtraIntellisense.modelsPaths": ["/tmp/attack"]
   }
   ```
3. Trigger model autocomplete (e.g., typing `$model->` in a Blade file).
4. Verify the command execution by checking for the existence of `/tmp/exploit`.
