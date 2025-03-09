- Vulnerability name: Arbitrary Code Execution via phpCommand Configuration
  Description: The extension executes PHP commands using the user-configurable `phpCommand` setting without proper input validation. An attacker can set the `phpCommand` configuration to include malicious PHP code wrapped in the `{code}` placeholder, allowing arbitrary code execution. For example, setting `phpCommand` to `php -r "{code} && rm -rf /"` would execute the destructive command alongside legitimate code.
  Impact: Full remote code execution on the user's machine, leading to data destruction, unauthorized access, or system compromise.
  Vulnerability rank: Critical
  Currently implemented mitigations: None. The extension trusts the `phpCommand` configuration without validation.
  Missing mitigations: Input validation for the `phpCommand` configuration to prevent shell injection, sandboxing, or whitelisting allowed commands.
  Preconditions: The attacker must have access to configure the VSCode extension's settings.
  Source code analysis: In `Helpers.ts`, `runPhp` constructs the command by replacing `{code}` in the `phpCommand` string. The user-controlled `phpCommand` is executed directly via `child_process.exec`, allowing injection of arbitrary commands. For example:
  ```typescript
  // Helpers.ts: runPhp function
  let command = commandTemplate.replace("{code}", code); // commandTemplate comes from user config
  // ... then executes via cp.exec(command)
  ```
  Security test case:
  1. Install the extension in VSCode.
  2. Configure `phpCommand` to `php -r "{code} && echo 'ATTACK_SUCCESS' > /tmp/exploit.txt"`.
  3. Trigger the extension to run any PHP command (e.g., by editing a Blade file).
  4. Check for `/tmp/exploit.txt` creation, indicating successful RCE.

- Vulnerability name: Path Traversal in Model Directories
  Description: The extension dynamically includes PHP files from user-specified `modelsPaths` directories without validating their contents. An attacker can manipulate these paths to include malicious PHP files, which are executed during model discovery.
  Impact: Execution of arbitrary PHP code via included files, leading to code execution or data exposure.
  Vulnerability rank: High
  Currently implemented mitigations: None. The extension trusts all files in `modelsPaths`.
  Missing mitigations: Input validation for `modelsPaths` to restrict to valid Laravel model directories, and sandboxing when loading files.
  Preconditions: The attacker has write access to directories referenced in `modelsPaths`.
  Source code analysis: In `EloquentProvider.ts`, the code scans directories from `modelsPaths`:
  ```typescript
  // EloquentProvider.ts: loadModels()
  for (let modelsPath of ...modelsPaths) {
    // Includes all .php files in modelsPath via include_once
  }
  ```
  Security test case:
  1. Set `modelsPaths` to `../../malicious_dir` in the extension settings.
  2. Create `malicious_dir/evil.php` containing `<?php system('id') ?>`.
  3. Trigger model autocomplete, causing the extension to include `evil.php`.
  4. Verify `id` command execution via logs or spawned processes.

- Vulnerability name: Unvalidated Middleware Class Execution
  Description: The extension dynamically executes middleware classes from user-configured paths. An attacker can inject malicious middleware by manipulating the `app/Http/Kernel.php` file or paths, leading to code execution.
  Impact: Execution of arbitrary code via middleware handlers.
  Vulnerability rank: High
  Currently implemented mitigations: None. The extension trusts kernel configuration.
  Missing mitigations: Validation of middleware class sources and parameter checks.
  Preconditions: Write access to Laravel's `Kernel.php` or middleware directories.
  Source code analysis: `MiddlewareProvider.ts` loads middleware without validation:
  ```typescript
  // MiddlewareProvider.ts: loadMiddlewares()
  Helpers.runLaravel("...", "Middlewares") // Dynamically analyses middleware classes
  ```
  Security test case:
  1. Modify `Kernel.php` to register a malicious middleware class.
  2. Trigger a route autocomplete to load the middleware list.
  3. The malicious code in the middleware executes during analysis.
