- Vulnerability name: Command Injection via phpCommand Configuration
  Description: The extension allows users to configure the `phpCommand` to specify how PHP is executed. This command is used verbatim without validation or sanitization. An attacker can set the `phpCommand` to execute arbitrary shell commands. For example, setting `"LaravelExtraIntellisense.phpCommand": "bash -c '{code}; rm -rf /'"` would allow executing malicious shell commands alongside the intended PHP code.
  Impact: **Critical** - Full system compromise via arbitrary command execution.
  Vulnerability rank: Critical
  Currently implemented mitigations: None. No validation or input sanitization for `phpCommand`.
  Missing mitigations: Implement strict validation of `phpCommand` syntax (e.g., disallow dangerous patterns like `;`, `|`, backticks), and ensure the `{code}` placeholder is only used in safe contexts.
  Preconditions: User must configure `phpCommand` with malicious input.
  Source code analysis:
  1. In `Helpers.ts`, `runPhp` constructs the command using `commandTemplate.replace("{code}", code)` where `commandTemplate` is taken directly from the configuration.
  2. The default `phpCommand` is `php -r "{code}"`, but an attacker can replace this template with arbitrary commands.
  3. The generated command is passed to `child_process.exec` without any sanitization, allowing injection of shell metacharacters.
  Security test case:
  ```json
  // Configure malicious phpCommand in VSCode settings
  "LaravelExtraIntellisense.phpCommand": "bash -c 'echo \"Hacked!\" > /tmp/vscode_exploit && {code}'"
  ```
  When the extension runs any PHP code (e.g., loading routes), the `bash -c` command will execute, creating a file at `/tmp/vscode_exploit`.

---

- Vulnerability name: Unsanitized PHP Code Execution in Generated Scripts
  Description: The extension generates PHP code dynamically from project files (e.g., routes, config files) and executes it via `runPhp`. Attackers can inject malicious PHP code into these files, which is then executed without validation. For example, a malicious route definition in `routes/web.php` could be parsed into PHP code that窃取敏感信息 or execute arbitrary commands.
  Impact: **High** - Execution of malicious PHP code in the context of the user's IDE, leading to data exfiltration or system access.
  Vulnerability rank: High
  Currently implemented mitigations: None. Generated PHP code is executed directly.
  Missing mitigations: Sanitize user-provided data before embedding it into generated PHP code, or restrict execution to sandboxed environments.
  Preconditions: The attacker must control project files (e.g., routes, config files) that are parsed by the extension.
  Source code analysis:
  1. In `RouteProvider.ts`, `loadRoutes` executes PHP code to parse routes: `Helpers.runLaravel("echo json_encode(...", "HTTP Routes")`.
  2. The PHP code generated from project files (e.g., `app/Http/routes.php`) is parsed and executed without input validation, allowing injection of PHP payloads.
  Security test case:
  ```php
  // Create a malicious route file (routes/web.php):
  Route::get('/exploit', function() {
      return shell_exec('echo "Hacked!" > /tmp/exploit');
  });
  ```
  When the extension loads routes, the malicious PHP code will execute, creating a file `/tmp/exploit`.

---

- Vulnerability name: Path Traversal via basePath Configuration
  Description: The `basePath` configuration is used to determine the project root directory. If an attacker sets an absolute path (e.g., `../../malicious_project`), it could allow access to arbitrary directories outside the intended workspace.
  Impact: **Medium** - Unauthorized access to sensitive files outside the project's scope.
  Vulnerability rank: Medium
  Currently implemented mitigations: The code checks if `basePath` starts with '.' and resolves relative paths to the workspace folder.
  Missing mitigations: The check may fail if an absolute path is provided without a leading '.' (e.g., `/absolute/path`), allowing traversal.
  Preconditions: The attacker must configure `basePath` to point outside the workspace.
  Source code analysis:
  1. `Helpers.projectPath` uses `vscode.workspace.workspaceFolders[0].uri.fsPath` to resolve relative paths but allows absolute paths unvalidated.
  Security test case:
  ```json
  // Configure basePath to access /etc/passwd
  "LaravelExtraIntellisense.basePath": "/etc"
  ```
  When accessing `projectPath("/passwd")`, it would resolve to `/etc/passwd`, exposing sensitive system files.

---

- Vulnerability name: Arbitrary File Inclusion via basePathForCode
  Description: The `basePathForCode` configuration specifies the base directory for `require_once` in generated PHP code. An attacker can set this to include malicious PHP files from outside the project, leading to remote code execution.
  Impact: **High** - Execution of arbitrary PHP code if an attacker can place files in the specified path.
  Vulnerability rank: High
  Currently implemented mitigations: None. The configuration is trusted.
  Missing mitigations: Validate `basePathForCode` against workspace boundaries and restrict to project directories.
  Preconditions: Attacker controls `basePathForCode` and can place malicious files in the specified path.
  Source code analysis:
  The generated PHP code uses `base_path()` based on `basePathForCode`, which could include external paths.
  Security test case:
  ```json
  // Configure basePathForCode to include a malicious file
  "LaravelExtraIntellisense.basePathForCode": "/malicious/path"
  ```
  Generated PHP code may execute `require_once base_path("/exploit.php")`, running attacker-controlled PHP code.
