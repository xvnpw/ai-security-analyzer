- **Vulnerability Name**: PHP Code Execution via Untrusted Project Files
  **Description**:
  The extension executes PHP code derived from the user's Laravel project files (routes, controllers, Blade templates, etc.). An attacker can inject malicious PHP code into these files, which the extension will execute when parsing project data. For example, modifying a Blade template or controller to include `system('malicious_command');` will execute arbitrary PHP code during extension runtime.

  **Trigger Steps**:
  1. An attacker modifies a Laravel project file (e.g., `routes/web.php` or a Blade template) to include malicious PHP code, such as `<?php system('rm -rf /');?>`.
  2. The extension uses `runLaravel` to execute PHP code (e.g., fetching routes or config values), which includes the attacker’s malicious code.
  3. The malicious code executes, allowing arbitrary command execution.

  **Impact**:
  Arbitrary PHP code execution within the user’s environment. Attackers can steal sensitive data, modify files, or take control of the system.

  **Rank**: Critical

  **Currently Implemented Mitigations**: None. The extension directly executes user-provided code without validation.

  **Missing Mitigations**:
  - Input sanitization of user-provided PHP code.
  - Execution in a sandboxed environment to prevent unauthorized actions.

  **Preconditions**:
  - The attacker has write access to Laravel project files (e.g., routes, Blade templates).
  - The extension is configured to use the default `phpCommand` or a vulnerable custom command.

  **Source Code Analysis**:
  - `Helpers.runLaravel()` (helpers.ts) constructs PHP execution commands that include user project code. For instance, in `RouteProvider.loadRoutes()`, the code executes `$route->getActionName()` which may reference malicious controllers.
  - `runPhp()` (helpers.ts) directly inserts unescaped user-controlled code into the PHP command string, allowing injection.

  **Security Test Case**:
  ```bash
  # Step 1: Create a malicious route in routes/web.php:
  Route::get('/malicious', function() {
      echo shell_exec('touch /tmp/ATTACK_SUCCESS');
  });

  # Step 2: Reload VSCode and trigger the extension to parse routes (e.g., save a PHP file).
  # Step 3: Check if /tmp/ATTACK_SUCCESS is created, indicating code execution.
  ```

- **Vulnerability Name**: Command Injection via phpCommand Configuration
  **Description**:
  The `phpCommand` configuration allows users to define how PHP code is executed. An attacker can manipulate this configuration to inject malicious shell commands. For example, setting `phpCommand` to `php -r "{code}"; rm -rf /` would execute arbitrary commands alongside the intended PHP code.

  **Trigger Steps**:
  1. An attacker modifies VSCode settings to set `phpCommand` to `"php -r \"{code}\"; malicious_command"`.
  2. The extension executes the configured command when running PHP code, e.g., fetching config values or routes.
  3. The malicious command (e.g., `malicious_command`) executes, compromising the system.

  **Impact**:
  Arbitrary command execution in the user’s environment. Attackers can delete files, execute programs, or escalate privileges.

  **Rank**: Critical

  **Currently Implemented Mitigations**: None. The configuration is treated as trusted input.

  **Missing Mitigations**:
  - Input validation and escaping for `phpCommand` configuration.
  - Restricting the command format to prevent shell injection.

  **Preconditions**:
  - The attacker can modify the VSCode settings for `LaravelExtraIntellisense.phpCommand`.

  **Source Code Analysis**:
  - `runPhp()` (helpers.ts) uses `commandTemplate.replace("{code}", code)` without escaping or validating the user-defined `phpCommand`. An attacker can inject shell commands via this parameter.

  **Security Test Case**:
  ```bash
  # Step 1: In VSCode settings, set "phpCommand": "php -r \"{code}\"; touch /tmp/ATTACK_SUCCESS".
  # Step 2: Trigger the extension to execute PHP code (e.g., view autocomplete).
  # Step 3: Check if /tmp/ATTACK_SUCCESS is created, indicating successful command injection.
  ```

- **Vulnerability Name**: Path Traversal via basePathForCode
  **Description**:
  The `basePathForCode` configuration specifies the base directory for PHP `require_once` paths. An attacker can manipulate this to include arbitrary files outside the project, leading to code execution or data exposure.

  **Trigger Steps**:
  1. An attacker sets `basePathForCode` to a malicious path like `/var/www/hacked_project`.
  2. The extension executes PHP code that includes `require_once` with this path, loading malicious files.

  **Impact**: Execution of arbitrary code from attacker-controlled paths or exposure of sensitive files.

  **Rank**: High

  **Currently Implemented Mitigations**: None. The configuration is treated as trusted.

  **Missing Mitigations**:
  - Validation of `basePathForCode` to restrict paths to the project directory.

  **Preconditions**:
  - The attacker can modify VSCode settings for `LaravelExtraIntellisense.basePathForCode`.

  **Source Code Analysis**:
  - `Helpers.projectPath()` (helpers.ts) constructs paths using `basePathForCode` without validation, allowing traversal to arbitrary directories.

  **Security Test Case**:
  ```bash
  # Step 1: In VSCode settings, set "basePathForCode": "/var/www/hacked_project".
  # Step 2: Create a malicious file (e.g., `/var/www/hacked_project/exploit.php`) with `<?php system('touch /tmp/PATH_ATTACK'); ?>`.
  # Step 3: Trigger the extension to execute PHP code (e.g., config parsing).
  # Step 4: Check if /tmp/PATH_ATTACK exists, indicating path traversal success.
  ```
