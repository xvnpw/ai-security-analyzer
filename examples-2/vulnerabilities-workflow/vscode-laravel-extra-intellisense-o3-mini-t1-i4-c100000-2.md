# List of High-Severity Vulnerabilities

Below is the updated list of vulnerabilities that can be triggered by an attacker supplying a malicious repository (with a manipulated `.vscode/settings.json` file) to a victim. These vulnerabilities have a rank of at least high and fall under the classes of Remote Code Execution (RCE), Command Injection, or Code Injection.

---

## Vulnerability 1: Command Injection via Malicious `phpCommand` Configuration

- **Description:**
  An attacker can create a malicious repository (or workspace) that includes a `.vscode/settings.json` file overriding the extension’s default PHP command. Instead of using the safe default
  ```
  php -r "{code}"
  ```
  the attacker can substitute a crafted command string that injects extra shell commands. For example, if the attacker sets:
  ```json
  {
    "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; rm -rf ~/sensitive_data"
  }
  ```
  then when the extension later calls the helper function to run PHP code, it performs a simple string replacement—without sanitizing the configured value. This results in a complete shell command such as:
  ```
  php -r "generated_php_code"; rm -rf ~/sensitive_data
  ```
  whereby the extra shell command is executed immediately after the intended PHP code, resulting in arbitrary command execution.

- **Impact:**
  An attacker can achieve full remote code execution on the victim’s machine. Arbitrary shell commands may be executed with the same privileges as VSCode (and thus, the user), potentially leading to data loss, unauthorized access, or complete system compromise.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  The extension simply reads the user/workspace configuration without any input validation or sanitization. No escaping or safe templating is performed on the user-supplied `phpCommand`.

- **Missing Mitigations:**
  - Validate and strictly sanitize configuration values before using them to build shell commands.
  - Disallow workspace-provided settings from overriding secure defaults or require explicit user confirmation for critical settings.
  - Use a safer method for composing the command (for example, passing arguments without shell interpolation).

- **Preconditions:**
  - The victim opens a repository (or workspace) supplied by an attacker that includes a manipulated `.vscode/settings.json` file.
  - The configuration key `LaravelExtraIntellisense.phpCommand` is overridden with a payload that injects additional shell commands.

- **Source Code Analysis:**
  1. In `helpers.ts` (function `runPhp`), the code reads the configuration value as follows:
     ```js
     let commandTemplate = vscode.workspace
       .getConfiguration("LaravelExtraIntellisense")
       .get<string>('phpCommand') ?? "php -r \"{code}\"";
     let command = commandTemplate.replace("{code}", code);
     ```
     There is no validation or escaping of the retrieved string.
  2. The constructed command (now containing any injected payload from the malicious configuration) is passed directly into `cp.exec(...)`.
  3. Because the extension uses the workspace configuration without filtering, an attacker’s payload in the `phpCommand` setting is embedded directly into the shell command, thereby enabling command injection.

- **Security Test Case:**
  1. Create a test repository that includes a `.vscode/settings.json` file with the following contents:
     ```json
     {
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo '[INJECTION SUCCEEDED]'"
     }
     ```
  2. Open this repository in VSCode.
  3. Trigger any functionality that causes the extension to call `Helpers.runPhp` (for example, open a PHP file that requires autocompletion based on Laravel routes or models).
  4. Observe the output of the command (e.g., in the extension’s output panel or system logs) to verify if the injected output marker (`[INJECTION SUCCEEDED]`) appears.
  5. Confirm that additional injected commands execute (in a controlled test environment) to validate arbitrary command execution.

---

## Vulnerability 2: PHP Code Injection via Malicious `basePathForCode` Configuration

- **Description:**
  The extension calls PHP’s `require_once` on files whose paths are constructed using the user-configurable `LaravelExtraIntellisense.basePathForCode` setting. In the helper function `projectPath` (in *helpers.ts*), when `forCode` is true the extension uses:
  ```js
  let basePathForCode = vscode.workspace
      .getConfiguration("LaravelExtraIntellisense")
      .get<string>('basePathForCode');
  // (After some minimal formatting—only a trailing slash is removed)
  return basePathForCode + path;
  ```
  If an attacker supplies a malicious value containing a single quote or other PHP code–breaking characters (for example,
  ```
  dummy'; system('calc'); //
  ```
  then when the extension builds the PHP code in `runLaravel` it will generate a snippet such as:
  ```php
  require_once 'dummy'; system('calc'); //bootstrap/app.php';
  ```
  The closing single quote is broken out of, and the injected PHP code (in this example, a system call) is executed.

- **Impact:**
  The attacker gains the ability to inject arbitrary PHP code, leading to remote code execution in the PHP environment. This could allow the attacker to read/write files, access databases, or compromise the victim’s system further.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  The only manipulation done on the configuration value in `projectPath` is a trailing-slash removal. No escaping or proper validation is applied, thus leaving the injection vector open.

- **Missing Mitigations:**
  - Sanitize and properly escape any user- or workspace-controlled values before inserting them into PHP code executed on the command line.
  - Validate that `basePathForCode` is a safe file path (for example, check it against a whitelist or enforce a strict pattern).
  - Use parameterized invocation (if possible) so that file paths and code segments are not directly interpolated into executable PHP code.

- **Preconditions:**
  - The attacker must supply a malicious repository that includes a `.vscode/settings.json` file overriding `LaravelExtraIntellisense.basePathForCode` with a value containing an injection payload (for example, inserting a single quote to break out of the string literal).
  - The extension’s functionality that relies on including PHP files (i.e., booting Laravel via `runLaravel`) must be triggered.

- **Source Code Analysis:**
  1. In `Helpers.projectPath(path: string, forCode: boolean)` (in *helpers.ts*), when `forCode` is true the function obtains the configuration value for `basePathForCode` and does minimal processing:
     ```js
     let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
     if (basePathForCode && basePathForCode.length > 0) {
         // Resolves relative path if necessary
         basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
         return basePathForCode + path;
     }
     ```
  2. Later, in `Helpers.runLaravel`, this value is inserted into the PHP code without further escaping:
     ```js
     "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';"
     "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
     ```
  3. If a configuration value such as `dummy'; system('calc'); //` is provided, the resulting PHP code becomes malformed and allows execution of arbitrary PHP commands.

- **Security Test Case:**
  1. In a controlled test environment, create a repository with a `.vscode/settings.json` file that sets:
     ```json
     {
       "LaravelExtraIntellisense.basePathForCode": "dummy'; echo '[INJECTION SUCCEEDED]'; //"
     }
     ```
  2. Open the repository in VSCode so that the extension picks up the malicious configuration.
  3. Trigger any functionality that calls `Helpers.runLaravel` (for example, by opening a PHP file that requires Laravel data for code completion).
  4. In the extension’s output channel, look for the marker `[INJECTION SUCCEEDED]` or other indicators that the injected PHP code was executed.
  5. Confirm that arbitrary PHP code execution occurs as a result of the configured payload.

---
