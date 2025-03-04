# Vulnerabilities in VSCode Laravel Extra Intellisense Extension

## 1. Command Injection via phpCommand Configuration Setting

- **Vulnerability Name**: Command Injection via phpCommand Configuration Setting

- **Description**: The extension allows users to configure a custom command template for executing PHP code via the `LaravelExtraIntellisense.phpCommand` setting. When the extension loads and detects a Laravel project, it executes PHP commands using this template by simply replacing `{code}` with PHP code and executing it directly via `cp.exec()`. There's no validation or sanitization of this template.

  Steps to trigger the vulnerability:
  1. An attacker creates a malicious repository with a Laravel-like structure
  2. The repository includes a `.vscode/settings.json` file with a malicious command in the `LaravelExtraIntellisense.phpCommand` setting
  3. When a victim opens this repository in VSCode with the extension installed, the malicious command is executed

  The relevant code is in the `runPhp` method in `helpers.ts`:
  ```typescript
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  let command = commandTemplate.replace("{code}", code);
  // This command is then passed directly to cp.exec()
  ```

- **Impact**: An attacker can execute arbitrary commands with the privileges of the VSCode process on the victim's machine. This can lead to full system compromise, data theft, or installation of malware. Since the command executes immediately when a Laravel project is opened, the victim doesn't need to perform any special action other than opening the project.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**: None. The extension does not validate or sanitize the phpCommand setting at all. There is a general security warning in the README, but it doesn't specifically mention the risk of opening unknown repositories.

- **Missing Mitigations**:
  - The extension should validate the phpCommand setting to ensure it only contains safe characters
  - Shell command injection protection should be implemented
  - A prompt should warn users when a custom phpCommand is detected in workspace settings
  - Documentation should be updated to warn users about the risks of opening untrusted repositories

- **Preconditions**:
  - The victim must have the Laravel Extra Intellisense extension installed
  - The victim must open a malicious repository/project in VSCode
  - The malicious project must contain a basic Laravel structure (at least an `artisan` file)

- **Source Code Analysis**:
  The vulnerability occurs in the interaction between `helpers.ts` and workspace settings:

  1. In `extension.ts`, when the extension activates, it checks if an "artisan" file exists, indicating a Laravel project
  2. If found, it initializes various providers like RouteProvider, ViewProvider, etc.
  3. These providers use `Helpers.runLaravel()` which in turn calls `Helpers.runPhp()`
  4. In `Helpers.runPhp()`, it retrieves the phpCommand setting without validation:
     ```typescript
     let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
     let command = commandTemplate.replace("{code}", code);
     cp.exec(command, ...);
     ```
  5. An attacker can set the phpCommand to something like `malicious_command & php -r "{code}"` in a `.vscode/settings.json` file
  6. When executed, this will run the malicious command alongside the intended PHP code

- **Security Test Case**:
  1. Create a new directory with a basic Laravel structure (at minimum, include an empty `artisan` file)
  2. Create a `.vscode/settings.json` file with the following content:
     ```json
     {
       "LaravelExtraIntellisense.phpCommand": "echo 'VULNERABLE' > /tmp/hacked.txt && php -r \"{code}\""
     }
     ```
  3. Open this directory in VSCode with the Laravel Extra Intellisense extension installed
  4. Verify that the file `/tmp/hacked.txt` is created, containing the text "VULNERABLE"
  5. In a real attack, the malicious command would be replaced with something far more dangerous

## 2. Path Traversal via basePath and basePathForCode Configuration

- **Vulnerability Name**: Path Traversal via basePath Configuration Settings

- **Description**: The extension allows configuration of custom base paths for the Laravel project via `LaravelExtraIntellisense.basePath` and `LaravelExtraIntellisense.basePathForCode`. These paths are used to construct file paths that are directly included in PHP code without sufficient validation. If an attacker can manipulate these settings, they can potentially cause the extension to execute code from arbitrary locations.

  Steps to trigger:
  1. An attacker creates a malicious repository with a `.vscode/settings.json` file containing crafted basePathForCode setting
  2. When a victim opens this repository, the extension uses these paths to include PHP files
  3. This can lead to inclusion of malicious PHP files or loading of sensitive files from the victim's system

- **Impact**: An attacker could cause the extension to include malicious PHP files from arbitrary locations on the filesystem. This could result in arbitrary code execution within the PHP process.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: There are minimal validations - the code does check if required Laravel files exist before proceeding, but there's no validation of the path content itself.

- **Missing Mitigations**:
  - The extension should validate that the base paths don't contain dangerous path traversal sequences
  - Path sanitization should be implemented to prevent accessing unexpected files
  - A warning should be displayed when custom base paths are specified in workspace settings

- **Preconditions**:
  - The victim has the extension installed
  - The victim opens a malicious repository with custom basePath settings
  - PHP must be installed on the victim's machine

- **Source Code Analysis**:
  In `helpers.ts`, the `projectPath` method allows for configuration of base paths:

  ```typescript
  static projectPath(path:string, forCode: boolean = false) : string {
      if (path[0] !== '/') {
          path = '/' + path;
      }

      let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
      if (forCode === false && basePath && basePath.length > 0) {
          if (basePath.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
              basePath = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePath);
          }
          basePath = basePath.replace(/[\/\\]$/, "");
          return basePath + path;
      }
      // Similar code for basePathForCode
  }
  ```

  This path is then used directly in PHP code construction in the `runLaravel` method:
  ```typescript
  "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
  "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
  ```

  An attacker can set basePathForCode to a location containing malicious PHP files that will be included when the extension runs PHP code.

- **Security Test Case**:
  1. Create a basic Laravel-like structure with an `artisan` file
  2. Create a malicious PHP file outside the project directory (e.g., `/tmp/malicious.php`) containing:
     ```php
     <?php
     file_put_contents('/tmp/path_traversal.txt', 'VULNERABLE');
     ?>
     ```
  3. Create a fake `vendor/autoload.php` and `bootstrap/app.php` in this external location
  4. Add a `.vscode/settings.json` file with:
     ```json
     {
       "LaravelExtraIntellisense.basePathForCode": "/tmp/malicious_project"
     }
     ```
  5. Open the project in VSCode with the extension installed
  6. Verify that `/tmp/path_traversal.txt` is created, confirming the vulnerability
