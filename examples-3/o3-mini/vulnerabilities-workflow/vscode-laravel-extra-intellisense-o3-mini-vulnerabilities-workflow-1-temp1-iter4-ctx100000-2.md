# Vulnerability List

## 1. Vulnerability Name: Command Injection via Malicious phpCommand Configuration

**Description:**
An attacker can include a malicious `.vscode/settings.json` in a repository that overrides the default value for `LaravelExtraIntellisense.phpCommand`. The extension retrieves this configuration value and passes it to the helper function that builds a shell command by replacing a `{code}` placeholder. Because no proper escaping or validation is performed on the configuration value, an attacker can inject additional shell commands.
*Steps to Trigger:*
1. A malicious repository is created containing a `.vscode/settings.json` file which overrides the default `phpCommand` configuration with a payload that includes additional shell commands (e.g., appending `; rm -rf /` after the original command).
2. The victim opens this repository in VSCode as a trusted workspace, causing the unsafe configuration to be loaded automatically.
3. The extension triggers a feature that calls the helper (e.g., during a Laravel command execution), resulting in the construction of a shell command that includes the injected commands.

**Impact:**
The injected shell command(s) will be executed on the victim’s machine when the extension calls the helper to run Laravel code (via `cp.exec`). This can lead to complete remote code execution and full system compromise.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension simply reads the configuration value via VSCode’s workspace configuration.
- No additional sanitization or escaping is applied in the helper function (`Helpers.runPhp`).

**Missing Mitigations:**
- Proper validation and escaping of the `phpCommand` string to ensure that shell metacharacters cannot be injected.
- Restricting configuration sources or warning the user when an unsafe configuration value is detected.

**Preconditions:**
- The victim opens a repository (or project workspace) that contains a manipulated `.vscode/settings.json` file.
- The malicious file overrides `LaravelExtraIntellisense.phpCommand` with a payload containing extra shell commands (for example, appending `; rm -rf /` or any arbitrary command).

**Source Code Analysis:**
1. In `Helpers.runPhp`, the code retrieves the command template with:
   ```ts
   let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
   ```
2. It then performs a simple replacement:
   ```ts
   let command = commandTemplate.replace("{code}", code);
   ```
3. Finally, it calls `cp.exec(command, …)` without sanitizing or validating the resulting string.
4. Since the configuration value is fully user-controlled (e.g., provided via `.vscode/settings.json` in a trusted workspace), an attacker can supply a command template that executes additional malicious commands.

**Security Test Case:**
1. Create a test repository that includes a `.vscode/settings.json` file with a malicious override such as:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo 'Injected';"
   }
   ```
2. Open this repository in VSCode (ensuring that the workspace is trusted so that the settings apply).
3. Trigger an action of the extension that calls `Helpers.runLaravel` (for example, by requesting autocompletion from a provider such as the ConfigProvider).
4. Monitor the output channel or terminal to verify that the additional “Injected” string is output, confirming that the extra shell command was executed.
5. This test confirms that an attacker can inject arbitrary shell commands.

---

## 2. Vulnerability Name: Code Injection via Manipulated basePathForCode Configuration

**Description:**
The extension builds PHP code dynamically (to bootstrap and probe the Laravel application) by using configuration values obtained through `LaravelExtraIntellisense.basePathForCode` (as well as `basePath`). These values are inserted directly into PHP `require/include` statements without proper escaping. An attacker who supplies a malicious repository may include a `.vscode/settings.json` that sets, for example, the `basePathForCode` to a payload containing a closing quote and arbitrary PHP code. When the helper function concatenates this value into a PHP `require_once` statement, the injected PHP code is executed.
*Steps to Trigger:*
1. A malicious repository is created that contains a `.vscode/settings.json` file setting `basePathForCode` to a payload such as `/var/www/html'; system('echo Injected'); //`.
2. The victim opens the repository in VSCode as a trusted workspace, causing the manipulated configuration to be loaded.
3. The extension invokes a function (e.g., `Helpers.runLaravel`) that uses the unsanitized configuration value to dynamically generate PHP code.
4. During the PHP code generation (notably, within a `require_once` statement), the injected payload breaks out of the intended string context and executes arbitrary PHP commands.

**Impact:**
Arbitrary PHP code injection occurs within the context of the local Laravel application. When the injected PHP code is executed (via the `php -r` invocation), it provides a pathway for full remote code execution on the victim’s system.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The configuration value is read directly without any sanitization.
- No escaping or validation is performed on the values returned by the VSCode configuration.

**Missing Mitigations:**
- Verification that any string read from user-controlled configuration (`basePathForCode` and `basePath`) does not contain quotes, shell/metacharacters, or other unexpected tokens.
- Escaping or sanitization when concatenating configuration values into the dynamically generated PHP code.

**Preconditions:**
- The victim opens a repository containing a manipulated `.vscode/settings.json` that sets `LaravelExtraIntellisense.basePathForCode` with a payload such as:
  ```
  /var/www/html'; system('echo Injected'); //
  ```
- The manipulated value is used by `Helpers.projectPath` (with `forCode` set to true) to generate the path used in `require_once` calls within `Helpers.runLaravel`.

**Source Code Analysis:**
1. In `Helpers.projectPath`, the code obtains the configuration value:
   ```ts
   let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
   if (forCode && basePathForCode && basePathForCode.length > 0) {
       if (basePathForCode.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
           basePathForCode = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePathForCode);
       }
       basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
       return basePathForCode + path;
   }
   ```
2. The resulting string is then concatenated into PHP code (for example, as part of a `require_once` statement in `Helpers.runLaravel`).
3. Because no sanitization or escaping is performed, the presence of a single quote or other special characters in the configuration value allows for the injection of arbitrary PHP commands.

**Security Test Case:**
1. Create a test repository that includes a `.vscode/settings.json` file with a malicious override such as:
   ```json
   {
     "LaravelExtraIntellisense.basePathForCode": "/var/www/html'; system('echo Injected'); //"
   }
   ```
2. Open the repository in VSCode (with a trusted workspace so that the settings are applied).
3. Trigger the extension to execute a Laravel command (for instance, by initiating a `Helpers.runLaravel` call through an autocompletion action).
4. Observe the PHP command output (or check the logging in the output channel) for the appearance of the word “Injected.”
5. The appearance of the injected string confirms that the unsanitized configuration value allowed PHP code injection and arbitrary PHP command execution.
