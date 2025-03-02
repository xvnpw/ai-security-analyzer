### Vulnerability List:

- **Vulnerability Name:**  Command Injection via `phpCommand` configuration
  - **Description:**
    1. A threat actor can craft a malicious repository containing a `.vscode/settings.json` file.
    2. This settings file can override the `LaravelExtraIntellisense.phpCommand` configuration of the VSCode extension.
    3. The threat actor can inject arbitrary shell commands into the `phpCommand` setting. For example, they could set it to `php -r "{code}; malicious_command"`.
    4. When the victim opens the malicious repository in VSCode and the Laravel Extra Intellisense extension activates, the extension will use the attacker-controlled `phpCommand` to execute PHP code.
    5. Because the `phpCommand` now contains injected shell commands, these commands will be executed on the victim's machine in addition to the intended PHP code.
  - **Impact:** Remote Code Execution (RCE). The attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could allow the attacker to steal sensitive information, install malware, or compromise the victim's system.
  - **Vulnerability Rank:** Critical
  - **Currently Implemented Mitigations:**
    - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
  - **Missing Mitigations:**
    - Input sanitization and validation for the `phpCommand` setting. The extension should prevent users from injecting shell commands.
    - Restricting the characters allowed in `phpCommand`.
    - Displaying a warning to the user when `phpCommand` is modified from workspace settings, especially if it deviates from a safe default.
    - Consider using a safer method for executing PHP code, potentially avoiding shell execution entirely if possible, or using secure execution sandboxes.
  - **Preconditions:**
    - Victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - Victim must open a malicious repository in VSCode that contains a crafted `.vscode/settings.json` file.
    - Workspace settings override user settings in VSCode, so no specific user setting is needed for exploitation if workspace settings are present.
  - **Source Code Analysis:**
    1. **File: `src/helpers.ts`**
    2. **Function: `runPhp(code: string, description: string|null = null)`**
    3. The function retrieves the `phpCommand` from VSCode configuration:
       ```typescript
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       ```
    4. It then replaces the `{code}` placeholder with the provided PHP code:
       ```typescript
       let command = commandTemplate.replace("{code}", code);
       ```
    5. Finally, it executes the constructed command using `cp.exec`:
       ```typescript
       cp.exec(command, ... , function (err, stdout, stderr) { ... });
       ```
    6. **Vulnerability:** The `commandTemplate` is directly taken from user configuration (`phpCommand`). If a malicious user provides a `phpCommand` that includes shell commands, these commands will be executed by `cp.exec`. There is no input validation or sanitization on the `phpCommand` setting. The `{code}` placeholder replacement does not prevent command injection because it's still within the context of shell execution.

    ```mermaid
    graph LR
        A[VSCode Configuration System] --> B(getConfiguration('LaravelExtraIntellisense').get('phpCommand'));
        B --> C{phpCommand Value};
        C --> D{Construct Command};
        D --> E(cp.exec(command));
        E --> F[System Shell];
        F -- Executes php and injected commands --> G[Victim Machine];
    ```

  - **Security Test Case:**
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch /tmp/rce_vulnerability_confirmed'"
       }
       ```
    4. Open VSCode and open the `malicious-repo` directory as a workspace.
    5. Open any PHP or Blade file in the workspace (or create a new one).
    6. Trigger any autocompletion feature of the Laravel Extra Intellisense extension that executes PHP code. For example, in a PHP file, type `config('app.` and wait for config autocompletion suggestions to appear.
    7. After the autocompletion feature is triggered, check if the file `/tmp/rce_vulnerability_confirmed` exists on the victim's system.
    8. If the file exists, the command injection vulnerability is confirmed.

- **Vulnerability Name:** Code Injection via `require_once` and `basePathForCode` manipulation
  - **Description:**
    1. A threat actor can create a malicious repository and configure `LaravelExtraIntellisense.basePathForCode` to point to a directory they control, either within the workspace or an absolute path if the victim allows it.
    2. The attacker places a malicious PHP file (e.g., `malicious.php`) in the controlled directory. This file contains arbitrary PHP code to be executed.
    3. The extension uses `require_once` with paths constructed using `basePathForCode`.
    4. If the attacker sets `basePathForCode` to their controlled directory and the extension attempts to `require_once` a file based on this path, the malicious file `malicious.php` can be included.
    5. When the extension executes PHP code that triggers the inclusion of this file (e.g., during model loading or view parsing), the malicious PHP code within `malicious.php` will be executed on the victim's machine.
  - **Impact:** Remote Code Execution (RCE). The attacker can execute arbitrary PHP code within the context of the Laravel application, potentially leading to full application compromise and access to the victim's system.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - None. The extension uses `basePathForCode` directly in `require_once` statements without sufficient validation to prevent path traversal or inclusion of malicious files.
  - **Missing Mitigations:**
    - Path validation for `basePathForCode` to ensure it points only within the intended project directory.
    - Preventing absolute paths in `basePathForCode` configuration.
    - Input sanitization to prevent path traversal characters in `basePathForCode`.
    - Consider using `include` instead of `require_once` and implement checks to verify the integrity and origin of included files.
  - **Preconditions:**
    - Victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - Victim must open a malicious repository in VSCode.
    - The malicious repository must contain a `.vscode/settings.json` file to set a malicious `LaravelExtraIntellisense.basePathForCode`.
  - **Source Code Analysis:**
    1. **File: `src/helpers.ts`**
    2. **Function: `projectPath(path:string, forCode: boolean = false)`**
    3. This function constructs file paths using `basePathForCode` when `forCode` is true.
       ```typescript
       let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
       if (forCode && basePathForCode && basePathForCode.length > 0) {
           ...
           return basePathForCode + path;
       }
       ```
    4. **File: `src/EloquentProvider.ts`**
    5. **Function: `loadModels()`**
    6. Inside `loadModels`, the extension iterates through configured `modelsPaths` and uses `require_once` to include PHP files:
       ```typescript
       "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
       "             include_once base_path(\"$modelPath/$sourceFile\");" +
       "         }" +
       ```
    7. **Vulnerability:** The `base_path()` function in the dynamically generated PHP code, when resolved by Laravel, uses `Helpers.projectPath(..., true)` which is influenced by `basePathForCode`. By manipulating `basePathForCode`, an attacker can control the base path used in `require_once`, leading to inclusion of arbitrary PHP files.

    ```mermaid
    graph LR
        A[VSCode Configuration System] --> B(getConfiguration('LaravelExtraIntellisense').get('basePathForCode'));
        B --> C{basePathForCode Value};
        C --> D(Helpers.projectPath(..., true));
        D --> E{Constructed File Path};
        E --> F(require_once(filePath));
        F --> G[PHP Interpreter];
        G -- Executes malicious php code --> H[Victim Machine];
    ```

  - **Security Test Case:**
    1. Create a new directory named `malicious-repo-code-injection`.
    2. Inside `malicious-repo-code-injection`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "LaravelExtraIntellisense.basePathForCode": "/tmp"
       }
       ```
    4. In `/tmp`, create a file named `malicious.php` with the following content:
       ```php
       <?php
           touch('/tmp/code_injection_vulnerability_confirmed');
       ?>
       ```
    5. Open VSCode and open the `malicious-repo-code-injection` directory as a workspace.
    6. Trigger the Eloquent model autocompletion feature. This can be done by opening a PHP file and typing `Product::` to trigger static method suggestions for an Eloquent model.
    7. After triggering the autocompletion, check if the file `/tmp/code_injection_vulnerability_confirmed` exists on the victim's system.
    8. If the file exists, the code injection vulnerability is confirmed, as the extension likely attempted to load models and in the process included `/tmp/malicious.php` due to the manipulated `basePathForCode`.
