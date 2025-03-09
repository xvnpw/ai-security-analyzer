## Vulnerability List for vscode-laravel-extra-intellisense

### 1. Remote Code Execution via Model Path Injection

* Vulnerability Name: Remote Code Execution via Model Path Injection
* Description:
    1. A threat actor crafts a malicious Laravel repository.
    2. The attacker adds a `.vscode/settings.json` file to the repository, configuring the `LaravelExtraIntellisense.modelsPaths` setting to include a path they control, for example: `/tmp/malicious_models`.
    3. The attacker instructs the victim to create the directory specified in `modelsPaths` (e.g., `/tmp/malicious_models`) on their local machine and place a malicious PHP file (e.g., `evil.php`) within it. This file contains arbitrary PHP code, such as a backdoor or code to execute system commands.
    4. The victim is tricked into opening the malicious repository in VSCode and installing the "Laravel Extra Intellisense" extension.
    5. When the extension initializes, the `EloquentProvider` attempts to load Eloquent models. It reads the `LaravelExtraIntellisense.modelsPaths` setting, which now includes the attacker-controlled path.
    6. The extension iterates through the directories in `modelsPaths` and includes any `.php` files found using `include_once`. This includes the malicious PHP file `evil.php`.
    7. The PHP code within `evil.php` is executed in the context of the VSCode extension's PHP execution environment, leading to Remote Code Execution on the victim's machine.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary PHP code on the victim's machine when they open a malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed. This can lead to complete compromise of the victim's local development environment and potentially further access to other systems.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The extension directly uses user-provided paths from the `LaravelExtraIntellisense.modelsPaths` setting without validation or sanitization when including PHP files.
* Missing Mitigations:
    - Input validation and sanitization for the `LaravelExtraIntellisense.modelsPaths` setting.
    - Path validation to ensure that paths specified in `LaravelExtraIntellisense.modelsPaths` are within the workspace or project directory and prevent absolute paths or paths outside the intended scope.
    - Sandboxing or isolation of the PHP execution environment to limit the impact of executed code.
    - Displaying a warning to the user when settings like `LaravelExtraIntellisense.modelsPaths` are modified, especially when opening a new workspace, to alert them about potential security risks.
* Preconditions:
    - The victim must open a malicious Laravel repository in VSCode.
    - The victim must have the "Laravel Extra Intellisense" extension installed and activated.
    - The attacker needs to convince the victim to create a directory outside the project and place a malicious PHP file in it, or find a common writable location.
    - The malicious repository must contain a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.modelsPaths` setting to include the attacker's malicious path.
* Source Code Analysis:
    - File: `src/EloquentProvider.ts`
    - Function: `loadModels()`

    ```typescript
    loadModels() {
        var self = this;
        try {
            Helpers.runLaravel(
                "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" + // [1]
                "   if (is_dir(base_path($modelPath))) {" +
                "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
                "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" + // [2]
                "             include_once base_path(\"$modelPath/$sourceFile\");" + // [3]
                "         }" +
                "      }" +
                "   }" +
                "}" +
                "..."
                ,
                "Eloquent Attributes and Relations"
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

    - **[1]**: The code retrieves the `modelsPaths` configuration from user settings using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])`. This setting is directly embedded into the PHP code string without any validation.
    - **[2]**: Inside the PHP code, for each path in `modelsPaths`, the code scans for `.php` files using `scandir(base_path($modelPath))`.
    - **[3]**: For each `.php` file found, `include_once base_path(\"$modelPath/$sourceFile\")` is used to include the file. If `modelPath` is controlled by the attacker (via `LaravelExtraIntellisense.modelsPaths`), and the attacker places a malicious PHP file in that path, it will be included and executed.

* Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a `.vscode` directory, and within it, create a `settings.json` file with the following content:
        ```json
        {
            "LaravelExtraIntellisense.modelsPaths": ["/tmp/malicious_models"]
        }
        ```
    3. On the *victim's machine*, open a terminal and create a directory `/tmp/malicious_models`:
        ```bash
        mkdir /tmp/malicious_models
        ```
    4. Inside `/tmp/malicious_models`, create a file named `evil.php` with the following malicious PHP code:
        ```php
        <?php
        file_put_contents(__DIR__ . "/pwned.txt", "PWNED by Laravel Extra Intellisense");
        ?>
        ```
    5. Open the `malicious-repo` directory in VSCode.
    6. Install the "Laravel Extra Intellisense" extension if not already installed.
    7. Open any PHP file within the `malicious-repo` or create a new PHP file (e.g., `test.php`). No specific content is needed in this PHP file.
    8. Observe if a file named `pwned.txt` is created inside the `/tmp/malicious_models` directory on the victim's machine. If `pwned.txt` is present and contains "PWNED by Laravel Extra Intellisense", the vulnerability is confirmed. This indicates that the `evil.php` file was successfully included and executed by the extension, achieving code execution.
