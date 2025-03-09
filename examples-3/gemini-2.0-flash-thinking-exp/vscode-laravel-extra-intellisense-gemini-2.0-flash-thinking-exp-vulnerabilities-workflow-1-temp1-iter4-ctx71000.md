## Combined Vulnerability List for vscode-laravel-extra-intellisense

### 1. Remote Code Execution via Model Path Injection

* Vulnerability Name: Remote Code Execution via Model Path Injection
* Description:
    1. A threat actor crafts a malicious Laravel repository.
    2. The attacker adds a `.vscode/settings.json` file to the repository, configuring the `LaravelExtraIntellisense.modelsPaths` setting and potentially `LaravelExtraIntellisense.basePathForCode` to include paths they control. For example, setting `LaravelExtraIntellisense.modelsPaths` to `["/tmp/malicious_models"]` or `["."]`, and `LaravelExtraIntellisense.basePathForCode` to `"."`.
    3. The attacker instructs the victim to create the directory specified in `modelsPaths` (e.g., `/tmp/malicious_models`) on their local machine and place a malicious PHP file (e.g., `evil.php`) within it, or includes a malicious PHP file directly within the project if `modelsPaths` includes project directories like `["."]` and `basePathForCode` is set to `.`. This malicious PHP file contains arbitrary PHP code, such as a backdoor or code to execute system commands.
    4. The victim is tricked into opening the malicious repository in VSCode and installing the "Laravel Extra Intellisense" extension.
    5. When the extension initializes or refreshes model information (e.g., upon opening a PHP file or triggering autocompletion), the `EloquentProvider` attempts to load Eloquent models. It reads the `LaravelExtraIntellisense.modelsPaths` setting, which now includes the attacker-controlled path.
    6. The extension iterates through the directories in `modelsPaths` and includes any `.php` files found using `include_once`. This includes the malicious PHP file `evil.php` or `malicious.php`.
    7. The PHP code within the malicious file is executed in the context of the VSCode extension's PHP execution environment, leading to Remote Code Execution on the victim's machine.
* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary PHP code on the victim's machine when they open a malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed. This can lead to complete compromise of the victim's local development environment and potentially further access to other systems, data exfiltration, or malware installation.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The extension directly uses user-provided paths from the `LaravelExtraIntellisense.modelsPaths` setting and `LaravelExtraIntellisense.basePathForCode` without validation or sanitization when including PHP files.
* Missing Mitigations:
    - Input validation and sanitization for the `LaravelExtraIntellisense.modelsPaths` and `LaravelExtraIntellisense.basePathForCode` settings.
    - Path validation to ensure that paths specified in `LaravelExtraIntellisense.modelsPaths` are within the workspace or project directory and prevent absolute paths or paths outside the intended scope. Restrict `modelsPaths` to only include specific, trusted directories (e.g., only within the `app` directory).
    - Sandboxing or isolation of the PHP execution environment to limit the impact of executed code.
    - Displaying a warning to the user when settings like `LaravelExtraIntellisense.modelsPaths` or `LaravelExtraIntellisense.basePathForCode` are modified, especially when opening a new workspace, to alert them about potential security risks.
    - Implementing checks to ensure that included files are actual Laravel models and not arbitrary PHP code (though this might be complex).
* Preconditions:
    - The victim must open a malicious Laravel repository in VSCode.
    - The victim must have the "Laravel Extra Intellisense" extension installed and activated.
    - The malicious repository must contain a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.modelsPaths` and potentially `LaravelExtraIntellisense.basePathForCode` settings to include attacker-controlled paths.
    - The malicious repository must either contain a malicious PHP file in a location included in `modelsPaths`, or the attacker needs to convince the victim to create a directory outside the project and place a malicious PHP file in it.
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

    - **[1]**: The code retrieves the `modelsPaths` configuration from user settings using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])`. This setting, along with `basePathForCode`, is directly used to construct PHP code string without any validation.
    - **[2]**: Inside the PHP code, for each path in `modelsPaths`, the code scans for `.php` files using `scandir(base_path($modelPath))`. `base_path()` resolves based on `basePathForCode` setting.
    - **[3]**: For each `.php` file found, `include_once base_path(\"$modelPath/$sourceFile\")` is used to include the file. If `modelPath` is controlled by the attacker (via `LaravelExtraIntellisense.modelsPaths`), and the attacker places a malicious PHP file in that path, it will be included and executed. Also if `basePathForCode` is set to `"."` and `modelsPaths` contains `"."`, any PHP file in the project root can be included and executed.

* Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a `.vscode` directory, and within it, create a `settings.json` file with the following content:
        ```json
        {
            "LaravelExtraIntellisense.modelsPaths": ["."] ,
            "LaravelExtraIntellisense.basePathForCode": "."
        }
        ```
    3. Inside `malicious-repo`, create a file named `malicious.php` with the following malicious PHP code:
        ```php
        <?php
        file_put_contents(__DIR__ . "/pwned-model-path.txt", "PWNED by Laravel Extra Intellisense Model Path Injection");
        ?>
        ```
    4. Open the `malicious-repo` directory in VSCode.
    5. Install the "Laravel Extra Intellisense" extension if not already installed.
    6. Open any PHP file within the `malicious-repo` or create a new PHP file (e.g., `test.php`). No specific content is needed in this PHP file.
    7. Observe if a file named `pwned-model-path.txt` is created inside the `malicious-repo` directory. If `pwned-model-path.txt` is present and contains "PWNED by Laravel Extra Intellisense Model Path Injection", the vulnerability is confirmed. This indicates that the `malicious.php` file was successfully included and executed by the extension, achieving code execution.

### 2. Command Injection via `phpCommand` setting

* Vulnerability Name: Command Injection via `phpCommand` setting
* Description:
    1. A threat actor creates a malicious Laravel repository.
    2. Within this repository, the threat actor crafts a `.vscode/settings.json` file.
    3. This `settings.json` file is configured to maliciously override the `LaravelExtraIntellisense.phpCommand` setting. The malicious command injected into `phpCommand` is designed to execute arbitrary system commands when the extension attempts to run PHP code. This can be achieved by setting `phpCommand` to a command template like `php -r 'system(\"malicious_command\"); {code}'` or `bash -c "{code}"` where `{code}` placeholder is intended for PHP code execution by the extension. Using `bash -c "{code}"` is especially dangerous as it can lead to command injection even with valid PHP code if it contains shell metacharacters like backticks or `$()`.
    4. A victim user opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension is triggered to provide autocompletion (e.g., when the user opens a PHP or Blade file in the workspace and starts typing code that activates the extension's features), the extension executes PHP code using the command specified in `LaravelExtraIntellisense.phpCommand`.
    6. Due to the malicious configuration and insufficient sanitization, instead of just running PHP code related to Laravel autocompletion, the injected command (like `system("touch /tmp/pwned")` or shell commands within backticks) is executed on the victim's system, either before or as part of the intended PHP code `{code}` execution depending on the injection method.
    7. This results in arbitrary command execution on the victim's machine, effectively allowing the threat actor to compromise the victim's system simply by the victim opening the malicious repository.
* Impact:
    - Remote Code Execution (RCE). Successful exploitation allows the threat actor to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, malware installation, and other malicious activities.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - The extension performs basic escaping of double quotes (`"`) and dollar signs (`$`) in the PHP code snippet (`code`) before substituting it into the `phpCommand`. However, this is insufficient to prevent command injection because the user-controlled `phpCommand` setting itself is not sanitized or validated.  The escaping applied to `{code}` is inadequate as the attacker controls the surrounding command structure within `phpCommand`.
* Missing Mitigations:
    - **Restrict or Sanitize `phpCommand`:** The most critical missing mitigation is to prevent users from directly controlling the command execution template. The extension should either:
        - **Remove user configurability of `phpCommand`:** Hardcode a safe execution command within the extension and do not allow user overrides.
        - **Sanitize and Validate `phpCommand`:** If configurability is necessary, strictly sanitize and validate the `phpCommand` setting to ensure it cannot be used for command injection. This might involve whitelisting allowed commands and options or using secure command construction methods that prevent injection.
        - **Use `cp.spawn` with Argument Separation:** Instead of using `cp.exec` which executes commands in a shell, switch to `cp.spawn`. `cp.spawn` allows passing command arguments as separate parameters, preventing shell injection vulnerabilities by avoiding shell interpretation of the command string.
        - **Warn Users:** If `phpCommand` configurability is retained without robust sanitization, display a clear and prominent warning to users about the security risks of modifying this setting, especially when opening workspaces from untrusted sources.
* Preconditions:
    - The victim must open a malicious Laravel repository in VSCode.
    - The victim must have the Laravel Extra Intellisense extension installed and activated.
    - The malicious repository must contain a `.vscode/settings.json` file that overrides `LaravelExtraIntellisense.phpCommand` with a malicious command template.
    - The extension needs to be enabled for the opened workspace.
* Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\""); // Basic escaping of double quotes in PHP code
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Retrieve phpCommand setting, default is "php -r \"{code}\""
        let command = commandTemplate.replace("{code}", code); // Substitute {code} placeholder with user-provided PHP code (after basic escaping)
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Execute the constructed command using child_process.exec
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ... handle command execution and errors ...
                }
            );
        });
        return out;
    }
    ```
    - The `runPhp` function retrieves the `phpCommand` setting from the workspace configuration without validation or sanitization.
    - It substitutes the `{code}` placeholder in the `phpCommand` with the provided `$code` after performing insufficient escaping.
    - It then uses `cp.exec` to execute the resulting command in a shell.
    - **Vulnerability point:** The lack of sanitization of the `phpCommand` setting allows for command injection. If a malicious user provides a crafted `phpCommand`, they can inject arbitrary commands that will be executed by `cp.exec`. The use of `cp.exec` and allowing user-configurable command template are the root causes of this vulnerability.

* Security Test Case:
    1. **Setup Malicious Repository:**
        - Create a new directory named `malicious-laravel-repo-phpcommand`.
        - Inside `malicious-laravel-repo-phpcommand`, create a `.vscode` directory.
        - Inside `.vscode`, create a file named `settings.json`.
        - Add the following content to `settings.json`:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned-phpcommand && {code}'"
            }
            ```
        - You do not need to create a full Laravel project; a minimal directory structure with the malicious settings file is sufficient to demonstrate the vulnerability.

    2. **Open Malicious Repository in VSCode:**
        - Open VSCode.
        - Open the `malicious-laravel-repo-phpcommand` directory as a workspace (File -> Open Folder...).
        - Ensure the "Laravel Extra Intellisense" extension is installed and enabled for this workspace.

    3. **Trigger Extension Activity:**
        - Open any PHP file in the `malicious-laravel-repo-phpcommand` directory or create a new one (e.g., `test.php`).
        - Trigger extension functionality, for example by typing `route(` in a PHP file to invoke route autocompletion.

    4. **Verify Command Injection:**
        - After triggering the extension, check if the file `/tmp/pwned-phpcommand` has been created on your system.
        - **If the file `/tmp/pwned-phpcommand` exists, the command injection vulnerability is confirmed.** This indicates that the `touch /tmp/pwned-phpcommand` command injected through the malicious `phpCommand` setting was successfully executed before the intended PHP code.
