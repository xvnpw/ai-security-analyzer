### Vulnerability List

- Vulnerability Name: Command Injection in `phpCommand` setting
  - Description:
    1. A threat actor creates a malicious Laravel project.
    2. The threat actor modifies the `.vscode/settings.json` file within the malicious project and sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "php -r \\"system('calc');\\""`. This setting is intended to customize the PHP command used by the extension, but can be abused for command injection.
    3. The threat actor distributes this malicious Laravel project to a victim, for example, by hosting it on a public code repository.
    4. The victim clones or downloads the malicious project and opens it in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension initializes or performs any operation that triggers the execution of PHP code (e.g., autocompletion in a PHP or Blade file), the extension reads the `LaravelExtraIntellisense.phpCommand` setting from `.vscode/settings.json`.
    6. The extension executes the malicious command specified in the `phpCommand` setting using `child_process.exec` in `helpers.ts`.
    7. As a result, arbitrary commands, such as launching the calculator application (`calc`), are executed on the victim's machine.
  - Impact: Remote Code Execution. An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further propagation of attacks.
  - Vulnerability Rank: Critical
  - Currently implemented mitigations: None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
  - Missing mitigations:
    - Input validation and sanitization for the `phpCommand` setting. The extension should validate that the `phpCommand` setting only contains a safe PHP command invocation and arguments. Ideally, it should restrict the command to only execute `php -r` and disallow any other commands or options.
    - Consider disallowing user configuration of the entire command and only allow configuration of specific parameters like the PHP executable path if necessary.
    - Display a warning message to the user when a workspace setting overrides the default `phpCommand`, indicating potential security risks.
  - Preconditions:
    - The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim opens a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand` setting.
  - Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
    - Line: `let command = commandTemplate.replace("{code}", code);`
    - Line: `cp.exec(command, ...)`
    - The `runPhp` function retrieves the `phpCommand` from the configuration without any validation.
    - It then uses `replace("{code}", code)` to insert the PHP code to be executed, but the command itself is taken directly from user settings.
    - The constructed `command` is then executed using `cp.exec`, which can lead to command injection if the `phpCommand` setting is maliciously crafted.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: User-controlled command template
        let command = commandTemplate.replace("{code}", code); // Command constructed with user input
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable line: Command execution
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    if (err == null) {
                        if (description != null) {
                            Helpers.outputChannel?.info("Laravel Extra Intellisense Resolved: " + description);
                        }
                        resolve(stdout);
                    } else {
                        const errorOutput = stderr.length > 0 ? stderr : stdout;
                        Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\n\n' + errorOutput);
                        Helpers.showErrorPopup();
                        error(errorOutput);
                    }
                }
            );
        });
        return out;
    }
    ```
  - Security test case:
    1. Create a new folder for a malicious Laravel project.
    2. Inside the folder, create a `.vscode` subfolder.
    3. Inside `.vscode`, create a `settings.json` file with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \\"system('calc');\\""
    }
    ```
    4. Open the malicious project folder in VSCode with the "Laravel Extra Intellisense" extension enabled.
    5. Open any PHP file (e.g., create an empty `test.php` file in the project root and open it).
    6. Observe that the calculator application (`calc.exe` on Windows, `calc` on Linux/macOS) is launched. This confirms arbitrary command execution due to the malicious `phpCommand` setting.

- Vulnerability Name: Code Injection via `modelsPaths` setting in EloquentProvider
  - Description:
    1. A threat actor creates a malicious Laravel project.
    2. The threat actor creates a malicious PHP file within the project, for instance, named `malicious.php`, containing arbitrary PHP code, such as `<?php system('calc'); ?>`.
    3. The threat actor modifies the `.vscode/settings.json` file in the malicious project and sets the `LaravelExtraIntellisense.modelsPaths` configuration to include the directory containing the malicious PHP file, for example: `"LaravelExtraIntellisense.modelsPaths": ["."]` if `malicious.php` is in the project root. This setting is intended to specify paths to model files for autocompletion, but can be abused for code injection.
    4. The threat actor distributes this malicious Laravel project to a victim.
    5. The victim opens the malicious project in VSCode with the "Laravel Extra Intellisense" extension installed.
    6. When the extension initializes or performs operations related to Eloquent models (e.g., autocompletion for model attributes), the `EloquentProvider` is activated.
    7. The `EloquentProvider` reads the `LaravelExtraIntellisense.modelsPaths` setting from `.vscode/settings.json`.
    8. The extension constructs PHP code in `loadModels` function in `EloquentProvider.ts` that iterates through the configured paths and uses `include_once` to include PHP files found in those paths.
    9. Because the `modelsPaths` setting is controlled by the attacker and points to a directory containing `malicious.php`, the `include_once base_path("$modelPath/$sourceFile")` statement in the generated PHP code includes and executes the malicious PHP file.
    10. As a result, the arbitrary PHP code within `malicious.php`, such as launching the calculator application (`calc`), is executed on the victim's machine.
  - Impact: Remote Code Execution. An attacker can execute arbitrary PHP code on the victim's machine by including a malicious PHP file through the `modelsPaths` setting. This can lead to the same severe consequences as Command Injection, including system compromise and data theft.
  - Vulnerability Rank: Critical
  - Currently implemented mitigations: None. The extension directly uses the user-provided `modelsPaths` setting to include PHP files without proper validation or sanitization.
  - Missing mitigations:
    - Input validation and sanitization for the `modelsPaths` setting. The extension should validate that the paths in `modelsPaths` are within the workspace and ideally, within expected model directories.
    - Restrict file inclusion to only files within the intended model directories and avoid including files based on user-provided paths directly.
    - Consider parsing model files statically instead of executing them via `include_once`. This would eliminate the risk of code execution from included files.
    - Display a warning message if `modelsPaths` is configured outside of standard model directories, indicating a potential security risk.
  - Preconditions:
    - The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim opens a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.modelsPaths` setting, and a malicious PHP file within the specified paths.
  - Source code analysis:
    - File: `src/EloquentProvider.ts`
    - Function: `loadModels()`
    - Lines:
    ```typescript
    Helpers.runLaravel(
        "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
        "   if (is_dir(base_path($modelPath))) {" +
        "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
        "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
        "             include_once base_path(\"$modelPath/$sourceFile\");" + // Vulnerable line: Dynamic file inclusion based on user setting
        "         }" +
        "      }" +
        "   }" +
        "}" +
        "..."
    ```
    - The `loadModels` function constructs PHP code that iterates through paths specified in `modelsPaths` setting.
    - It uses `include_once base_path("$modelPath/$sourceFile")` to include PHP files from these paths.
    - This dynamic file inclusion, based on user-controlled `modelsPaths`, allows for code injection if a malicious path and PHP file are provided.
  - Security test case:
    1. Create a new folder for a malicious Laravel project.
    2. Inside the folder, create a `malicious.php` file with the following content:
    ```php
    <?php system('calc'); ?>
    ```
    3. Inside the folder, create a `.vscode` subfolder.
    4. Inside `.vscode`, create a `settings.json` file with the following content:
    ```json
    {
        "LaravelExtraIntellisense.modelsPaths": ["."]
    }
    ```
    5. Open the malicious project folder in VSCode with the "Laravel Extra Intellisense" extension enabled.
    6. Open any PHP file (e.g., create an empty `test.php` file in the project root and open it).
    7. Observe that the calculator application (`calc.exe` on Windows, `calc` on Linux/macOS) is launched. This confirms arbitrary code execution due to the malicious `modelsPaths` setting leading to file inclusion.
