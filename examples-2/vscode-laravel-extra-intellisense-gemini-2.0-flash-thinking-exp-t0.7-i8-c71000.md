### Vulnerability List

#### 1. Code Injection via Malicious Laravel Application Bootstrapping

* Description:
    A threat actor can exploit a code injection vulnerability by crafting a malicious Laravel repository. This repository contains a `.vscode/settings.json` file that configures the `LaravelExtraIntellisense.basePathForCode` setting to point to the repository's root directory.  The attacker then replaces legitimate Laravel bootstrapping files, specifically `vendor/autoload.php` and/or `bootstrap/app.php`, with malicious PHP code. When a victim opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension activated, the extension, upon initialization or when providing autocompletion features, executes PHP code using `Helpers.runLaravel`. This function uses `require_once` and `include_once` with paths constructed using the attacker-controlled `LaravelExtraIntellisense.basePathForCode`, leading to the inclusion and execution of the malicious bootstrapping files. Consequently, the attacker's arbitrary PHP code is executed on the victim's machine.

    **Step-by-step trigger:**
    1. A threat actor creates a malicious Laravel repository.
    2. The malicious repository includes a `.vscode/settings.json` file that sets `LaravelExtraIntellisense.basePathForCode` to point to the root directory of the malicious repository (e.g., ".").
    3. The threat actor replaces legitimate Laravel bootstrapping files, specifically `vendor/autoload.php` and/or `bootstrap/app.php`, within the malicious repository with PHP files containing arbitrary malicious code.
    4. A victim opens this malicious Laravel repository in VSCode with the "Laravel Extra Intellisense" extension activated.
    5. When the extension initializes or attempts to provide autocompletion features, it executes PHP code using `Helpers.runLaravel`.
    6. `Helpers.runLaravel` uses `require_once` and `include_once` with paths constructed using `LaravelExtraIntellisense.basePathForCode`. Due to the malicious configuration, this leads to the inclusion and execution of the attacker's malicious `vendor/autoload.php` or `bootstrap/app.php` files.
    7. The attacker's arbitrary PHP code is executed on the victim's machine, achieving code injection.

* Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary code on a victim's machine simply by the victim opening a malicious Laravel project in VSCode with the extension installed. This can lead to complete system compromise, data exfiltration, or other malicious activities.

* Vulnerability Rank:
    Critical

* Currently implemented mitigations:
    None. The extension directly uses the `basePathForCode` configuration value without any validation or sanitization when constructing paths for `require_once` and `include_once`.

* Missing mitigations:
    - Validate the `LaravelExtraIntellisense.basePathForCode` setting to ensure it points to a valid and expected Laravel project structure.
    - Sanitize the `basePathForCode` to prevent directory traversal attacks.
    - Restrict `basePathForCode` to be within the workspace or a trusted location.
    - Consider removing the `basePathForCode` setting and rely on workspace root detection for project path resolution to simplify path handling and reduce attack surface.

* Preconditions:
    - Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - Victim opens a workspace containing a malicious Laravel repository provided by the threat actor.
    - The malicious repository is crafted with a malicious `.vscode/settings.json` and malicious Laravel bootstrapping files (`vendor/autoload.php`, `bootstrap/app.php`).

* Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runLaravel(code: string, description: string|null = null)`
    ```typescript
    static runLaravel(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
        if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) { // [POINT OF CONCERN] Paths constructed with Helpers.projectPath
            var command =
                "define('LARAVEL_START', microtime(true));" +
                "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" + // [POINT OF CONCERN] Uses basePathForCode
                "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" + // [POINT OF CONCERN] Uses basePathForCode
                "..."
    ```
    3. File: `src/helpers.ts`
    4. Function: `projectPath(path:string, forCode: boolean = false)`
    ```typescript
    static projectPath(path:string, forCode: boolean = false) : string {
        ...
        let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
        if (forCode && basePathForCode && basePathForCode.length > 0) { // [POINT OF CONCERN] basePathForCode is user-configurable
            if (basePathForCode.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                basePathForCode = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePathForCode);
            }
            basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
            return basePathForCode + path; // [POINT OF CONCERN] Path concatenation without validation
        }
        ...
    }
    ```
    The `projectPath` function, when `forCode` is true, uses the `basePathForCode` setting to construct file paths. This setting is directly configurable by the user and is used without validation when concatenating paths, leading to potential code injection through malicious file inclusion.

* Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a directory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
        ```json
        {
            "LaravelExtraIntellisense.basePathForCode": "."
        }
        ```
    4. Inside `malicious-laravel-project`, create a directory named `vendor`.
    5. Inside `vendor`, create a file named `autoload.php` with the following malicious PHP code (for Windows, for other OS use `touch /tmp/pwned`):
        ```php
        <?php
        system('calc.exe');
        ```
    6. Open VSCode and open the `malicious-laravel-project` directory as a workspace.
    7. Activate the "Laravel Extra Intellisense" extension for this workspace if it's not already active.
    8. Open any PHP file in the workspace or trigger any feature of the extension that relies on Laravel functionality (e.g., autocompletion in a Blade file).
    9. Observe if the calculator application (`calc.exe`) launches, indicating successful code injection and RCE.

#### 2. Command Injection via `phpCommand` Configuration

* Description:
    The "Laravel Extra Intellisense" VSCode extension allows users to customize the command used to execute PHP code through the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended for users to adapt the extension to different environments, such as Docker or Laravel Sail. However, the extension's `runPhp` function in `src/helpers.ts` directly incorporates this user-configurable setting into shell commands executed using `child_process.exec` without sufficient sanitization. A malicious actor can craft a workspace configuration file (`.vscode/settings.json`) that overrides the `phpCommand` setting with malicious commands. When a victim opens this malicious repository in VSCode, the extension will use this malicious `phpCommand` to execute PHP code, leading to command injection and arbitrary command execution on the victim's machine.

    **Step-by-step trigger:**
    1. Attacker creates a malicious Laravel project repository.
    2. Inside the repository, the attacker creates a `.vscode` directory.
    3. Inside the `.vscode` directory, the attacker creates a `settings.json` file.
    4. In `settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "php -r \\"{code}; system('calc.exe');\\""`.
    5. The attacker distributes this malicious Laravel project to a victim, for example, by hosting it on a public code repository or via email.
    6. Victim clones or downloads the malicious project and opens it in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    7. The extension activates upon opening the workspace and attempts to gather Laravel project information by executing PHP code using `Helpers.runPhp`.
    8. The extension reads the workspace settings, including the attacker-controlled `LaravelExtraIntellisense.phpCommand`.
    9. When the extension attempts to gather autocompletion data (e.g., route list, view list, etc.), it uses `Helpers.runPhp` with the malicious `phpCommand`.
    10. The `system('calc.exe')` command injected by the attacker is executed on the victim's machine.

* Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by manipulating the `phpCommand` configuration setting. This can lead to complete system compromise, data exfiltration, malware installation, and further propagation of attacks.

* Vulnerability Rank:
    Critical

* Currently implemented mitigations:
    None. The extension directly utilizes the `phpCommand` configuration string in `cp.exec` without any validation or sanitization. While the `runPhp` function attempts to escape double quotes and dollar signs in the PHP code itself, it does not sanitize or validate the `phpCommand` setting.

* Missing mitigations:
    - Validate and sanitize the `LaravelExtraIntellisense.phpCommand` setting to remove or escape potentially harmful characters and commands. Ideally, restrict the command to only execute `php -r "{code}"` and disallow any other commands or options.
    - Avoid using `phpCommand` as a template where user-provided code is directly substituted. Instead, construct the PHP execution command in a safer, programmatic way, possibly using `child_process.spawn` and passing arguments as separate parameters.
    - Consider restricting the allowed commands or arguments within `phpCommand` to a predefined safe list, or completely disallow user modification of the core execution command.
    - Display a warning message to the user when a workspace setting overrides the default `phpCommand`, indicating potential security risks.

* Preconditions:
    - Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - Victim opens a workspace in VSCode that contains or applies a malicious `.vscode/settings.json` file that configures `LaravelExtraIntellisense.phpCommand` with injected commands.
    - The extension attempts to execute PHP code, triggering the vulnerable `Helpers.runPhp` function.

* Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null) : Promise<string>`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [POINT OF CONCERN] phpCommand is user-configurable
        let command = commandTemplate.replace("{code}", code); // [POINT OF CONCERN] Direct substitution, potential for injection
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [POINT OF CONCERN] Command execution with user-influenced command string
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                ...
    ```
    The vulnerability lies in the `commandTemplate.replace("{code}", code)` line, where user-controlled `phpCommand` setting is used as a template and directly substituted with PHP code without proper sanitization, leading to command injection when executed by `cp.exec`.

* Security test case:
    1. Create a new directory named `command-injection-test`.
    2. Inside `command-injection-test`, create a directory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content (for Windows, for other OS use `touch /tmp/pwned`):
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('calc.exe');\""
        }
        ```
    4. Open VSCode and open the `command-injection-test` directory as a workspace.
    5. Activate the "Laravel Extra Intellisense" extension for this workspace if it's not already active.
    6. Open any PHP file in the workspace or trigger any feature of the extension that relies on PHP execution (e.g., autocompletion for routes, views, configs).
    7. Observe if the calculator application (`calc.exe`) launches upon triggering an extension feature, indicating successful command injection and RCE.

#### 3. Code Injection via `modelsPaths` setting in EloquentProvider

* Description:
    The `Laravel Extra Intellisense` extension uses the `LaravelExtraIntellisense.modelsPaths` setting to determine directories where Eloquent models are located. This setting is intended to customize model paths for project analysis. However, the `EloquentProvider.ts` utilizes this setting to dynamically include PHP files using `include_once`. By crafting a malicious `.vscode/settings.json` file within a Laravel project to include a path containing a malicious PHP file, an attacker can achieve code injection. When the extension initializes or performs model-related operations, it will execute the malicious PHP code included through the attacker-controlled `modelsPaths` setting.

    **Step-by-step trigger:**
    1. A threat actor creates a malicious Laravel project.
    2. The threat actor creates a malicious PHP file within the project, e.g., `malicious.php`, containing arbitrary PHP code like `<?php system('calc'); ?>`.
    3. The threat actor modifies the `.vscode/settings.json` file in the malicious project and sets the `LaravelExtraIntellisense.modelsPaths` configuration to include the directory containing the malicious PHP file, for example: `"LaravelExtraIntellisense.modelsPaths": ["."]` if `malicious.php` is in the project root.
    4. The threat actor distributes this malicious Laravel project to a victim.
    5. The victim opens the malicious project in VSCode with the "Laravel Extra Intellisense" extension installed.
    6. When the extension initializes or performs operations related to Eloquent models, the `EloquentProvider` is activated.
    7. The `EloquentProvider` reads the `LaravelExtraIntellisense.modelsPaths` setting from `.vscode/settings.json`.
    8. The extension constructs PHP code that iterates through the configured paths and uses `include_once` to include PHP files found in those paths.
    9. Because the `modelsPaths` setting is controlled by the attacker and points to a directory containing `malicious.php`, the `include_once` statement includes and executes the malicious PHP file.
    10. The arbitrary PHP code within `malicious.php`, such as launching the calculator application (`calc`), is executed on the victim's machine.

* Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary PHP code on the victim's machine by including a malicious PHP file through the `modelsPaths` setting. This can lead to complete system compromise, data theft and other malicious activities.

* Vulnerability Rank:
    Critical

* Currently implemented mitigations:
    None. The extension directly uses the user-provided `modelsPaths` setting to include PHP files without proper validation or sanitization.

* Missing mitigations:
    - Input validation and sanitization for the `modelsPaths` setting. The extension should validate that the paths in `modelsPaths` are within the workspace and ideally, within expected model directories like `app/Models` or similar.
    - Restrict file inclusion to only files within the intended model directories and avoid including files based on user-provided paths directly.
    - Consider parsing model files statically instead of executing them via `include_once`. This would eliminate the risk of code execution from included files.
    - Display a warning message if `modelsPaths` is configured outside of standard model directories, indicating a potential security risk.

* Preconditions:
    - The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim opens a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.modelsPaths` setting, and a malicious PHP file within the specified paths.

* Source code analysis:
    1. File: `src/EloquentProvider.ts`
    2. Function: `loadModels()`
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
    The `loadModels` function constructs PHP code that iterates through paths specified in `modelsPaths` setting and uses `include_once base_path("$modelPath/$sourceFile")` to include PHP files from these paths. This dynamic file inclusion, based on user-controlled `modelsPaths`, allows for code injection if a malicious path and PHP file are provided.

* Security test case:
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
