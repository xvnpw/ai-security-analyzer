### Vulnerability List for Laravel Extra Intellisense VSCode Extension

* Vulnerability Name: Command Injection via `phpCommand` Configuration
* Description:
    1. A threat actor creates a malicious Laravel repository.
    2. The threat actor adds a `.vscode/settings.json` file to the repository.
    3. In the `settings.json`, the threat actor configures the `LaravelExtraIntellisense.phpCommand` setting to inject malicious commands. For example: `"LaravelExtraIntellisense.phpCommand": "bash -c '{code}' && touch /tmp/pwned"`.
    4. The victim opens the malicious Laravel repository in VSCode with the "Laravel Extra Intellisense" extension installed.
    5. When the extension activates and attempts to gather data for autocompletion (which happens automatically on project open or when editing relevant files), it executes the configured `phpCommand`.
    6. Due to insufficient sanitization of the `phpCommand` setting, the injected shell commands are executed on the victim's machine.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the machine of a user who opens a malicious Laravel project in VSCode.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None. The extension directly uses the user-provided `phpCommand` setting without any validation or sanitization.
* Missing Mitigations:
    * Input validation and sanitization of the `phpCommand` setting to prevent command injection.
    * Restricting the characters allowed in the `phpCommand` to only those necessary for executing PHP.
    * Ideally, the extension should avoid using `php -r` with user-configurable settings altogether and find a safer way to interact with the Laravel application. Sandboxing the execution environment could also be considered.
* Preconditions:
    * The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    * The victim opens a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `phpCommand`.
    * The extension activates and attempts to use the `phpCommand` to gather autocompletion data.
* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` setting from VSCode configuration.
    4. Line: `let command = commandTemplate.replace("{code}", code);` - Constructs the command by simply replacing `{code}` with the provided PHP code.
    5. Line: `cp.exec(command, ...)` - Executes the constructed command using `child_process.exec`.
    6. There is no input validation or sanitization performed on either `commandTemplate` (from user settings) or `code` before executing the command. This allows an attacker to inject arbitrary shell commands through the `phpCommand` setting.

    ```
    // Visualization of vulnerable code path in src/helpers.ts:runPhp
    phpCommandSetting = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get('phpCommand')
    commandTemplate = phpCommandSetting ?? "php -r \"{code}\""
    command = commandTemplate.replace("{code}", code) // No sanitization of phpCommandSetting
    cp.exec(command, ...)                  // Command execution with user controlled phpCommandSetting
    ```
* Security Test Case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "bash -c '{code}' && touch /tmp/pwned_command_injection"
    }
    ```
    4. Open VSCode and open the `malicious-laravel-project` directory.
    5. Wait for VSCode to activate extensions.
    6. Open any PHP file or Blade template file within the `malicious-laravel-project` (e.g., create a dummy `index.php` or `index.blade.php` if needed). This will trigger the extension to run and use the malicious `phpCommand`.
    7. After a short delay (to allow the command to execute), check if the file `/tmp/pwned_command_injection` exists on your system. On Linux/macOS, you can use the command `ls /tmp/pwned_command_injection`. If the file exists, the command injection vulnerability is confirmed.

* Vulnerability Name: Code Injection via Malicious Workspace Files
* Description:
    1. A threat actor creates a malicious Laravel repository.
    2. The threat actor modifies files within the repository (e.g., view files, configuration files, model files) to inject malicious PHP code.
    3. When the victim opens the malicious repository in VSCode, the "Laravel Extra Intellisense" extension automatically executes PHP code from the workspace to gather data for autocompletion.
    4. If the extension processes and executes the malicious PHP code injected by the attacker (e.g., during view parsing, model loading, or config retrieval), it can lead to arbitrary code execution on the victim's machine.
    5. For instance, a malicious Blade view file could contain `<?php system('touch /tmp/pwned_code_injection_view'); ?>` which gets executed when the extension tries to parse views.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary PHP code by crafting malicious files within a Laravel project, which gets executed by the extension when the project is opened in VSCode.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None. The extension executes PHP code from the workspace without sufficient sandboxing or security considerations. The "Security Note" in the README is just a warning and not a mitigation.
* Missing Mitigations:
    * Sandboxing the PHP execution environment to limit the impact of malicious code execution.
    * Input validation and sanitization of data retrieved from the Laravel application before processing it.
    * More robust error handling to prevent the execution of unexpected code paths due to parsing errors or manipulated data.
    * Principle of least privilege: The extension should only execute the minimum necessary code and commands required for its functionality and avoid executing potentially dangerous code from the workspace if possible.
* Preconditions:
    * The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    * The victim opens a malicious Laravel repository in VSCode that contains crafted files with embedded malicious PHP code.
    * The extension activates and processes these malicious files, leading to the execution of the injected code.
* Source Code Analysis:
    1. Multiple files in `src/` directory use `Helpers.runLaravel()` to execute PHP code from the workspace. For example:
        - `src/ViewProvider.ts`: `loadViews()` function executes PHP code to get view paths and namespaces.
        - `src/ConfigProvider.ts`: `loadConfigs()` function executes PHP code to retrieve configuration values.
        - `src/RouteProvider.ts`: `loadRoutes()` function executes PHP code to fetch route information.
        - `src/EloquentProvider.ts`: `loadModels()` function executes PHP code to load models and their attributes.
        - `src/TranslationProvider.ts`: `loadTranslations()` function executes PHP code to get translations.
        - `src/AuthProvider.ts`: `loadAbilities()` function executes PHP code to get authorization abilities.
        - `src/BladeProvider.ts`: `loadCustomDirectives()` function executes PHP code to fetch custom Blade directives.
    2. These functions use `Helpers.runLaravel()` which, in turn, uses `Helpers.runPhp()` to execute the PHP code.
    3. If a malicious user modifies files (e.g., views, configs, models) to inject PHP code, and if the extension processes these files using the described PHP execution mechanisms, the injected code will be executed.

    ```
    // Visualization of vulnerable code path in src/ViewProvider.ts:loadViews
    runLaravel("echo json_encode(app('view')->getFinder()->getHints());", ...) // Executes PHP code from workspace
        .then(function (viewPathsResult) {
            viewPaths = JSON.parse(viewPathsResult); // Parses result, but if malicious PHP in view, already executed
            ...
        });
    ```
* Security Test Case:
    1. Create a new directory named `malicious-laravel-project-code-injection`.
    2. Inside `malicious-laravel-project-code-injection`, create a standard Laravel project (you can use `laravel new malicious-laravel-project-code-injection`).
    3. Modify a Blade view file, for example, `resources/views/welcome.blade.php`. Add the following malicious PHP code to the top of the file: `<?php system('touch /tmp/pwned_code_injection_view_file'); ?>`.
    4. Open VSCode and open the `malicious-laravel-project-code-injection` directory.
    5. Wait for VSCode to activate extensions.
    6. Open the modified Blade view file `resources/views/welcome.blade.php` or any other file that might trigger view autocompletion (e.g., another blade file or php file where you might use `@include('welcome')`).
    7. After a short delay, check if the file `/tmp/pwned_code_injection_view_file` exists on your system. On Linux/macOS, use `ls /tmp/pwned_code_injection_view_file`. If the file exists, the code injection vulnerability via malicious view file is confirmed. You can repeat this test by injecting code into other file types that the extension processes (e.g., config files, model files).
