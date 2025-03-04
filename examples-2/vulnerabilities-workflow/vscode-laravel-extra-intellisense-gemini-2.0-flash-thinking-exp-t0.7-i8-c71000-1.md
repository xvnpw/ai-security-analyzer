### Vulnerability List for Laravel Extra Intellisense VSCode Extension

* Vulnerability Name: Code Injection via Malicious Laravel Application Bootstrapping
    * Description:
        1. A threat actor creates a malicious Laravel repository.
        2. The malicious repository includes a `.vscode/settings.json` file that sets `LaravelExtraIntellisense.basePathForCode` to point to the root directory of the malicious repository (e.g., ".").
        3. The threat actor replaces legitimate Laravel bootstrapping files, specifically `vendor/autoload.php` and/or `bootstrap/app.php`, within the malicious repository with PHP files containing arbitrary malicious code.
        4. A victim opens this malicious Laravel repository in VSCode with the "Laravel Extra Intellisense" extension activated.
        5. When the extension initializes or attempts to provide autocompletion features, it executes PHP code using `Helpers.runLaravel`.
        6. `Helpers.runLaravel` uses `require_once` and `include_once` with paths constructed using `LaravelExtraIntellisense.basePathForCode`. Due to the malicious configuration, this leads to the inclusion and execution of the attacker's malicious `vendor/autoload.php` or `bootstrap/app.php` files.
        7. The attacker's arbitrary PHP code is executed on the victim's machine, achieving code injection.
    * Impact: Remote Code Execution (RCE). An attacker can execute arbitrary code on a victim's machine simply by the victim opening a malicious Laravel project in VSCode with the extension installed.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations: None. The extension directly uses the `basePathForCode` configuration value without any validation or sanitization when constructing paths for `require_once` and `include_once`.
    * Missing Mitigations:
        - Validate the `LaravelExtraIntellisense.basePathForCode` setting to ensure it points to a valid and expected Laravel project structure.
        - Sanitize the `basePathForCode` to prevent directory traversal attacks.
        - Restrict `basePathForCode` to be within the workspace or a trusted location.
        - Consider removing the `basePathForCode` setting and rely on workspace root detection for project path resolution to simplify path handling and reduce attack surface.
    * Preconditions:
        - Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
        - Victim opens a workspace containing a malicious Laravel repository provided by the threat actor.
        - The malicious repository is crafted with a malicious `.vscode/settings.json` and malicious Laravel bootstrapping files (`vendor/autoload.php`, `bootstrap/app.php`).
    * Source Code Analysis:
        - File: `src/helpers.ts`
        - Function: `runLaravel(code: string, description: string|null = null)`
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
        - File: `src/helpers.ts`
        - Function: `projectPath(path:string, forCode: boolean = false)`
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
    * Security Test Case:
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

* Vulnerability Name: Command Injection via `phpCommand` Configuration
    * Description:
        1. A threat actor crafts a malicious `.vscode/settings.json` file.
        2. This settings file is designed to be included in a malicious repository or provided to a victim through other means (e.g., shared settings).
        3. The malicious `.vscode/settings.json` file sets the `LaravelExtraIntellisense.phpCommand` configuration to a value that injects arbitrary commands into the PHP execution command. For example, appending `system('malicious_command')` to the default `php -r "{code}"`.
        4. A victim opens a workspace in VSCode where this malicious setting is applied, and the "Laravel Extra Intellisense" extension is active.
        5. When the extension attempts to execute any PHP code (which is a core function of the extension for providing autocompletion), it uses `Helpers.runPhp`.
        6. `Helpers.runPhp` retrieves the `LaravelExtraIntellisense.phpCommand` setting and substitutes `{code}` with the PHP code it intends to execute.
        7. Due to the malicious configuration, the injected command (e.g., `system('malicious_command')`) is appended to or embedded within the command executed by `cp.exec`.
        8. The injected command is executed by the system shell, resulting in command injection and potentially Remote Code Execution (RCE).
    * Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's operating system by manipulating the `phpCommand` configuration setting.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations: None. The extension directly utilizes the `phpCommand` configuration string in `cp.exec` without any validation or sanitization.
    * Missing Mitigations:
        - Validate and sanitize the `LaravelExtraIntellisense.phpCommand` setting to remove or escape potentially harmful characters and commands.
        - Avoid using `phpCommand` as a template where user-provided code is directly substituted. Instead, construct the PHP execution command in a safer, programmatic way.
        - Consider restricting the allowed commands or arguments within `phpCommand` to a predefined safe list, or completely disallow user modification of the core execution command.
    * Preconditions:
        - Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
        - Victim opens a workspace in VSCode that contains or applies a malicious `.vscode/settings.json` file that configures `LaravelExtraIntellisense.phpCommand` with injected commands.
        - The extension attempts to execute PHP code, triggering the vulnerable `Helpers.runPhp` function.
    * Source Code Analysis:
        - File: `src/helpers.ts`
        - Function: `runPhp(code: string, description: string|null = null) : Promise<string>`
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
    * Security Test Case:
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
