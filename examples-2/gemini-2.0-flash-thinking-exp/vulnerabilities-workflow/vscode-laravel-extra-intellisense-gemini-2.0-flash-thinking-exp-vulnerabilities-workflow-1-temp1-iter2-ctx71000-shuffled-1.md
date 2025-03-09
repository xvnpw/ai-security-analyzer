### Vulnerability List for Laravel Extra Intellisense VSCode Extension

*   **Vulnerability Name:**  Unsafe PHP Command Configuration leading to Command Injection
    *   **Description:**
        1.  The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code for features like autocompletion.
        2.  This setting is intended to allow customization for environments like Docker or Laravel Sail.
        3.  However, the extension insufficiently sanitizes this user-provided command before executing it using `child_process.exec`.
        4.  A malicious user can craft a workspace settings file (`.vscode/settings.json`) within a Laravel project to inject arbitrary shell commands into the `phpCommand` setting.
        5.  When a victim opens this malicious project in VSCode and the extension attempts to run a PHP command (e.g., to fetch routes or configurations for autocompletion), the injected commands will be executed on the victim's machine.
    *   **Impact:**
        *   Remote Code Execution (RCE) on the victim's machine.
        *   An attacker can gain full control over the victim's system by injecting and executing arbitrary commands.
        *   This could lead to data theft, malware installation, or further attacks on the victim's network.
    *   **Vulnerability Rank:** Critical
    *   **Currently implemented mitigations:**
        *   The extension attempts to escape double quotes (`"`) and some characters (`$`, `'`, `"`) on Unix-like systems in the PHP code injected into the command using these lines in `src/helpers.ts`:
            ```typescript
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            ```
        *   These mitigations are insufficient to prevent command injection when the user can control the entire command template via the `phpCommand` setting.
    *   **Missing mitigations:**
        *   Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting. The extension should strictly validate and sanitize this setting to prevent the injection of arbitrary commands.
        *   Ideally, avoid using `child_process.exec` with user-configurable command templates. Consider alternative, safer methods to interact with the Laravel application, or restrict the commands that can be executed to a predefined and safe set.
        *   Implement a warning or confirmation prompt when a workspace settings file attempts to override the `phpCommand` setting, informing the user of the potential security risks.
    *   **Preconditions:**
        *   The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
        *   The victim must open a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file.
        *   The malicious `.vscode/settings.json` file must set the `LaravelExtraIntellisense.phpCommand` setting to include malicious shell commands.
        *   The extension must attempt to execute a PHP command after the malicious project is opened (this happens automatically for features like autocompletion).
    *   **Source code analysis:**
        1.  **File: `src/helpers.ts` Function: `runPhp(code: string, description: string|null = null)`**
            ```typescript
            static async runPhp(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/\"/g, "\\\"");
                if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                    code = code.replace(/\$/g, "\\$");
                    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
                }
                let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable point: User-controlled command template
                let command = commandTemplate.replace("{code}", code); // Vulnerable point: Insufficient sanitization when replacing {code}
                let out = new Promise<string>(function (resolve, error) {
                    if (description != null) {
                        Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                    }

                    cp.exec(command, // Vulnerable point: Execution of unsanitized command
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) {
                            // ...
                        }
                    );
                });
                return out;
            }
            ```
            *   The `runPhp` function retrieves the `phpCommand` from the extension's configuration. This configuration is user-controlled and can be set in workspace settings.
            *   It attempts to escape double quotes and some characters, but this is insufficient to prevent command injection because the entire command structure is derived from the user-provided `phpCommand` setting.
            *   The `commandTemplate.replace("{code}", code)` line simply substitutes `{code}` with the escaped PHP code. If the `commandTemplate` itself contains malicious shell commands, they will remain and be executed.
            *   `cp.exec(command, ...)` then executes this potentially malicious command.

        2.  **File: `src/helpers.ts` Function: `runLaravel(code: string, description: string|null = null)`**
            ```typescript
            static runLaravel(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
                if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                    var command = // ... Laravel boot code ...
                        "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                            code + // Injected PHP code
                        "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                        // ...
                    var self = this;

                    return new Promise(function (resolve, error) {
                        self.runPhp(command, description) // Calls runPhp, inheriting the vulnerability
                            .then(function (result: string) {
                                // ...
                            })
                            .catch(function (e : Error) {
                                error(e);
                            });
                    });
                }
                return new Promise((resolve, error) => resolve(""));
            }
            ```
            *   `runLaravel` constructs a PHP script that boots the Laravel application and then executes the provided `code`.
            *   Critically, it calls `Helpers.runPhp(command, description)` to execute this script. This means the command injection vulnerability in `runPhp` is directly exploitable through any function in the extension that uses `runLaravel`.

    *   **Security test case:**
        1.  **Setup:**
            *   Create a new directory named `malicious-laravel-project`.
            *   Inside `malicious-laravel-project`, create a `.vscode` directory.
            *   Inside `.vscode`, create a `settings.json` file with the following content to inject a malicious command into `phpCommand`:
                ```json
                {
                    "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"touch /tmp/pwned\");'"
                }
                ```
            *   Create a basic Laravel project structure (you don't need a fully functional Laravel app, just the basic directories). You can use `mkdir app bootstrap config database public routes storage tests vendor` inside `malicious-laravel-project`. You don't need to run `composer install` or `artisan`.
            *   Create an empty PHP file, e.g., `malicious.php`, in the root of `malicious-laravel-project`.
        2.  **Execution:**
            *   Open the `malicious-laravel-project` directory in VSCode.
            *   Open the `malicious.php` file.
            *   In `malicious.php`, type `config(`. This should trigger the extension's autocompletion for `config()` function and consequently execute the malicious `phpCommand`.
        3.  **Verification:**
            *   After typing `config(` and waiting a few seconds for the autocompletion to attempt to load (you might see a brief "Loading..." message from the extension), check if the file `/tmp/pwned` exists on your system.
            *   On Linux/macOS, run `ls /tmp/pwned`. If the file exists, the command injection was successful. On Windows, you can adapt the injected command to create a file in the `TEMP` directory and check for its existence.

This vulnerability allows for Remote Code Execution and is ranked as **Critical** due to the ease of exploitation and the severe impact. It's crucial to address this command injection vulnerability immediately.
