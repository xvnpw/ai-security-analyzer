### Vulnerability List

*   **Vulnerability Name:** Command Injection in `phpCommand` setting

*   **Description:**
    The `Laravel Extra Intellisense` extension is vulnerable to command injection through the `LaravelExtraIntellisense.phpCommand` setting. This setting, intended to allow users to customize the PHP command used by the extension, can be maliciously modified within workspace settings (`.vscode/settings.json`). If a user opens a workspace containing a malicious `.vscode/settings.json` file that overrides this setting with a command injecting shell code, the extension will execute this injected code when it attempts to run Laravel commands in the background for features like autocompletion. This leads to arbitrary command execution on the victim's machine.

    Steps to trigger the vulnerability:
    1.  An attacker creates a malicious Laravel repository.
    2.  Within this repository, the attacker creates a `.vscode` directory.
    3.  Inside the `.vscode` directory, the attacker creates a `settings.json` file.
    4.  In `settings.json`, the attacker defines the `LaravelExtraIntellisense.phpCommand` setting with a malicious payload, for example:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && touch /tmp/pwned"
        }
        ```
    5.  The attacker hosts this malicious repository publicly (e.g., on GitHub).
    6.  A victim, who has the `Laravel Extra Intellisense` extension installed, clones or downloads this malicious repository and opens it in VSCode.
    7.  When the extension activates in the opened workspace, it reads the workspace settings, including the malicious `phpCommand`.
    8.  Subsequently, when the extension tries to gather information from the Laravel application (e.g., for route completion), it uses the configured `phpCommand` to execute PHP code.
    9.  Due to the command injection, the attacker's malicious command (`touch /tmp/pwned` in the example) will be executed after the intended PHP command. For instance, setting `phpCommand` to `php -r "{code}; system('whoami');"` will execute `system('whoami')` when the extension runs a PHP command.

*   **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the machine of a user who opens a malicious Laravel project in VSCode with the `Laravel Extra Intellisense` extension installed. Successful exploitation allows the attacker to:
    *   Steal sensitive data from the victim's machine.
    *   Install malware.
    *   Pivot to other systems on the victim's network.
    *   Modify or delete files.
    The execution occurs with the privileges of the VSCode process.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    None. The extension directly utilizes the `LaravelExtraIntellisentense.phpCommand` setting from the workspace configuration without any sanitization or validation. While the extension attempts to escape characters like `"` and `$` in the generated PHP code passed to the command, this escaping does not prevent injection through the `phpCommand` setting itself.

*   **Missing Mitigations:**
    *   **Input Sanitization and Validation:** Implement robust sanitization and validation of the `phpCommand` setting to prevent command injection. Ensure that only the `php` command is executed and disallow the injection of additional commands.
    *   **Restrict User Customization:** Consider removing or restricting user customization of the `phpCommand` setting. If customization is essential, provide a limited and safe way to configure the PHP execution path.
    *   **Sanitize `{code}` Placeholder:** If `phpCommand` customization is retained, sanitize the `{code}` placeholder within the `phpCommand` template to prevent injection through this vector, although securing the entire `phpCommand` is more critical.
    *   **Warning to User:** Display a clear and prominent warning to users about the security risks associated with modifying the `phpCommand` setting, especially when opening workspaces from untrusted sources. Educate users about the potential for arbitrary code execution and advise caution.
    *   **Default to Safe Command:** The default `phpCommand` should be as safe as possible, avoiding constructs that could easily be exploited for injection.

*   **Preconditions:**
    *   The victim must have the `Laravel Extra Intellisense` extension installed in VSCode.
    *   The victim must open a workspace in VSCode that contains a malicious `.vscode/settings.json` file setting a malicious `LaravelExtraIntellisense.phpCommand`.
    *   The extension must be activated and attempt to execute a Laravel command after the workspace is opened. This can be triggered by opening a PHP or Blade file within the malicious project or by initiating any extension feature that relies on PHP execution (e.g., autocompletion, code analysis).

*   **Source Code Analysis:**

    1.  **`src/helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Retrieves phpCommand from config
            let command = commandTemplate.replace("{code}", code); // Vulnerable line: Replaces {code} without sanitizing commandTemplate
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Vulnerable line: Executes command directly using cp.exec
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) {
                        // ...
                    }
                );
            });
            return out;
        }
        ```
        The `runPhp` function is the core of the vulnerability. It retrieves the `phpCommand` setting directly from the VSCode workspace configuration without any sanitization. The function then proceeds to replace the `{code}` placeholder within this `commandTemplate` with the PHP code intended for execution. Critically, the `commandTemplate` itself, derived directly from user-controlled settings, is not validated or sanitized. The resulting `command` string, potentially containing injected shell commands, is then passed to `cp.exec()`.  `cp.exec()` executes the string as a shell command, leading to command injection. The escaping applied to the `$code` variable is insufficient to prevent injection because the vulnerability lies in the unsanitized `commandTemplate`.

    2.  **`src/helpers.ts` - `runLaravel` function:**
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            // ...
            var command =
                "define('LARAVEL_START', microtime(true));" +
                "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                // ... more php code ...
                "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                    code + // User-provided code is inserted here, but the overall command is built using phpCommand
                "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                // ... more php code ...
                "exit($status);"

            var self = this;

            return new Promise(function (resolve, error) {
                self.runPhp(command, description) // Calls runPhp, which uses the vulnerable phpCommand
                    .then(function (result: string) {
                        // ...
                    })
                    .catch(function (e : Error) {
                        error(e);
                    });
            });
        }
        ```
        The `runLaravel` function constructs a comprehensive PHP script designed to interact with a Laravel application. It incorporates user-provided `$code` within this larger script. Crucially, it then delegates the execution of this script to the `runPhp` function. Since `runPhp` is vulnerable to command injection via the `phpCommand` setting, `runLaravel` becomes an indirect vector for the same vulnerability when a maliciously crafted `phpCommand` is configured. Any feature of the extension that utilizes `runLaravel` is therefore also potentially vulnerable.

    3.  **Widespread Usage in Providers:**
        Almost all providers within the extension (e.g., `AuthProvider.ts`, `ConfigProvider.ts`, `RouteProvider.ts`, `ViewProvider.ts`, etc.) rely on `Helpers.runLaravel` to retrieve data essential for autocompletion and other features. Consequently, every feature that depends on these providers becomes a potential trigger point for the command injection vulnerability if a malicious `phpCommand` is set. This broad usage significantly expands the attack surface.

*   **Security Test Case:**

    1.  **Setup:**
        *   Ensure the `Laravel Extra Intellisense` extension is installed in VSCode.
        *   Open any Laravel project in VSCode or create a new temporary Laravel project for testing purposes.

    2.  **Create Malicious Settings:**
        *   If a `.vscode` directory does not exist at the root of your Laravel project, create one.
        *   Inside the `.vscode` directory, create or modify the `settings.json` file.
        *   Add the following JSON content to `settings.json` to inject a command that creates a file named `pwned` in the `/tmp` directory (or `C:\Windows\Temp` on Windows):
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && touch /tmp/pwned"
            }
            ```
            *(For Windows, use: `\"LaravelExtraIntellisense.phpCommand\": \"php -r \\\"{code}\\\" && type nul > C:\\\\Windows\\\\Temp\\\\pwned\"`)*
            *Alternatively, to test command execution more directly, use:*
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('whoami > /tmp/whoami.txt');\""
            }
            ```

    3.  **Trigger Extension Activity:**
        *   Open any PHP or Blade file within your Laravel project (e.g., a controller, model, or view file).
        *   To trigger autocompletion, which often invokes the extension's PHP execution features, try typing code that would normally trigger the extension. For example, in a Blade file, type `@route('` to invoke route autocompletion. In a PHP file, type `Route::get('', function () { route('')` to trigger route name autocompletion.
        *   In some cases, simply opening a Laravel project with the extension active may be sufficient to trigger background tasks that execute Laravel commands, thus triggering the vulnerability.

    4.  **Verify Command Injection:**
        *   After triggering the extension's features, check for the indicator of command execution.
        *   If you used `touch /tmp/pwned` (or `type nul > C:\Windows\Temp\pwned` on Windows), check if the `pwned` file exists in the `/tmp` (or `C:\Windows\Temp`) directory.
            *   On Linux/macOS: `ls /tmp/pwned`
            *   On Windows: `dir C:\Windows\Temp\pwned`
        *   If you used `system('whoami > /tmp/whoami.txt')`, check if the `whoami.txt` file exists in the `/tmp` directory and examine its content.
            *   On Linux/macOS: `cat /tmp/whoami.txt`
        *   If the `pwned` file exists or `whoami.txt` contains the username of the user running VSCode, it confirms that the injected command part of the malicious `phpCommand` was executed, demonstrating successful command injection and Remote Code Execution.
