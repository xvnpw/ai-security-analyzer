* Vulnerability Name: Command Injection via `phpCommand` setting
* Description:
    1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code.
    2. This setting is intended to allow customization for different environments, such as Docker or Laravel Sail, as documented in the README.
    3. However, the extension directly uses this setting to execute PHP code without any sanitization or validation.
    4. A malicious user can craft a workspace configuration file (`.vscode/settings.json`) within a Laravel project and set `LaravelExtraIntellisense.phpCommand` to inject arbitrary shell commands.
    5. When a victim opens this malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed and activated, the extension will execute the attacker-controlled command specified in `LaravelExtraIntellisense.phpCommand`.
    6. This can occur when the extension attempts to gather autocompletion data, which triggers the execution of the configured `phpCommand`.

* Impact:
    - Remote Code Execution (RCE) on the victim's machine.
    - An attacker can execute arbitrary shell commands with the privileges of the VSCode user.
    - This can lead to complete compromise of the victim's local system, including data theft, malware installation, and further lateral movement within the victim's network if applicable.

* Vulnerability Rank: Critical

* Currently implemented mitigations:
    - None. The extension directly uses the user-provided `phpCommand` setting without any validation or sanitization. The README.md contains a "Security Note" but it's more of a disclaimer than a mitigation.

* Missing mitigations:
    - Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting. The extension should validate and sanitize the user-provided command to prevent command injection.
    - Restricting allowed characters or command structure for `phpCommand`. A more restrictive configuration schema for `phpCommand` could limit the attack surface.
    - Displaying a clear warning to the user when they are about to use or modify the `phpCommand` setting, especially when opening a workspace with a pre-configured setting.
    - Considering alternative approaches to execute PHP code that do not involve shell commands, if feasible for the extension's functionality.
    - Implementing a Content Security Policy (CSP) for the extension's execution environment to restrict capabilities, although this might be less directly applicable to command execution in the user's environment.

* Preconditions:
    1. Victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    2. Victim opens a malicious Laravel project in VSCode.
    3. The malicious project contains a `.vscode/settings.json` file that sets the `LaravelExtraIntellisense.phpCommand` to a malicious command.
    4. The extension activates and attempts to gather autocompletion data, triggering the execution of the malicious `phpCommand`.

* Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Retrieves phpCommand from configuration
        let command = commandTemplate.replace("{code}", code); // Vulnerable line: Directly substitutes {code} without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable line: Executes command without sanitization
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
    - The `runPhp` function retrieves the `phpCommand` from the extension's configuration.
    - It then uses `String.prototype.replace()` to insert the `$code` into the `phpCommand` template.
    - Finally, `child_process.exec()` is used to execute the constructed command.
    - There is no input validation or sanitization on the `phpCommand` retrieved from the configuration, allowing for command injection.
    - The `code` variable is escaped with `code = code.replace(/\"/g, "\\\"")`, but this is insufficient to prevent command injection when the user controls the entire command template via `phpCommand`.

* Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/vscode-laravel-extra-intellisense-pwned'"
    }
    ```
    4. Open VSCode and open the `malicious-laravel-project` directory as a workspace.
    5. Ensure that the "Laravel Extra Intellisense" extension is installed and activated in VSCode.
    6. Open any PHP file within the `malicious-laravel-project` workspace (or create a dummy PHP file if none exists). This will trigger the extension to activate and attempt to provide autocompletion.
    7. After a short delay (during which the extension attempts to gather data), check if the file `/tmp/vscode-laravel-extra-intellisense-pwned` exists on your system.
    8. If the file exists, it indicates that the command injected via `LaravelExtraIntellisense.phpCommand` was successfully executed, confirming the command injection vulnerability.
