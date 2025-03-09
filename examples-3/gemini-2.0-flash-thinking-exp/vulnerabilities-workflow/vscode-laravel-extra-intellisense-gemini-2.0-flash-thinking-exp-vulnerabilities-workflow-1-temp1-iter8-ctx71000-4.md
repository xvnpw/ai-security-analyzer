### Vulnerability List

* Vulnerability Name: Command Injection in `phpCommand` setting
* Description:
    1. The `LaravelExtraIntellisense.phpCommand` setting allows users to configure the command used to execute PHP code within their Laravel project. This setting is intended to support various environments like Docker and Laravel Sail.
    2. The extension uses the configured `phpCommand` to execute arbitrary PHP code to gather information for autocompletion features (e.g., routes, views, configs).
    3. A threat actor can craft a malicious Laravel project and include a `.vscode/settings.json` file in the project root.
    4. This malicious `settings.json` can redefine the `LaravelExtraIntellisense.phpCommand` to inject arbitrary shell commands alongside the expected PHP execution.
    5. When a victim opens this malicious Laravel project in VSCode with the Laravel Extra Intellisense extension installed, the extension reads the workspace settings, including the attacker-controlled `phpCommand`.
    6. Subsequently, when the extension attempts to gather autocompletion data by executing PHP code using `phpCommand`, the injected shell commands from the malicious setting are also executed.
    7. This results in command injection, allowing the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process.

* Impact:
    - Remote Code Execution (RCE) on the victim's machine.
    - An attacker can gain full control over the victim's system, potentially leading to data theft, malware installation, or further malicious activities.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
    - The "Security Note" in the `README.md` mentions potential issues with sensitive code execution but does not address the command injection vulnerability through the `phpCommand` configuration itself.

* Missing Mitigations:
    - Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting.
    - Restricting the characters allowed in the `phpCommand` setting to prevent command separators or injection attempts.
    - Displaying a warning to the user when the `phpCommand` setting is changed, especially when opening a new workspace, to alert them to potential risks.
    - Using safer alternatives to `cp.exec` if possible, or carefully constructing the command to avoid shell injection.

* Preconditions:
    1. Victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    2. Victim opens a workspace in VSCode that contains a malicious `.vscode/settings.json` file.
    3. The malicious `.vscode/settings.json` file is crafted by a threat actor and included in a malicious Laravel project.

* Source Code Analysis:
    1. **`src/helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code);
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // <-- Vulnerable function
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
        - The `runPhp` function retrieves the `phpCommand` setting from VSCode configuration.
        - It uses `commandTemplate.replace("{code}", code)` to construct the final command to be executed.
        - **Vulnerability:** It directly passes this constructed `command` to `cp.exec()`. `cp.exec()` executes commands in a shell, and if the `phpCommand` contains shell metacharacters, it can lead to command injection.

    2. **`README.md` - `LaravelExtraIntellisense.phpCommand` configuration:**
        ```markdown
        ### LaravelExtraIntellisense.phpCommand
        Command to run PHP codes to interact with your Laravel application.

        Default:
        `php -r \"{code}\"`
        > Note: {code} is PHP code generated by extension and should be wrapped with "".

        ### Sample config to use docker
        This is a simple configuration to use via [Laradock](https://github.com/laradock/laradock).

        ```json
        "LaravelExtraIntellisense.phpCommand": "docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r \"{code}\"",
        "LaravelExtraIntellisense.basePathForCode": "/var/www/your-project"
        ```

        Another sample for [Laravel Sail](https://laravel.com/docs/sail).

        ```json
        "LaravelExtraIntellisense.basePathForCode": "/var/www/html",
        "LaravelExtraIntellisense.phpCommand": "docker-compose exec -w /var/www/html YOUR_SERVICE_NAME php -r \"{code}\""
        ```
        Default YOUR_SERVICE_NAME for Laravel sail is `laravel.test`.

        It is possible to use this extension with other docker images or even other virtual machines.
        ```
        - The documentation shows how to configure `phpCommand`, including examples with Docker. It does not warn about the security implications of modifying this setting and the potential for command injection.

* Security Test Case:
    1. Create a new Laravel project (or any directory that can be opened as a VSCode workspace).
    2. Create a `.vscode` directory in the project root.
    3. Inside `.vscode`, create a `settings.json` file with the following content to inject a malicious command into `phpCommand`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"touch /tmp/rce_vulnerability\");'"
        }
        ```
        - This malicious setting will execute `touch /tmp/rce_vulnerability` command in the system after the original PHP code provided by extension is executed.
    4. Open the created Laravel project in VSCode.
    5. Open any PHP file within the project (e.g., a controller or route file). This will trigger the extension to activate and attempt to use `phpCommand` to gather autocompletion data.
    6. **Expected Result:** After a short delay (or after triggering autocompletion), the file `/tmp/rce_vulnerability` should be created on the victim's system if the command injection is successful. You can check for the file using the terminal: `ls /tmp/rce_vulnerability`.
    7. **Clean-up (optional):** Delete the created file: `rm /tmp/rce_vulnerability`.

This test case demonstrates that arbitrary commands can be injected and executed via the `LaravelExtraIntellisense.phpCommand` setting, confirming the command injection vulnerability.
