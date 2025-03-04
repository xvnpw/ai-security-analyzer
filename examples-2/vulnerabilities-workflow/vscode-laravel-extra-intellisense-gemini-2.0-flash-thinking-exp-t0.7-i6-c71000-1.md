### Vulnerability List:

* **Vulnerability Name:**  Command Injection via `phpCommand` configuration
* **Description:**
    1. A threat actor compromises a Laravel repository.
    2. The threat actor modifies the `.vscode/settings.json` file within the repository to include a malicious `LaravelExtraIntellisense.phpCommand` configuration. This command can contain arbitrary system commands.
    3. A victim clones or opens the compromised repository in VSCode with the "Laravel Extra Intellisense" extension installed.
    4. The extension reads the workspace configuration, including the malicious `phpCommand`.
    5. When the extension attempts to provide autocompletion features, it executes PHP code by using `child_process.exec` with the configured `phpCommand`.
    6. Due to insufficient sanitization, the malicious commands embedded in `phpCommand` are executed on the victim's machine with the privileges of the VSCode process.
* **Impact:** Remote Code Execution (RCE). An attacker can execute arbitrary system commands on the victim's machine. This can lead to full system compromise, data theft, malware installation, and other malicious activities.
* **Vulnerability Rank:** Critical
* **Currently implemented mitigations:**
    * None. The extension directly uses the configured `phpCommand` in `child_process.exec` without any sanitization or validation.
* **Missing mitigations:**
    * Input sanitization and validation of the `phpCommand` configuration setting.
    * Restricting the characters allowed in `phpCommand`.
    * Warning the user when an unsafe `phpCommand` is detected.
    * Using a safer method to execute PHP code instead of `child_process.exec`, if possible.
    * Documentation strongly advising users to review and trust the repositories they open, especially concerning VSCode settings.
* **Preconditions:**
    * Victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    * Victim must open a workspace or folder containing a malicious `.vscode/settings.json` with a crafted `LaravelExtraIntellisense.phpCommand`.
    * The malicious repository must contain a Laravel project structure (artisan file, vendor autoload, etc.) for the extension to activate.
* **Source code analysis:**
    1. **`helpers.ts` - `runPhp` function:**
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

                cp.exec(command, // <-- Command Injection Vulnerability
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
        - The `runPhp` function retrieves the `phpCommand` configuration from VSCode settings using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It then uses `commandTemplate.replace("{code}", code)` to construct the command string. Critically, the `code` variable, while escaped for double quotes and some shell-specific characters, is embedded within the user-controlled `phpCommand` template.
        - The `cp.exec(command, ...)` function executes the constructed command string directly in a shell.
        - If a malicious user provides a `phpCommand` that includes shell command injection sequences (e.g., `php -r "{code}"; malicious_command`), these commands will be executed by `cp.exec`.

    2. **`README.md` - Configuration Section:**
        ```markdown
        ### LaravelExtraIntellisense.phpCommand
        Command to run PHP codes to interact with your Laravel application.

        Default:
        `php -r \"{code}\"`
        > Note: {code} is PHP code generated by extension and should be wrapped with "".
        ```
        - The documentation describes `phpCommand` as a configuration to customize how PHP code is executed, indicating that users can modify this setting.
        - Example configurations for Docker and Laravel Sail are provided, further encouraging users to customize this setting.
        - The note about `{code}` being wrapped in "" does not prevent command injection if a user crafts a malicious `phpCommand` that breaks out of this context.

* **Security test case:**
    1. **Attacker setup:**
        - Create a new Laravel project or use an existing one.
        - Create a `.vscode` folder in the project root.
        - Inside `.vscode`, create a `settings.json` file with the following content:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch /tmp/pwned'"
            }
            ```
            This malicious `phpCommand` will execute `touch /tmp/pwned` after the intended PHP code is executed.
        - Host this Laravel project on a public Git repository (e.g., GitHub).
    2. **Victim action:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Clone the attacker's malicious Laravel repository.
        - Open the cloned repository in VSCode.
        - Open any PHP or Blade file within the project. This will trigger the extension to run PHP commands for autocompletion.
    3. **Verification:**
        - After opening a file and waiting for a short period (for the extension to initialize and execute PHP commands), check if the file `/tmp/pwned` exists on the victim's system.
        - If the file `/tmp/pwned` is created, it confirms that the command injection vulnerability is successfully exploited, and arbitrary commands can be executed.

This test case demonstrates that by simply opening a project with a malicious `settings.json`, an attacker can achieve remote code execution on the victim's machine through the "Laravel Extra Intellisense" extension.
