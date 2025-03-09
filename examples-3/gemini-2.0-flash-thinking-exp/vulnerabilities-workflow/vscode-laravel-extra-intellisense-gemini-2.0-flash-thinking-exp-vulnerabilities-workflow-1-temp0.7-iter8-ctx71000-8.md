## Vulnerability List

### 1. Command Injection in `phpCommand` configuration

- Description:
    - The extension executes PHP code to provide autocompletion features.
    - To execute PHP code, the extension uses the `phpCommand` configuration setting, which is user-defined and specifies the command to run PHP.
    - This command is executed using `child_process.exec` in `Helpers.runPhp` function.
    - If a malicious user provides a crafted `phpCommand` that includes shell commands, it can lead to command injection.
    - An attacker can achieve this by providing a malicious workspace configuration (e.g., `.vscode/settings.json`) that overrides the `phpCommand` setting.
    - When the extension attempts to execute PHP code (e.g., to fetch routes, views, configs), the injected shell commands in the malicious `phpCommand` will be executed.

- Impact:
    - Remote Code Execution (RCE).
    - An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process.
    - This can lead to complete compromise of the victim's system, including data theft, malware installation, and further attacks.

- Vulnerability Rank: High

- Currently implemented mitigations:
    - None. The extension directly uses the user-provided `phpCommand` in `child_process.exec` without any sanitization or validation.

- Missing mitigations:
    - Input sanitization: Sanitize the `phpCommand` configuration to prevent the injection of shell commands. This could involve:
        - Validating that the command starts with `php` or a known safe executable.
        - Removing or escaping shell metacharacters from the command and the `{code}` placeholder.
    - Use safer command execution methods: Instead of `child_process.exec`, consider using `child_process.spawn` and properly escaping arguments to avoid shell injection vulnerabilities.
    - Principle of least privilege: While not directly a mitigation in code, educating users about the risks of modifying extension settings and recommending to only modify settings from trusted sources can reduce the attack surface.
    - Warning message: Display a warning message to the user when they modify the `phpCommand` setting, highlighting the security risks involved.

- Preconditions:
    - The victim opens a workspace in VSCode that contains a malicious `.vscode/settings.json` file.
    - The malicious `.vscode/settings.json` file overrides the `LaravelExtraIntellisense.phpCommand` configuration with a malicious command.
    - The Laravel Extra Intellisense extension is activated in the workspace.
    - An autocompletion feature of the extension is triggered that requires executing PHP code (e.g., autocompletion for routes, views, configs, etc.).

- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
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

            cp.exec(command, // Vulnerable function: child_process.exec
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
    - The code retrieves the `phpCommand` from the configuration and directly substitutes `{code}` with the PHP code to be executed.
    - `cp.exec` executes a command in a shell, which interprets shell metacharacters.
    - If the `phpCommand` configuration is maliciously crafted, `cp.exec` will execute the injected shell commands.

- Security test case:
    1. Create a new Laravel project or use an existing one.
    2. Create a `.vscode` directory in the project root if it doesn't exist.
    3. Inside `.vscode`, create a `settings.json` file.
    4. Add the following configuration to `settings.json` to inject a command to execute `calc.exe` (or equivalent command for other OS):
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"calc.exe\");'"
    }
    ```
    5. Open the Laravel project in VSCode.
    6. Open any PHP file (e.g., a controller or a blade template).
    7. Trigger any autocompletion feature that relies on PHP execution. For example, type `route('` to trigger route name autocompletion.
    8. Observe that `calc.exe` (or the injected command) is executed by the system, demonstrating command injection.
    9. Alternatively, to verify command injection without UI interaction, set a more silent command such as creating a file:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"mkdir /tmp/pwned\");'"
    }
    ```
    After triggering autocompletion, check if the `/tmp/pwned` directory is created.
