### Vulnerability List

#### 1. Command Injection in `phpCommand` setting

* Description:
    1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting in VSCode workspace settings.
    2. This setting is used to define the command executed by the extension to run PHP code.
    3. The extension replaces the `{code}` placeholder in the `phpCommand` with generated PHP code and executes it using `child_process.exec`.
    4. If a malicious user provides a crafted `phpCommand` setting, they can inject arbitrary commands that will be executed by the extension.
    5. For example, a malicious user could set `phpCommand` to `php -r "{code}; system('malicious_command')"` or even overwrite the entire command to execute something completely different than php.
    6. When the extension attempts to use this command to gather autocompletion data, the injected command will be executed.
    7. An attacker can leverage this to achieve Remote Code Execution (RCE) on the machine where the VSCode extension is running.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine, potentially leading to data theft, system compromise, or other malicious activities.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.

* Missing mitigations:
    - Input sanitization and validation for the `phpCommand` setting.
    - Restrict characters allowed in `phpCommand` setting, prevent command separators like `;`, `&&`, `||`, `&`, `|`.
    - Warn users about the security risks of modifying `phpCommand` and advise them to only use trusted configurations.
    - Consider using a safer method to execute PHP code instead of `child_process.exec`, if possible.

* Preconditions:
    - The victim must have the `Laravel Extra Intellisense` extension installed in VSCode.
    - The victim must open a workspace that contains a malicious `.vscode/settings.json` file (or have workspace/user settings) that sets a malicious `LaravelExtraIntellisense.phpCommand`.
    - The attacker needs to trick the victim into opening a malicious repository containing the crafted workspace settings.

* Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` setting from the workspace configuration.
    4. Line: `let command = commandTemplate.replace("{code}", code);` - Replaces the `{code}` placeholder with the provided PHP code.
    5. Line: `cp.exec(command, ...)` - Executes the constructed command using `child_process.exec`.

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [Vulnerable Code] User controlled value from settings
        let command = commandTemplate.replace("{code}", code); // [Vulnerable Code] No sanitization of command template
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [Vulnerable Code] Command execution
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

* Security test case:
    1. Create a new Laravel project or use an existing one.
    2. Create a malicious `.vscode/settings.json` file in the project root with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"calc.exe\");'"
    }
    ```
    3. Open the Laravel project in VSCode with the `Laravel Extra Intellisense` extension activated.
    4. Open any PHP or Blade file in the project to trigger autocompletion.
    5. Observe that `calc.exe` (or another system command depending on the OS) is executed. This confirms command injection.
    6. To further verify RCE, try more harmful commands, such as creating a file or sending network requests, within the `system()` call. For example:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"whoami > output.txt\");'"
    }
    ```
    Check if `output.txt` is created in the workspace with the output of `whoami` command.
