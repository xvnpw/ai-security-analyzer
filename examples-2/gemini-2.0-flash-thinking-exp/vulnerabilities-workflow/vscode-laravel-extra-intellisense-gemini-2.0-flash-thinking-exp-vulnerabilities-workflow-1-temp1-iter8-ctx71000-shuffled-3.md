### Vulnerability List

- Vulnerability Name: Command Injection via phpCommand setting
- Description: The `phpCommand` setting in the extension configuration is used to execute PHP code in the user's Laravel application. This setting is meant to allow users to customize how the extension interacts with their Laravel project, especially in containerized environments like Docker or Laravel Sail. However, if a malicious user can control this `phpCommand` setting, they can inject arbitrary commands into the execution flow. This can be achieved by crafting a malicious workspace and enticing a victim to open it in VSCode. The malicious workspace would include a `.vscode/settings.json` file that overrides the `phpCommand` setting with a command containing malicious code. When the extension attempts to run PHP commands using `Helpers.runLaravel` or `Helpers.runPhp`, the injected command will be executed alongside the intended PHP code.

    **Step-by-step trigger:**
    1. Attacker creates a malicious Laravel project.
    2. In the malicious project, attacker creates or modifies the `.vscode/settings.json` file in the project root to include a malicious `phpCommand`. For example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo '; touch /tmp/pwned; php -r \"{code}\"'"
       }
       ```
       This malicious command first uses `echo` to start a php command execution, then injects a command `touch /tmp/pwned` using `;` separator, and finally executes the original php command `php -r \"{code}\"`.
    3. Attacker distributes this malicious Laravel project (e.g., via a public repository or email).
    4. Victim, a developer using the Laravel Extra Intellisense extension, opens the malicious project in VSCode.
    5. The Laravel Extra Intellisense extension activates upon opening a PHP or Blade file within the project.
    6. The extension, in various providers (like `EloquentProvider`, `ConfigProvider`, etc.), uses `Helpers.runLaravel()` to gather autocompletion data by executing PHP code.
    7. `Helpers.runLaravel()` internally calls `Helpers.runPhp()`, which retrieves the `phpCommand` from the workspace settings.
    8. `Helpers.runPhp()` then uses `child_process.exec()` to execute the command, which now includes the attacker's injected command due to the malicious `phpCommand` setting.
    9. The injected command `touch /tmp/pwned` is executed on the victim's system.

- Impact: Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's development environment, including data theft, installation of malware, and further lateral movement within the victim's network if applicable.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None.
    - The extension's README.md contains a "Security Note" which vaguely warns about the extension running the Laravel application and advises disabling the extension if sensitive code is present in service providers. However, this is not a technical mitigation and relies on the user's awareness and caution.
- Missing mitigations:
    - Input validation and sanitization for the `phpCommand` setting. The extension should validate the `phpCommand` setting to ensure it adheres to a safe format and does not contain potentially harmful characters or command separators. A whitelist of allowed commands or arguments could be implemented.
    - Using `child_process.spawn` instead of `child_process.exec`. `spawn` avoids invoking a shell, which reduces the risk of command injection. By using `spawn` and passing the PHP command and arguments as separate parameters, the vulnerability can be effectively mitigated.
    - Display a clear security warning to the user when the extension detects a custom `phpCommand` setting in the workspace, especially if it deviates from the default or a known safe configuration.
    - Principle of least privilege: Explore if it's possible to run the PHP commands in a more restricted environment or with reduced privileges.
- Preconditions:
    - Victim has the Laravel Extra Intellisense extension installed and activated in VSCode.
    - Victim opens a malicious Laravel project workspace provided by the attacker.
    - The malicious project contains a `.vscode/settings.json` file with a crafted, malicious `phpCommand` setting.
- Source code analysis:
    - `src/helpers.ts`:
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
        The `runPhp` function in `src/helpers.ts` is vulnerable.
        - Line 10: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` retrieves the potentially attacker-controlled `phpCommand` setting.
        - Line 11: `let command = commandTemplate.replace("{code}", code);` constructs the final command string by embedding the PHP code into the template.
        - Line 15: `cp.exec(command, ...)` executes the constructed command using `child_process.exec`, which is known to be vulnerable to command injection when constructing commands from user-controlled strings without proper sanitization and when a shell is implicitly invoked.
- Security test case:
    1. **Setup:**
        - Ensure you have Node.js and VSCode installed.
        - Install the Laravel Extra Intellisense extension in VSCode.
        - Create a new directory for testing (e.g., `laravel-ext-test`).
        - Inside `laravel-ext-test`, create a `.vscode` directory and within it, create a `settings.json` file.
        - Create an empty PHP file (e.g., `test.php`) in the `laravel-ext-test` directory.
    2. **Malicious Configuration:**
        - Edit the `.vscode/settings.json` file and add the following configuration to inject a command that will create a file named `pwned` in the `/tmp` directory (or equivalent for your OS, e.g., `C:\Windows\Temp\pwned.txt` on Windows):
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "echo '; touch /tmp/pwned; php -r \"{code}\"'"
          }
          ```
          *(Note: For Windows, use `\"LaravelExtraIntellisense.phpCommand\": \"echo ^& \ntype nul ^> C:\\\\Windows\\\\Temp\\\\pwned.txt ^& php -r \\\"{code}\\\"\"`)*
    3. **Trigger Vulnerability:**
        - Open the `laravel-ext-test` directory as a workspace in VSCode.
        - Open the `test.php` file. This action should trigger the Laravel Extra Intellisense extension to activate and attempt to run a PHP command using the configured `phpCommand`.
    4. **Verify Exploitation:**
        - After a short delay (to allow the extension to run), check if the file `/tmp/pwned` (or `C:\Windows\Temp\pwned.txt` on Windows) has been created.
        - On Linux/macOS: Open a terminal and run `ls /tmp/pwned`. If the file exists, the vulnerability is confirmed.
        - On Windows: Open Command Prompt or PowerShell and run `dir C:\Windows\Temp\pwned.txt`. If the file exists, the vulnerability is confirmed.

This security test case demonstrates that by manipulating the `LaravelExtraIntellisense.phpCommand` setting, an attacker can inject and execute arbitrary commands on the victim's system when the extension attempts to run PHP code.
