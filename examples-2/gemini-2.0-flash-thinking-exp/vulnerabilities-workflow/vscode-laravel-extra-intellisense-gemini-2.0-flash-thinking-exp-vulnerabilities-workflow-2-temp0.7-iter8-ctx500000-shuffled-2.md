- Vulnerability Name: Remote Code Execution via `phpCommand` Configuration
- Description:
    1. An attacker crafts a malicious Laravel project.
    2. The attacker convinces a victim to open this malicious project in VSCode with the "Laravel Extra Intellisense" extension installed and enabled.
    3. The attacker modifies the victim's VSCode settings for the workspace to set a malicious `LaravelExtraIntellisense.phpCommand`. This could be achieved by including a `.vscode/settings.json` file in the malicious project.
    4. When the extension attempts to gather autocomplete data (e.g., for routes, views, configs), it executes a PHP command using the configured `phpCommand`.
    5. If the `phpCommand` is maliciously crafted, it can execute arbitrary system commands on the victim's machine instead of just running PHP code.
    6. For example, setting `LaravelExtraIntellisense.phpCommand` to `bash -c "{code} && touch /tmp/pwned"` would execute the intended PHP code and then create a file named `pwned` in the `/tmp` directory on a Linux system. A more sophisticated attack could involve reverse shells or data exfiltration.
- Impact: Remote Code Execution (RCE) on the victim's machine. An attacker can gain full control over the victim's machine, steal sensitive data, or use it as a bot in a botnet.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - The extension's README.md contains a "Security Note" advising users that the extension executes their Laravel application and to be cautious. This is not a technical mitigation but a warning.
- Missing mitigations:
    - Input validation and sanitization for the `phpCommand` configuration setting. The extension should verify that the command is safe and does not allow for command injection.
    - Least privilege execution. The extension should ideally not execute PHP code with the user's full privileges. However, this might be complex in the context of VSCode extensions.
    - Disabling execution of external commands altogether and relying on safer methods for data extraction if possible.
    - More prominent and explicit warnings within the extension itself when a workspace setting overrides the `phpCommand`, especially if it deviates from the default `php -r "{code}"`.
- Preconditions:
    1. Victim has the "Laravel Extra Intellisense" extension installed and enabled in VSCode.
    2. Victim opens a workspace containing a malicious Laravel project provided by the attacker.
    3. The attacker can influence the victim to use workspace settings, or the victim naively trusts and opens the malicious project without inspecting workspace settings.
- Source code analysis:
    1. **File: `src/helpers.ts`**
    2. **Function: `runPhp(code: string, description: string|null = null)`**
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

            cp.exec(command,
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
    3. The `runPhp` function is responsible for executing PHP code.
    4. It retrieves the `phpCommand` from the VSCode configuration: `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    5. It replaces the `{code}` placeholder in the `phpCommand` with the provided `$code` argument.
    6. It then uses `child_process.exec(command, ...)` to execute the constructed command.
    7. **Vulnerability:** There is no validation or sanitization of the `phpCommand` configuration setting itself. If an attacker can modify this setting (e.g., via workspace settings), they can inject arbitrary commands into the execution flow. The code only escapes double quotes and dollar signs in the *code* being executed by PHP, not in the `phpCommand` template itself. This allows for command injection if the user sets a malicious `phpCommand`.

- Security test case:
    1. **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Create a new empty folder to act as a workspace.
        - Inside this folder, create a subfolder named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - Add the following content to `settings.json`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned'"
        }
        ```
        - Open the empty folder as a workspace in VSCode.
        - Open any PHP file in the workspace (it doesn't need to be a Laravel project for this test).
    2. **Trigger Vulnerability:**
        - In the opened PHP file, start typing `config(`. This should trigger the ConfigProvider to run a PHP command to fetch config values.
    3. **Verify Impact:**
        - After a short delay (or after triggering autocompletion), check if the file `/tmp/pwned` exists on the system.
        - If the file `/tmp/pwned` is created, it confirms that the malicious `phpCommand` was executed, and arbitrary commands could be injected.

This vulnerability allows for Remote Code Execution and is critical because it can be triggered by simply opening a malicious workspace and relying on the extension's core functionality.
