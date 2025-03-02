### Vulnerability List

- Vulnerability Name: Command Injection via `phpCommand` setting
- Description:
    1. The extension uses the `phpCommand` setting to execute PHP code in the user's workspace.
    2. This `phpCommand` setting is customizable by the user and can be set in workspace settings (`.vscode/settings.json`).
    3. A malicious repository can include a `.vscode/settings.json` file to override the `phpCommand` setting with a malicious command.
    4. When the extension executes a command using `Helpers.runPhp`, it replaces `{code}` in the `phpCommand` with generated PHP code.
    5. If the `phpCommand` is crafted to include additional commands after the `{code}` placeholder, these commands will be executed by `cp.exec`.
    6. For example, setting `phpCommand` to `php -r "{code}; system('whoami');"` will execute `system('whoami')` when the extension runs a PHP command.
- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process.
- Vulnerability Rank: critical
- Currently implemented mitigations: No mitigations are implemented to prevent command injection through the `phpCommand` setting. While the extension performs some escaping of `"` and `$` characters within the generated PHP code, this does not prevent injection via the `phpCommand` configuration itself.
- Missing mitigations:
    - Restrict user customization of the `phpCommand` setting, or remove it entirely.
    - If `phpCommand` customization is necessary, implement robust sanitization and validation of the setting to prevent command injection.
    - Sanitize the `{code}` placeholder in `phpCommand` to prevent injection if `phpCommand` is kept customizable.
    - Display a clear warning to users about the security risks associated with modifying the `phpCommand` setting, especially when opening workspaces from untrusted sources.
- Preconditions:
    1. Victim opens a malicious repository in VSCode.
    2. Malicious repository includes a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command.
    3. Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    4. Victim triggers any feature of the extension that results in PHP code execution (e.g., autocompletion, code analysis, etc.). This can be triggered by simply opening a PHP or Blade file within the malicious project.
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
    The `runPhp` function retrieves the `phpCommand` from the configuration. It replaces the `{code}` placeholder with the provided PHP code. However, it does not sanitize the `commandTemplate` itself, allowing for command injection if a malicious `phpCommand` is configured. The escaping applied to the `code` variable is insufficient to prevent injection via the `phpCommand` template.

- Security test case:
    1. Create a new directory named `laravel-test-project`.
    2. Inside `laravel-test-project`, create a directory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; file_put_contents('/tmp/rce_test.txt', shell_exec('whoami'));\""
    }
    ```
    4. Inside `laravel-test-project`, create a file named `test.php` with the following content:
    ```php
    <?php
    Route::
    ```
    5. Open the `laravel-test-project` folder in VSCode.
    6. Open the `test.php` file in the editor.
    7. Place the text cursor immediately after `Route::` on line 2. This action should trigger the extension's autocompletion feature, which in turn executes PHP code using the configured `phpCommand`.
    8. Wait for a short period (e.g., 5-10 seconds) to allow the extension to execute and the command injection to take place.
    9. After the delay, check if a file named `rce_test.txt` has been created in the `/tmp/` directory.
    10. If the file `/tmp/rce_test.txt` exists, examine its content. If the file contains the username of the user running VSCode (the output of the `whoami` command), this confirms successful command injection and Remote Code Execution.
