### Vulnerability 1: Code Injection via `phpCommand` configuration

- Description:
    - The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which dictates the command used to execute PHP code.
    - This command is directly executed by the extension using `child_process.exec` without proper sanitization or validation.
    - An attacker can convince a user to modify this setting to inject arbitrary shell commands.
    - When the extension attempts to gather autocompletion data, it executes the configured `phpCommand`, which now includes the attacker's injected commands.
    - This results in arbitrary command execution on the user's system with the privileges of the VS Code process.

- Impact:
    - Arbitrary command execution on the user's system.
    - Potential for data exfiltration, installation of malware, system compromise, denial of service, and other malicious activities depending on the attacker's payload and the user's system permissions.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None in the code itself.
    - The `README.md` file includes a "Security Note" that warns users about the extension executing their Laravel application and suggests caution:
        > **Security Note**
        > This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete.
        > So if you have any unknown errors in your log make sure the extension not causing it.
        > Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing.
    - This security note acts as a weak advisory but does not prevent the vulnerability.

- Missing Mitigations:
    - Input validation and sanitization for the `phpCommand` setting. The extension should restrict the characters allowed in the `phpCommand` setting or provide predefined command templates that users can choose from, preventing arbitrary command injection.
    - A more prominent security warning within the extension's settings UI to highlight the risks of modifying the `phpCommand` and advising users to only use trusted commands.
    - Consider removing the user configurability of `phpCommand` altogether and providing only a fixed, safe command execution method internally, if possible, to eliminate this attack vector entirely.

- Preconditions:
    - The attacker needs to convince a user to manually change the `LaravelExtraIntellisense.phpCommand` setting in VS Code to a malicious command. This could be achieved through social engineering, phishing, or by compromising a user's settings synchronization if enabled in VS Code.

- Source Code Analysis:
    - File: `src\helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Step 1: The function retrieves the `phpCommand` setting from VS Code configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    - Step 2: It uses a default value `"php -r \"{code}\""` if the setting is not configured.
    - Step 3: It replaces the placeholder `{code}` in the retrieved `commandTemplate` with the `$code` argument: `let command = commandTemplate.replace("{code}", code);`. **Crucially, no sanitization is performed on either the `commandTemplate` (user-controlled) or the `$code` (extension-controlled PHP code snippet).**
    - Step 4: The resulting `command` string is directly passed to `child_process.exec(command, ...)` for execution. This executes the user-defined command string in the system shell.

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [!] User-controlled phpCommand setting
        let command = commandTemplate.replace("{code}", code); // [!] No sanitization of commandTemplate or code
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [!] Command execution via cp.exec
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

- Security Test Case:
    1. Open VS Code with any Laravel project (a dummy project is sufficient).
    2. Navigate to VS Code settings (File > Preferences > Settings or Code > Settings > Settings).
    3. Search for "Laravel Extra Intellisense" to access the extension's settings.
    4. Locate the `LaravelExtraIntellisense: Php Command` setting.
    5. Modify the `Php Command` setting to a malicious command. Examples:
        - On Linux/macOS:  `bash -c "touch /tmp/pwned_by_intellisense"`
        - On Windows PowerShell: `powershell -c "New-Item -ItemType file -Path C:\Users\$env:USERNAME\AppData\Local\Temp\pwned_by_intellisense.txt"`
        - A more harmful command (use with extreme caution and in a controlled VM): `bash -c "rm -rf ~"` (Linux/macOS - **deletes user's home directory!**) or `powershell -c "Remove-Item -Path C:\ -Recurse -Force"` (Windows - **attempts to delete the entire C drive!**)
    6. Open any PHP file within the Laravel project or trigger any autocompletion feature of the extension (e.g., by typing `route('` in a Blade file). This will force the extension to execute PHP code and thus, the modified `phpCommand`.
    7. Verify the execution of the injected command:
        - Check if the file `/tmp/pwned_by_intellisense` (Linux/macOS) or `C:\Users\<username>\AppData\Local\Temp\pwned_by_intellisense.txt` (Windows) was created.
        - **If you used a destructive command (step 5, harmful examples), verify the detrimental effects (in a controlled VM only!).**
    8. If the file is created (or destructive command executed), it confirms that arbitrary commands injected via the `phpCommand` setting are successfully executed by the extension, demonstrating the code injection vulnerability.
