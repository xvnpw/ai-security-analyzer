## Vulnerability List

### 1. Command Injection via `phpCommand` configuration

- **Vulnerability Name:** Command Injection via `phpCommand` configuration
- **Description:**
    1. A threat actor compromises a Laravel repository.
    2. The threat actor modifies the `.vscode/settings.json` file within the repository to inject a malicious command into the `LaravelExtraIntellisense.phpCommand` setting. For example, they could set: `"LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned' {code}"`.
    3. A victim, who has the "Laravel Extra Intellisense" extension installed in VSCode, opens the compromised repository.
    4. VSCode reads the project-specific settings from `.vscode/settings.json`, including the malicious `LaravelExtraIntellisense.phpCommand`.
    5. When the extension needs to execute PHP code (for features like route, view, or config autocompletion), it utilizes the `Helpers.runPhp` function.
    6. The `Helpers.runPhp` function directly uses the `phpCommand` setting, which is now attacker-controlled, in `child_process.exec`. The `{code}` placeholder is replaced with generated PHP code, but the attacker-injected command (e.g., `bash -c 'touch /tmp/pwned'`) is executed before the PHP code.
    7. Consequently, the attacker's arbitrary command is executed on the victim's machine with the same privileges as the VSCode process.

- **Impact:** Remote Code Execution (RCE). Successful exploitation allows the threat actor to execute arbitrary commands on the victim's machine, potentially leading to full system compromise, data theft, or further malicious activities.
- **Vulnerability Rank:** Critical
- **Currently implemented mitigations:**
    - None in the source code.
    - The `README.md` file includes a "Security Note" that warns users about the extension automatically running their Laravel application to gather data for autocompletion. However, this note does not specifically address the risk of command injection through the `phpCommand` configuration, nor does it provide mitigation guidance.
- **Missing mitigations:**
    - **Input Sanitization/Validation:** The extension lacks input sanitization and validation for the `phpCommand` setting. It should validate and sanitize user-provided commands to prevent injection of malicious code. For instance, it could restrict allowed characters or use a safer command construction method.
    - **Safer Command Execution:** Instead of using `child_process.exec`, which executes the entire command string in a shell, the extension should use `child_process.spawn`. `spawn` allows for separating command arguments, preventing shell injection vulnerabilities.
    - **Principle of Least Privilege:**  While harder to implement in VSCode extension context, consider if the extension needs to run PHP code at all, or if there are safer alternatives to extract necessary information. If execution is necessary, explore running the PHP process with the least possible privileges.
    - **Clearer Security Warning:** The security warning in `README.md` should be more explicit and highlight the command injection vulnerability associated with modifying `phpCommand`. It should advise users to only use trusted repositories with this extension and be cautious about modifying extension settings, especially `phpCommand`. The extension itself could display a more prominent warning in the settings UI when users modify `phpCommand`.
- **Preconditions:**
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a malicious Laravel repository that contains a crafted `.vscode/settings.json` with a malicious `LaravelExtraIntellisense.phpCommand`.
- **Source code analysis:**
    - **`src/helpers.ts`:**
        - **`runPhp(code: string, description: string|null = null)` function:** This function is responsible for executing PHP code.
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

                    cp.exec(command, // <-- Vulnerable function: child_process.exec
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
            - The vulnerability lies in the use of `cp.exec(command, ...)` where `command` is directly constructed by replacing `{code}` in the user-configurable `phpCommand` setting without proper sanitization. This allows for command injection.
        - **`projectPath(path:string, forCode: boolean = false)` function:** This function uses `basePathForCode` setting. While not directly related to command injection, improper handling of `basePathForCode` could lead to path traversal issues if not carefully managed, although command injection via `phpCommand` is the more critical vulnerability.

    - **`README.md`:**
        - Security note is present but insufficient to warn about command injection.
        - Sample configurations for Docker and Laravel Sail in `README.md` might encourage users to modify the `phpCommand` setting, increasing the risk if they open a malicious project.

- **Security test case:**
    1. **Setup:**
        - Ensure you have VSCode installed with the "Laravel Extra Intellisense" extension.
        - Create a new, empty directory for testing.
        - Inside this directory, create a subdirectory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - Populate `settings.json` with the following malicious configuration:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned' {code}"
            }
            ```
    2. **Execution:**
        - Open the empty test directory in VSCode. This simulates opening a malicious repository.
        - Open any PHP file in the opened directory (you can create a dummy `test.php` file). This will trigger the extension to activate and attempt to use the `phpCommand`.
    3. **Verification:**
        - After a short delay (to allow the extension to initialize and execute), check if a file named `pwned` has been created in the `/tmp/` directory of your system.
        - **Success:** If the `/tmp/pwned` file exists, this confirms that the injected command `touch /tmp/pwned` from `LaravelExtraIntellisense.phpCommand` was successfully executed, demonstrating the command injection vulnerability.
        - **Failure:** If the file is not created, the vulnerability may not be exploitable in this specific environment, or the test case needs adjustment. However, based on code analysis, the vulnerability is likely present.

This test case simulates a scenario where a developer opens a project with malicious VSCode settings, leading to arbitrary command execution due to the vulnerable `phpCommand` configuration.
