## Vulnerability List for Laravel Extra Intellisense

Here is the list of identified vulnerabilities in the Laravel Extra Intellisense VSCode extension based on the provided project files.

*   **Vulnerability Name:** Command Injection via `phpCommand` setting

    *   **Description:**
        1.  An attacker crafts a malicious Laravel repository.
        2.  The repository includes a `.vscode/settings.json` file.
        3.  This `settings.json` file defines a malicious `LaravelExtraIntellisense.phpCommand` setting. For example, setting it to execute an arbitrary command like `touch /tmp/pwned` after the PHP code execution. Example malicious setting:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r \\"{code}\\" && touch /tmp/pwned"
            }
            ```
        4.  A victim user opens this malicious repository in VSCode with the Laravel Extra Intellisense extension installed and activated.
        5.  When the extension initializes or needs to run a PHP command (e.g., for autocompletion data), it reads the `phpCommand` setting from the workspace's `.vscode/settings.json` due to VSCode's default workspace settings behavior.
        6.  The extension uses the configured `phpCommand` to execute PHP code by replacing the `{code}` placeholder with PHP commands it generates.
        7.  Due to the injected `&& touch /tmp/pwned` in the malicious `phpCommand`, after the intended PHP code is executed, the injected shell command `touch /tmp/pwned` is also executed on the victim's system.

    *   **Impact:** Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary commands on the victim's machine with the same privileges as the VSCode process. This could lead to full system compromise, data exfiltration, or other malicious activities.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:** None. The provided code does not include any input validation or sanitization for the `phpCommand` setting. While there is some escaping of double quotes and dollar signs within the `runPhp` function for the `{code}` part, this does not mitigate the vulnerability because the injection point is the `phpCommand` setting itself, which is processed by the shell before the PHP code is even executed.

    *   **Missing Mitigations:**
        *   **Input Validation and Sanitization:** The extension should validate and sanitize the `phpCommand` setting to ensure it only contains expected commands and arguments. It should prevent the injection of shell metacharacters or arbitrary commands.
        *   **Warning for Workspace Settings:** The extension could display a warning message to the user if it detects that the `phpCommand` setting is being overridden by workspace settings, especially if it deviates from a known safe default.
        *   **Use `child_process.spawn`:** Instead of using `child_process.exec`, which executes commands in a shell, the extension should use `child_process.spawn` with the PHP executable and arguments as separate parameters. This prevents shell injection vulnerabilities as arguments are passed directly to the executable without shell interpretation.

    *   **Preconditions:**
        *   The victim must have the Laravel Extra Intellisense extension installed and activated in VSCode.
        *   The victim must open a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file.
        *   Workspace settings must be enabled in VSCode (this is the default setting).

    *   **Source Code Analysis:**

        1.  **`src/helpers.ts` - `runPhp` function:**
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

                    cp.exec(command, // Vulnerable function: cp.exec
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) { ... }
                    );
                });
                return out;
            }
            ```
            -   The `runPhp` function retrieves the `phpCommand` from the VSCode configuration.
            -   It uses `commandTemplate.replace("{code}", code)` to construct the command string.
            -   Critically, it uses `cp.exec(command, ...)` to execute the command. `cp.exec` executes a command in a shell, which is susceptible to command injection if the command string is not properly sanitized, especially when parts of the command are user-controlled (in this case, via workspace settings).
            -   The code performs some escaping on the `$code` variable, but not on the `phpCommand` itself, making it vulnerable.

    *   **Security Test Case:**

        1.  **Setup Malicious Repository:**
            *   Create a new directory for the malicious Laravel repository (e.g., `malicious-repo`).
            *   Inside `malicious-repo`, create a `.vscode` directory.
            *   Inside `.vscode`, create a `settings.json` file with the following content:
                ```json
                {
                    "LaravelExtraIntellisense.phpCommand": "php -r \\"{code}\\" && touch /tmp/pwned"
                }
                ```
            *   You don't need to create a full Laravel project for this test, a simple empty directory with the `.vscode/settings.json` is sufficient to demonstrate the vulnerability.

        2.  **Open Repository in VSCode:**
            *   Open VSCode.
            *   Open the `malicious-repo` directory you created using "File" -> "Open Folder...".
            *   Ensure the Laravel Extra Intellisense extension is installed and enabled.

        3.  **Trigger Extension Activity:**
            *   Create a new PHP file (e.g., `test.php`) in the `malicious-repo` directory or open any existing PHP or Blade file in the workspace. This action will trigger the Laravel Extra Intellisense extension to become active and potentially execute a PHP command.

        4.  **Verify Command Injection:**
            *   After opening the PHP file and giving the extension a moment to initialize, check if the file `/tmp/pwned` exists on your system.
            *   On Linux/macOS, you can use the command `ls /tmp/pwned` in the terminal. If the file exists, the command injection was successful.
            *   On Windows, you would check for the file in the `\tmp` directory, or modify the injected command to create a file in a more easily accessible location (e.g., `touch C:\pwned.txt`).

        5.  **Expected Result:** If the file `/tmp/pwned` (or the equivalent file you chose) is created, it confirms that the attacker-controlled `phpCommand` setting from `.vscode/settings.json` was successfully used to inject and execute an arbitrary shell command, proving the Command Injection vulnerability.
