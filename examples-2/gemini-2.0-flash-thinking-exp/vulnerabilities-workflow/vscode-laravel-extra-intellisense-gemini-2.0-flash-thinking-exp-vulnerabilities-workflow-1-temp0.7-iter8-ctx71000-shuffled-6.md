## Vulnerability List

### 1. Command Injection via `phpCommand` setting

- **Vulnerability Name:** Command Injection via `phpCommand` setting
- **Description:**
    1. Attacker creates a malicious Laravel repository.
    2. Attacker adds a `.vscode/settings.json` file to the repository.
    3. In `settings.json`, attacker sets `LaravelExtraIntellisense.phpCommand` to a malicious command, e.g.,  `"php -r \\"{code}\\" && touch /tmp/pwned"`. This injects an additional command `touch /tmp/pwned` after the execution of the PHP code by the extension.
    4. Victim clones and opens the malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension attempts to provide autocompletion, it executes PHP code using the malicious `phpCommand` setting.
    6. The injected command `touch /tmp/pwned` is executed on the victim's machine.
- **Impact:** Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to data theft, system compromise, or further malicious activities.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
- **Missing Mitigations:**
    - **Input Sanitization:** Sanitize the `phpCommand` setting to prevent command injection. This could involve:
        - Validating the setting against a strict whitelist of allowed characters and commands.
        - Parsing the command to ensure it only contains a PHP interpreter command and the `{code}` placeholder.
        - Escaping shell metacharacters in the user-provided `phpCommand` template before using it in `cp.exec`.
    - **User Warning:** Display a clear warning to users about the security risks of modifying the `phpCommand` setting, especially when opening workspaces from untrusted sources.
    - **Restrict Characters:** Restrict the characters allowed in the `phpCommand` setting through VSCode's configuration schema to reduce the attack surface.
- **Preconditions:**
    - Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - Victim opens a malicious Laravel repository in VSCode.
    - The malicious repository contains a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.phpCommand` setting to include malicious commands.
- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `runPhp(code: string, description: string|null = null)`
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
    - **Explanation:** The `runPhp` function retrieves the `phpCommand` from the VSCode configuration (`vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`).
    - It then uses `String.prototype.replace()` to insert the generated PHP code (passed as the `code` argument) into the `commandTemplate` at the `{code}` placeholder.
    - **Vulnerability:**  The `commandTemplate` is taken directly from user settings without any validation. A malicious user can modify this setting to inject arbitrary commands that will be executed by `cp.exec` alongside the intended PHP code. The code only escapes double quotes in the `{code}` part and performs some platform-specific escaping, but it does not prevent injection in the template itself.

- **Security Test Case:**
    1. **Setup:**
        - Ensure you have VSCode and the "Laravel Extra Intellisense" extension installed.
        - Create an empty directory named `malicious-repo`.
        - Navigate into `malicious-repo` in your terminal.
        - Create `.vscode` directory: `mkdir .vscode`
        - Create `settings.json` file inside `.vscode` directory: `touch .vscode/settings.json`
        - Open `.vscode/settings.json` and paste the following malicious configuration:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && touch /tmp/pwned"
        }
        ```
        (For Windows, use `C:\\Windows\\Temp\\pwned.txt` instead of `/tmp/pwned`)
    2. **Trigger Vulnerability:**
        - Open the `malicious-repo` directory in VSCode.
        - Create a new PHP file (e.g., `test.php`) in the `malicious-repo`.
        - Open `test.php` in the editor. This should trigger the extension's activation and attempt to run PHP code for autocompletion.
    3. **Verify Exploitation:**
        - Check if the file `/tmp/pwned` (or `C:\Windows\Temp\pwned.txt` on Windows) exists.
        - In a Linux/macOS terminal: `ls /tmp/pwned`
        - In Windows PowerShell: `Test-Path C:\Windows\Temp\pwned.txt`
        - If the file exists, the command injection was successful and arbitrary code execution is confirmed.

This vulnerability allows for critical impact and requires immediate mitigation.
