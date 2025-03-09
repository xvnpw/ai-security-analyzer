## Vulnerability List:

### 1. Command Injection via `phpCommand` Configuration

- **Vulnerability Name:** Command Injection via `phpCommand` Configuration
- **Description:**
    1. A threat actor creates a malicious Laravel project repository.
    2. Inside this repository, the threat actor adds a `.vscode` directory.
    3. Within the `.vscode` directory, the threat actor creates a `settings.json` file.
    4. In the `settings.json` file, the threat actor overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command. For example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo ';'; touch malicious_file; php -r \"{code}\""
       }
       ```
       This malicious command first echoes a semicolon (`;`), then uses `touch malicious_file` to create a file named `malicious_file` in the workspace, and finally executes the original PHP code using `php -r \"{code}\"`. The `echo ';'` is added as a workaround to ensure that if the injected command is placed at the beginning, it correctly separates the injected command from the intended php command.
    5. A victim, who has the "Laravel Extra Intellisense" extension installed, clones or opens this malicious repository in VSCode.
    6. When the extension activates and tries to provide autocompletion features (e.g., when the victim opens a PHP or Blade file in the workspace), it executes PHP commands using the configured `phpCommand`.
    7. Due to the malicious configuration in `settings.json`, the injected commands (like `touch malicious_file`) are executed on the victim's machine, followed by the intended PHP code.
- **Impact:** Remote Code Execution (RCE). The threat actor can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to:
    - Data exfiltration: Stealing sensitive files from the victim's machine.
    - Malware installation: Installing viruses, ransomware, or other malicious software.
    - System compromise: Gaining full control over the victim's machine.
- **Vulnerability Rank:** Critical
- **Currently implemented mitigations:**
    - None. The extension relies on user configuration without any input validation or sanitization of the `phpCommand` setting.
    - The "Security Note" in the README.md warns users about potential risks, but it is not a technical mitigation.
- **Missing mitigations:**
    - Input validation and sanitization: The extension should validate and sanitize the `phpCommand` configuration to prevent command injection. It could check for dangerous characters or command separators.
    - Warning on configuration change: VSCode could display a warning to the user when a workspace setting overrides a sensitive extension setting like `phpCommand`, especially if it deviates significantly from the default.
    - Using `child_process.spawn`: Instead of using `child_process.exec`, the extension should use `child_process.spawn` with the command and arguments separated. This would prevent shell injection vulnerabilities as arguments are passed directly to the process without shell interpretation.
    - Principle of least privilege: While not directly related to code, running the extension processes with the least necessary privileges can limit the impact of a successful exploit.
- **Preconditions:**
    - The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim opens a malicious Laravel project repository in VSCode.
    - The malicious repository contains a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious payload.
- **Source code analysis:**
    - `src\helpers.ts`:
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
        - The `runPhp` function in `src\helpers.ts` uses `child_process.exec(command, ...)` to execute PHP commands.
        - The `command` variable is constructed by taking the `phpCommand` setting from the workspace configuration and replacing the `{code}` placeholder with the PHP code to be executed.
        - There is no sanitization of the `phpCommand` setting.
        - The `cp.exec` function executes a command in a shell, which is vulnerable to command injection if the command string is not properly sanitized, especially when constructed from user-controlled input like workspace settings.
- **Security test case:**
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a `.vscode` directory.
    3. Inside `.vscode`, create a file named `settings.json`.
    4. Add the following JSON content to `settings.json`:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo ';'; touch malicious_file_rce; php -r \"{code}\""
       }
       ```
    5. Open VSCode and open the `malicious-laravel-project` folder.
    6. Install and activate the "Laravel Extra Intellisense" extension in VSCode if not already installed.
    7. Create a new PHP file (e.g., `test.php`) in the `malicious-laravel-project` root directory and open it in the editor. This action should trigger the extension to run PHP commands.
    8. After a short delay (to allow the extension to activate and run), check the `malicious-laravel-project` root directory.
    9. Verify if a file named `malicious_file_rce` has been created.
    10. If `malicious_file_rce` exists, this confirms that the command injection vulnerability via `phpCommand` is present and exploitable.
