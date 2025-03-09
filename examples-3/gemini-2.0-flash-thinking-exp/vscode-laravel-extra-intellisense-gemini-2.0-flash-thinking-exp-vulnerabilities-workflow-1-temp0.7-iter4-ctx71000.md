## Combined Vulnerability List

### Command Injection via `phpCommand` Configuration

- **Vulnerability Name:** Command Injection via `phpCommand` Configuration
- **Description:**
    1. A threat actor crafts a malicious Laravel project repository.
    2. Within this repository, the attacker includes a `.vscode` directory.
    3. Inside the `.vscode` directory, a `settings.json` file is created.
    4. This `settings.json` file overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command. For example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo ';'; touch malicious_file; php -r \"{code}\""
       }
       ```
       This crafted command aims to execute arbitrary commands alongside the intended PHP execution by leveraging shell command separators like `&&` or `;`. The example uses `echo ';'` as a workaround to handle cases where the injected command is placed at the beginning, ensuring proper separation from the intended PHP command.
    5. A victim, who has the "Laravel Extra Intellisense" extension installed in VSCode, clones or opens this malicious repository.
    6. When the extension activates, typically upon opening a PHP or Blade file within the workspace, it attempts to provide autocompletion features.
    7. To achieve this, the extension executes PHP commands using the configured `phpCommand`.
    8. Due to the malicious configuration in `settings.json`, the injected commands (like `touch malicious_file`) are executed on the victim's machine via `child_process.exec`, followed by the intended PHP code. This occurs because the `phpCommand` setting is incorporated into a shell command without proper sanitization.
- **Impact:** Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to severe consequences:
    - **Data exfiltration:** Sensitive data and source code can be stolen from the victim's workspace.
    - **Malware installation:** The attacker can install persistent malware, ransomware, or other malicious software.
    - **System compromise:** Full control over the victim's machine can be gained, potentially leading to further attacks within the victim's network.
- **Vulnerability Rank:** Critical
- **Currently implemented mitigations:**
    - None. The extension relies on user configuration for the `phpCommand` setting without any input validation or sanitization.
    - A "Security Note" exists in the README.md, warning users about potential risks associated with modifying the `phpCommand` setting. However, this is not a technical mitigation and does not prevent exploitation.
- **Missing mitigations:**
    - **Input validation and sanitization:** The extension must validate and sanitize the `phpCommand` configuration to prevent command injection. This could include:
        - Restricting allowed characters and command structure.
        - Validating that the command primarily executes `php` and necessary arguments, preventing injection of arbitrary shell commands.
        - Ideally, limiting the configurable part to just the PHP binary path and strictly controlling the arguments passed to it.
    - **Warning on configuration change:** VSCode or the extension itself could display a prominent warning to the user when a workspace setting overrides a sensitive extension setting like `phpCommand`, especially if it deviates significantly from the default. This warning should highlight the security risks involved in executing untrusted commands.
    - **Use `child_process.spawn`:** Instead of using `child_process.exec`, which executes commands in a shell, the extension should use `child_process.spawn`. With `spawn`, the command and arguments are passed as separate parameters, preventing shell injection vulnerabilities.
    - **Principle of least privilege:** Running extension processes with the minimum necessary privileges can limit the impact of a successful exploit, although this is a general security practice and not a direct mitigation for this specific vulnerability.
- **Preconditions:**
    - The victim must have the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim must open a malicious Laravel project repository in VSCode.
    - The malicious repository must contain a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious payload designed for command injection.
- **Source code analysis:**
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
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE LINE] - Retrieves phpCommand from configuration (user-controlled)
        let command = commandTemplate.replace("{code}", code); // [VULNERABLE LINE] - Constructs command by embedding code into phpCommand without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABLE LINE] - Executes command using child_process.exec
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) { ... }
            );
        });
        return out;
    }
    ```
    - The `runPhp` function retrieves the `phpCommand` setting from the workspace configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    - It then constructs the `command` string by replacing the `{code}` placeholder in the `commandTemplate` (which is the `phpCommand` setting) with the actual PHP code to be executed.
    - Critically, there is no sanitization or validation of the `commandTemplate` (the `phpCommand` setting itself) before it is used in command construction.
    - Finally, `cp.exec(command, ...)` executes the constructed command. Because `cp.exec` executes commands in a shell, and the `command` string is built from a user-controlled setting without sanitization, it is vulnerable to command injection. An attacker can inject arbitrary shell commands into the `phpCommand` setting, which will then be executed when the extension calls `runPhp`.

- **Security test case:**
    1. Create a new directory named `malicious-laravel-test`.
    2. Inside `malicious-laravel-test`, create a `.vscode` directory.
    3. Within `.vscode`, create a file named `settings.json`.
    4. Add the following JSON content to `settings.json` to inject a command that creates a marker file in the `/tmp` directory (for Linux/macOS; adjust for Windows if needed):
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && touch /tmp/vscode-laravel-rce-test"
       }
       ```
       For Windows, you might use:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo vulnerable > C:\\vscode-laravel-rce-test.txt"
       }
       ```
    5. Open VSCode and open the `malicious-laravel-test` folder as a workspace.
    6. Install and activate the "Laravel Extra Intellisense" extension in VSCode if not already installed.
    7. Create a new PHP file (e.g., `test.php`) in the `malicious-laravel-test` root directory and open it in the editor. This action should trigger the extension to run PHP commands.
    8. After a short delay to allow the extension to activate and execute, check if the marker file has been created.
        - On Linux/macOS, in a terminal, run: `ls /tmp/vscode-laravel-rce-test`
        - On Windows, check for the file `C:\vscode-laravel-rce-test.txt`
    9. If the marker file exists, this confirms that the command injection vulnerability via `phpCommand` is present and exploitable, as the injected `touch` or `echo` command was successfully executed.
