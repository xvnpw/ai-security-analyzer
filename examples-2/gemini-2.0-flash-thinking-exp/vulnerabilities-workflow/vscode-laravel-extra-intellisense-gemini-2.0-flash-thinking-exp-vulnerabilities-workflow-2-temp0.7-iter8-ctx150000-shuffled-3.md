### Vulnerability List

- Vulnerability Name: Command Injection in `phpCommand` configuration
- Description:
    1. The extension allows users to configure the `phpCommand` setting, which specifies the command used to execute PHP code for Laravel project analysis.
    2. This setting is used in `helpers.ts` within the `runPhp` function to execute arbitrary PHP code provided by the extension to gather autocompletion data (routes, views, configs, etc.).
    3. A malicious user can modify the `phpCommand` configuration in VS Code settings to inject arbitrary system commands. For example, they can inject commands like `$(malicious_command)` or `;"malicious_command";`.
    4. When the extension attempts to gather autocompletion data, it executes the configured `phpCommand` with the generated PHP code.
    5. Due to the lack of sanitization of the `phpCommand` configuration, the injected system commands will be executed on the developer's machine with the privileges of the VS Code process.
- Impact:
    - Arbitrary command execution on the developer's machine.
    - Potential for sensitive data theft from the developer's environment.
    - Malware installation or further system compromise.
    - Unauthorized access to local resources and services.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Security Note in `README.md`: The README.md file includes a "Security Note" that warns users about the extension executing their Laravel application and suggests disabling the extension if sensitive code is present in service providers. This is a documentation-level warning, not a technical mitigation in the code.
    - Location: `README.md` file.
- Missing Mitigations:
    - Input validation and sanitization of the `phpCommand` configuration.
    - Restriction of allowed characters or command structure in `phpCommand`.
    - Sandboxing or isolation of the PHP execution environment.
    - User permission prompts before executing commands from configuration.
- Preconditions:
    - The attacker needs to be able to modify the user's VS Code settings for the workspace or globally. This could occur through:
        - Social engineering: tricking the developer into copying a malicious configuration.
        - Workspace sharing: a malicious actor provides a workspace configuration file (`.vscode/settings.json`) with a compromised `phpCommand`.
        - Supply chain attack: if the user imports settings from an untrusted source.
- Source Code Analysis:
    1. **`helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // [POINT OF VULNERABILITY] - Unsanitized phpCommand
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // [POINT OF VULNERABILITY] - Command execution
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... });
            });
            return out;
        }
        ```
        - The `runPhp` function retrieves the `phpCommand` configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It directly substitutes `{code}` in the `commandTemplate` with the `$code` argument without any sanitization or validation of the `commandTemplate` itself.
        - The resulting `command` is then passed to `cp.exec()`, which executes it as a system command.
        - **Visualization:**

        ```
        User Configuration (phpCommand) --> [Unsanitized Input] --> commandTemplate.replace("{code}", code) --> command --> cp.exec(command) --> System Command Execution
        ```

    2. **Configuration in `README.md`:**
        - The `README.md` provides examples of how to configure `phpCommand` for Docker environments, demonstrating the intended usage but also highlighting the flexibility (and potential risk) of this setting.
        - Sample configurations include:
            ```json
            "LaravelExtraIntellisense.phpCommand": "docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r \"{code}\"",
            "LaravelExtraIntellisense.phpCommand": "docker-compose exec -w /var/www/html YOUR_SERVICE_NAME php -r \"{code}\""
            ```
        - These examples show that the extension expects a command string that can include shell commands and options, increasing the risk of command injection if a malicious string is provided.

- Security Test Case:
    1. **Precondition:** Ensure you have a Laravel project opened in VS Code and the Laravel Extra Intellisense extension is activated.
    2. **Modify User Settings:** Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
    3. **Workspace Settings (Recommended):** Navigate to the Workspace settings tab.
    4. **Search for `phpCommand`:** Search for "LaravelExtraIntellisense: Php Command".
    5. **Set Malicious `phpCommand`:**  Modify the `phpCommand` setting to the following malicious command to execute `calc.exe` on Windows or `gnome-calculator` on Linux/macOS:
        ```json
        "LaravelExtraIntellisense.phpCommand": "php -r \"; system('calc.exe'); {code}; \""  // For Windows
        "LaravelExtraIntellisense.phpCommand": "php -r \"; system('gnome-calculator'); {code}; \"" // For Linux/macOS (Requires gnome-calculator)
        ```
        Alternatively, for a less intrusive test, use `echo`:
        ```json
        "LaravelExtraIntellisense.phpCommand": "php -r \"; system('echo VULNERABILITY_DEMOSTRATION'); {code}; \""
        ```
    6. **Trigger Autocompletion:** Open any PHP or Blade file in your Laravel project.
    7. **Initiate Laravel Extension Functionality:** Trigger any autocompletion feature of the extension that relies on executing PHP code. For example, try to get route autocompletion by typing `route('` or view autocompletion by typing `view('`.
    8. **Observe Command Execution:**
        - **Expected Result (Vulnerable):** If the vulnerability exists, you should observe the calculator application (`calc.exe` or `gnome-calculator`) launching, or "VULNERABILITY_DEMOSTRATION" being printed in the output if you used `echo`. This indicates that the injected system command within `phpCommand` was executed.
        - Check the "Laravel Extra Intellisense" output channel (View -> Output -> Laravel Extra Intellisense) for any error messages or output related to the command execution.

This test case demonstrates that by modifying the `phpCommand` configuration, an attacker can achieve arbitrary command execution on the developer's machine, confirming the Command Injection vulnerability.
