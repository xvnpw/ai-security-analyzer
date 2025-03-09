### Vulnerability List

- Vulnerability Name: Remote Code Execution via `phpCommand` Configuration

- Description:
    1. The "Laravel Extra Intellisense" extension allows users to configure the `phpCommand` setting in VSCode, which specifies the command used to execute PHP code for Laravel application interaction.
    2. This setting is used by the extension to run PHP scripts within the user's Laravel project to gather autocompletion data for routes, views, configs, and other Laravel features.
    3. An attacker can potentially trick a developer into modifying the `LaravelExtraIntellisense.phpCommand` setting to inject malicious commands. This could be achieved through social engineering, phishing, or by compromising the developer's VSCode settings synchronization.
    4. When the extension subsequently attempts to provide autocompletion, it executes PHP code using the user-provided `phpCommand`.
    5. If the `phpCommand` has been maliciously modified, arbitrary commands injected by the attacker will be executed on the developer's machine with the privileges of the VSCode process.

- Impact:
    Critical. Successful exploitation allows for Remote Code Execution (RCE) on the developer's machine. An attacker can gain complete control over the developer's workstation, potentially leading to:
    - Data theft: Access to source code, credentials, and other sensitive information stored on the developer's machine or accessible from it.
    - Malware installation: Installation of ransomware, spyware, or other malicious software.
    - Supply chain attacks: Compromising the developer's environment to inject malicious code into projects, potentially affecting other developers and users of the software.
    - Denial of Service: Crashing the developer's machine or system processes.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - Security Note in `README.md`: The `README.md` file includes a "Security Note" section that warns users about the extension executing their Laravel application and advises caution regarding potential errors and sensitive code execution. This note serves as a documentation-based warning but does not prevent the vulnerability.
    - Location: [README.md](../vscode-laravel-extra-intellisense/README.md), under the "Security Note" heading.

- Missing Mitigations:
    - Input Validation and Sanitization: The extension lacks any validation or sanitization of the `phpCommand` setting. It should validate that the provided command is safe and does not contain malicious or unexpected components.
    - Warning Prompt: When a user modifies the `phpCommand` setting, especially if it deviates from the default or contains potentially dangerous keywords (like `system`, `exec`, `bash`, `sh`, `powershell`, etc.), the extension should display a prominent warning prompt explaining the security risks associated with modifying this setting.
    - Principle of Least Privilege: The extension should ideally avoid relying on user-provided commands for executing code. If executing external commands is necessary, explore safer alternatives like:
        - Using a fixed, predefined set of commands internally, without user configuration.
        - Sandboxing the execution environment to limit the impact of potentially malicious commands.
        - Restricting the `phpCommand` to only accept the path to the PHP executable and handle the code execution internally in a safer manner.

- Preconditions:
    1. Developer has installed the "Laravel Extra Intellisense" VSCode extension.
    2. Attacker is able to convince or force the developer to change the `LaravelExtraIntellisense.phpCommand` setting to a malicious value. This could be through social engineering, phishing, or by exploiting other vulnerabilities to modify the developer's VSCode settings (e.g., settings sync compromise).

- Source Code Analysis:
    1. **File:** `src/helpers.ts`
    2. **Function:** `runPhp(code: string, description: string|null = null)`
    3. **Vulnerable Code Snippet:**
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

                cp.exec(command, // Vulnerable line: Executes user-controlled command
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
    4. **Code Flow Explanation:**
        - The `runPhp` function is responsible for executing arbitrary PHP code.
        - It retrieves the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. If no setting is provided, it defaults to `"php -r \"{code}\""`.
        - It then replaces the `{code}` placeholder in the `phpCommand` template with the PHP code that needs to be executed.
        - **Vulnerability:** The `command` variable, which is constructed using the user-controlled `phpCommand` setting and the PHP code, is directly passed to `child_process.exec()`. This function executes shell commands, and because the `phpCommand` is not validated, a malicious user can inject arbitrary shell commands by manipulating this setting.
        - The code performs minimal escaping of the PHP code itself (escaping double quotes and handling `$` for Unix-like systems), but there is **no validation or sanitization of the `phpCommand` itself**. This allows injection of arbitrary commands before the PHP code is even processed by `php -r`.

- Security Test Case:
    1. **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Open a Laravel project in VSCode.
    2. **Modify `phpCommand` Setting:**
        - Open VSCode Settings (JSON).
        - Add the following malicious configuration to your User or Workspace settings file:
          ```json
          "LaravelExtraIntellisense.phpCommand": "bash -c 'echo \"<?php system(\\\"calc.exe\\\"); ?>\" | php -r \"{code}\"'"
          ```
          (For Linux/macOS, replace `calc.exe` with `xcalc` or `gnome-calculator` or `open -a Calculator.app`. For example, on macOS: `"LaravelExtraIntellisense.phpCommand": "bash -c 'echo \"<?php system(\\\"open -a Calculator.app\\\"); ?>\" | php -r \"{code}\"'"`)
        - **Explanation of Malicious Command:**
          - `bash -c '...'`: Executes the string within single quotes using `bash`.
          - `echo "<?php system(\"calc.exe\"); ?>" `: Prints the PHP code `<?php system("calc.exe"); ?>` to standard output. This PHP code, when executed by `php -r`, will attempt to run the `calc.exe` (Calculator) program.
          - `| php -r "{code}"`: Pipes the output of the `echo` command (the malicious PHP code) to `php -r "{code}"`. The `{code}` placeholder will be replaced by the extension's generated PHP code, but due to the pipe, the malicious code will be executed first.

    3. **Trigger Autocompletion:**
        - Open any PHP file (e.g., a controller) or a Blade template file within your Laravel project in VSCode.
        - In the editor, type `route('` to trigger route autocompletion, or `config('` to trigger config autocompletion, or any other autocompletion feature of the extension.
    4. **Verify RCE:**
        - Observe that the Calculator application (or equivalent for your OS) is launched. This indicates that the `system("calc.exe")` command injected through the malicious `phpCommand` setting was successfully executed, confirming Remote Code Execution.

This test case demonstrates how a malicious `phpCommand` configuration can lead to arbitrary code execution when the extension attempts to use it for its autocompletion features.
