### Vulnerability List

- Vulnerability Name: Remote Code Execution via `phpCommand` configuration
- Description:
    1. A user installs the "Laravel Extra Intellisense" VS Code extension.
    2. An attacker gains the ability to modify the user's VS Code settings, specifically the `LaravelExtraIntellisense.phpCommand` setting. This could be achieved through various means, such as social engineering, phishing, or compromising the user's machine through other vulnerabilities.
    3. The attacker modifies the `LaravelExtraIntellisense.phpCommand` setting to inject malicious PHP code. For example, they might change it to: `php -r "system('malicious_command'); {code}"`.
    4. The developer uses the VS Code extension as intended, working on a Laravel project.
    5. When the extension needs to gather autocompletion data (e.g., for routes, views, configs), it executes PHP code by running a command based on the `phpCommand` setting.
    6. Due to the attacker's modification, the injected malicious PHP code (`system('malicious_command')` in the example) is executed on the developer's machine, within the context of their Laravel application environment, before the intended extension code is run.
- Impact:
    - **Complete compromise of the developer's environment:** The attacker can execute arbitrary commands on the developer's machine with the same privileges as the user running VS Code.
    - **Data theft:** The attacker can access and exfiltrate sensitive data, including source code, database credentials, environment variables, and other project files.
    - **Code modification:** The attacker can modify the project's source code, potentially injecting backdoors, malware, or introducing vulnerabilities into the application itself.
    - **Denial of service:** The attacker could execute commands that consume system resources, leading to a denial of service on the developer's machine or the Laravel application's development environment.
    - **Lateral movement:** If the developer's machine is part of a network, the attacker could use the compromised machine to gain access to other systems on the network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension's code directly uses the `phpCommand` setting without any input validation or sanitization.
    - The `README.md` file includes a "Security Note" that warns users about the risks of running the extension, but this is not a technical mitigation. It states: "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. So if you have any unknown errors in your log make sure the extension not causing it. Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing." This note is more of a disclaimer and a suggestion for users to be cautious rather than a mitigation built into the extension itself.
- Missing Mitigations:
    - **Input validation and sanitization:** The extension should validate and sanitize the `phpCommand` setting to prevent injection of arbitrary commands. This could involve:
        - Restricting allowed characters in the `phpCommand` setting.
        - Whitelisting allowed commands or command patterns.
        - Using parameterized commands or নিরাপদ command execution methods that prevent injection.
    - **Principle of least privilege:** The extension should ideally not require executing arbitrary PHP code from user configuration. If possible, the extension's functionality should be redesigned to minimize or eliminate the need for user-provided commands.
    - **Security warnings in settings UI:** Display a clear and prominent warning in the VS Code settings UI when users are configuring the `phpCommand` setting, emphasizing the security risks associated with modifying this setting and advising them to only use trusted and safe commands.
- Preconditions:
    - The "Laravel Extra Intellisense" VS Code extension is installed.
    - The attacker has the ability to modify the user's VS Code configuration settings, specifically `LaravelExtraIntellisense.phpCommand`.
- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code); // Vulnerable line: Direct string replacement without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Execution of the constructed command
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
    - **Vulnerability Explanation:**
        - The `runPhp` function in `helpers.ts` is responsible for executing PHP code.
        - It retrieves the `phpCommand` setting from VS Code configuration, which defaults to `php -r "{code}"`.
        - The function then uses simple string replacement (`commandTemplate.replace("{code}", code)`) to insert the PHP code to be executed into the command.
        - **Crucially, there is no sanitization or validation of either the `phpCommand` setting or the `code` variable before executing the command using `cp.exec`.**
        - This allows an attacker who can modify the `phpCommand` setting to inject arbitrary shell commands or PHP code. The injected code will be executed whenever the extension attempts to gather autocompletion data.
    - **Visualization:**

    ```
    [VS Code Settings (LaravelExtraIntellisense.phpCommand)] --> Attacker Controlled Input
                                                                    |
                                                                    V
    "php -r \"{code}\"" (Default Command Template) --> `commandTemplate` in runPhp()
                                                                    |
                                                                    V
    `code` (PHP code to execute for autocompletion) --> User Input (indirectly triggered by extension)
                                                                    |
                                                                    V
    `command = commandTemplate.replace("{code}", code)` --> String Replacement (Vulnerable Point)
                                                                    |
                                                                    V
    `cp.exec(command)` --> Command Execution (Remote Code Execution)
    ```
- Security Test Case:
    1. **Environment Setup:**
        - Ensure you have VS Code installed.
        - Install the "Laravel Extra Intellisense" extension in VS Code.
        - Open a Laravel project in VS Code. If you don't have one, create a basic Laravel project.
        - Ensure you have PHP installed and accessible in your system's PATH.
    2. **Modify `phpCommand` Setting (Malicious Configuration):**
        - Open VS Code settings (File -> Preferences -> Settings, or Code -> Settings -> Settings on macOS).
        - In the Settings editor, search for "LaravelExtraIntellisense: Php Command".
        - Click the "Edit in settings.json" icon to open your `settings.json` file.
        - Add or modify the `LaravelExtraIntellisense.phpCommand` setting to the following malicious command:
        ```json
        "LaravelExtraIntellisense.phpCommand": "php -r \\"system('touch /tmp/pwned_by_laravel_intellisense'); {code}\\""
        ```
        - This malicious command injects `system('touch /tmp/pwned_by_laravel_intellisense')` before the original code. This injected code will attempt to create a file named `pwned_by_laravel_intellisense` in the `/tmp/` directory when the extension executes.
        - Save the `settings.json` file.
    3. **Trigger Extension Autocompletion:**
        - Open any PHP file or Blade template file in your Laravel project (e.g., a Blade view file `welcome.blade.php` or a controller file).
        - In the opened file, type `route('` or `config('` or any other Laravel helper function that triggers autocompletion provided by the extension.
        - Wait for a few seconds for the extension to process and provide autocompletion suggestions. This action will trigger the extension to execute PHP code using the configured `phpCommand`.
    4. **Verify Remote Code Execution:**
        - Open a terminal or command prompt on your system.
        - Check if the file `/tmp/pwned_by_laravel_intellisense` has been created by running the command: `ls /tmp/pwned_by_laravel_intellisense` (on Linux/macOS) or check for the file in `C:\tmp\` if you are on Windows and adjusted the command accordingly.
        - If the file `pwned_by_laravel_intellisense` exists in the `/tmp/` directory, it confirms that the injected `system('touch /tmp/pwned_by_laravel_intellisense')` command was successfully executed by the extension, demonstrating Remote Code Execution vulnerability.
    5. **Clean up (Optional):**
        - Delete the `/tmp/pwned_by_laravel_intellisense` file: `rm /tmp/pwned_by_laravel_intellisense`.
        - Revert the `LaravelExtraIntellisense.phpCommand` setting in your `settings.json` back to its default value or remove it to use the default.

This test case demonstrates how a malicious user can inject arbitrary commands via the `phpCommand` setting and achieve Remote Code Execution.
