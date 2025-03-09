## Vulnerabilities List

### Arbitrary PHP Code Execution via `phpCommand` Configuration

- **Vulnerability Name:** Arbitrary PHP Code Execution via `phpCommand` Configuration
- **Description:**
    1. The "Laravel Extra Intellisense" extension for Visual Studio Code allows developers to customize the PHP command used by the extension through the `LaravelExtraIntellisense.phpCommand` setting. This is intended to support various environments like Docker or Laravel Sail, where a simple `php` command might not suffice.
    2. This setting is used by the extension to execute PHP scripts from the opened Laravel project to gather necessary information for autocompletion features, such as route lists, view variables, and configuration values.
    3. A malicious actor can exploit this by manipulating the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary operating system commands. This can be achieved by crafting a malicious Laravel project that includes a `.vscode/settings.json` file with a modified `phpCommand` setting, or by tricking a developer into manually changing this setting in their VS Code configuration.
    4. When a developer opens a project with a malicious `.vscode/settings.json` or has a maliciously configured `phpCommand` setting, the extension, upon activation or when autocompletion is triggered, will execute PHP code using this compromised command.
    5. Due to the lack of sanitization or validation of the `phpCommand` setting, any commands injected into it will be executed by the underlying shell command execution function (`child_process.exec` in Node.js). This results in arbitrary command execution on the developer's machine, beyond the intended PHP code execution.

- **Impact:**
    - **Critical Impact:** Successful exploitation of this vulnerability leads to arbitrary code execution on the developer's machine with the privileges of the user running VS Code.
    - **Full System Compromise:** An attacker can gain complete control over the developer's system, potentially leading to:
        - **Data Theft:** Access to sensitive information, including source code, credentials, environment variables, and personal files.
        - **Malware Installation:** Installation of malware, backdoors, ransomware, or other malicious software.
        - **System Takeover:** Complete control of the affected machine, allowing for further malicious activities within the developer's environment and potentially the organization's network.
        - **Code Modification:** Attackers can modify project files, inject backdoors into the codebase, or introduce vulnerabilities into the application being developed.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Security Note in `README.md`:** The extension's `README.md` file includes a "Security Note" section that warns users about the risks of running the extension and executing their Laravel application automatically. It advises caution, especially when working with sensitive code in service providers, suggesting to temporarily disable the extension in such cases.
        - **File:** `README.md`
        - **Section:** `Security Note`
        - **Effectiveness:** This mitigation is extremely weak and relies solely on user awareness and caution. It does not technically prevent the vulnerability and is easily overlooked by developers. It acts more as a disclaimer than an actual security measure.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The most critical missing mitigation is the lack of input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting. The extension should implement robust validation to ensure that the configured command is safe and prevents the injection of arbitrary shell commands. This could include:
        - **Whitelisting allowed commands or command patterns:** Restricting the `phpCommand` to a predefined set of safe commands or patterns, ensuring it only executes `php` with specific, safe arguments.
        - **Escaping special characters:** Properly escaping shell-sensitive characters in the user-provided `phpCommand` setting. However, escaping alone is often insufficient to prevent command injection.
        - **Preventing shell operators and redirects:** Disallowing the use of shell operators (like `&`, `;`, `|`, `>` etc.) and redirects in the `phpCommand` setting.
    - **Restricting Execution Environment (Sandboxing):** The extension could explore sandboxing techniques to isolate the execution of PHP code. Running the PHP process in a restricted environment could limit the impact of any malicious code execution. Technologies like containers or secure sandboxes could be considered.
    - **Principle of Least Privilege:** Re-evaluate the necessity of executing arbitrary PHP code from user configuration. If possible, the extension's design should be refactored to minimize or eliminate the need for user-provided commands and potentially explore safer mechanisms for gathering autocompletion data, such as static analysis or controlled reflection.
    - **Prominent Security Warnings within VS Code:** Display a clear and prominent warning within the VS Code settings UI when a user modifies the `LaravelExtraIntellisense.phpCommand` setting. This warning should highlight the security risks associated with custom commands and advise users to only use trusted and safe configurations.
    - **Restricting to `php -r "{code}"`:**  The simplest and most effective mitigation would be to remove the user-configurable `phpCommand` setting altogether and hardcode the execution command to `php -r "{code}"`, disallowing any modifications or additional commands. This would eliminate the command injection vulnerability but might limit flexibility for users in specific environments.

- **Preconditions:**
    1. The "Laravel Extra Intellisense" extension is installed and activated in Visual Studio Code.
    2. A Laravel project is opened in VS Code.
    3. The `LaravelExtraIntellisense.phpCommand` setting is either:
        - Modified by a malicious actor in the workspace settings (`.vscode/settings.json` within the Laravel project).
        - Modified by the developer themselves, potentially through social engineering or by unknowingly applying malicious settings.

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
        let command = commandTemplate.replace("{code}", code); // [VULNERABLE CODE] String replacement without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABLE CODE] Command execution with user-defined command
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ... error handling and output processing ...
                }
            );
        });
        return out;
    }
    ```
    - **Explanation:**
        - The `runPhp` function is responsible for executing PHP code within the extension.
        - It retrieves the `phpCommand` setting from VS Code's configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. If no setting is defined, it defaults to `"php -r \"{code}\""`.
        - The function then constructs the command to be executed by replacing the placeholder `{code}` in the `commandTemplate` with the actual PHP code (`code` argument).
        - **Vulnerability:** The crucial vulnerability lies in the direct string replacement using `commandTemplate.replace("{code}", code)` and the subsequent execution of the resulting `command` string using `child_process.exec(command, ...)`. There is no sanitization or validation applied to either the `commandTemplate` (which is derived from user configuration) or the `code` variable before execution. This allows for command injection if the `phpCommand` setting is maliciously crafted to include additional shell commands.
        - **Visualization:**
        ```
        [VS Code Configuration: LaravelExtraIntellisense.phpCommand] --> User Controlled Input (Maliciously Modifiable)
                                                                         |
                                                                         V
        "php -r \"{code}\"" (Default Template) OR Malicious Command --> commandTemplate (in `runPhp`)
                                                                         |
                                                                         V
        PHP Code for Autocompletion (e.g., `echo json_encode(config()->all());`) --> code (in `runPhp`)
                                                                         |
                                                                         V
        String Concatenation (commandTemplate.replace("{code}", code)) --> command (Unsanitized Command String)
                                                                         |
                                                                         V
        `child_process.exec(command)` --> Command Execution (Arbitrary Code Execution Vulnerability)
        ```

- **Security Test Case:**
    1. **Prerequisites:**
        - Visual Studio Code installed.
        - "Laravel Extra Intellisense" extension installed.
        - A Laravel project opened in VS Code.
        - PHP installed and accessible in your system's PATH.
    2. **Malicious Configuration:**
        - Open VS Code settings (File > Preferences > Settings or Code > Settings > Settings).
        - Search for "LaravelExtraIntellisense: Php Command".
        - Modify the `LaravelExtraIntellisense.phpCommand` setting to the following malicious command (example for Linux/macOS - adapt for Windows if needed):
        ```json
        "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/vscode_extension_pwned\"); {code}'"
        ```
        - This command will attempt to create a file named `vscode_extension_pwned` in the `/tmp/` directory in addition to executing the intended PHP code.
    3. **Trigger Autocompletion:**
        - Open any PHP file (e.g., a controller or blade template) in your Laravel project.
        - Start typing a Laravel function that triggers autocompletion, such as `config(` or `route(`. This action will invoke the extension and trigger the execution of the PHP command using the malicious `phpCommand` setting.
    4. **Verify Command Execution:**
        - Open a terminal or command prompt.
        - Check if the file `/tmp/vscode_extension_pwned` exists by running the command `ls /tmp/vscode_extension_pwned`.
        - If the file exists, it confirms that the injected `system("touch /tmp/vscode_extension_pwned")` command was successfully executed, demonstrating arbitrary command execution.
    5. **Expected Result:** The successful creation of the `/tmp/vscode_extension_pwned` file indicates that arbitrary commands injected via the `phpCommand` setting are executed by the extension, confirming the Remote Code Execution vulnerability.

This detailed description combines the information from all provided vulnerability lists, ensuring all required sections are present and thoroughly explained. It clearly demonstrates the critical nature of the vulnerability and how it can be exploited.
