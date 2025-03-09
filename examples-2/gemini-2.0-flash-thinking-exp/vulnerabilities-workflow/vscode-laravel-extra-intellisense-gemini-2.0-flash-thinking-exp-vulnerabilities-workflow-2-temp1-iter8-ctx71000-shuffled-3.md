### Vulnerability List:

- **Vulnerability Name:** Command Injection via `phpCommand` setting
- **Description:**
    1. The VSCode extension "Laravel Extra Intellisense" allows users to configure the PHP command used for internal operations via the `LaravelExtraIntellisense.phpCommand` setting. This setting defaults to `php -r "{code}"`.
    2. The extension uses this setting in `helpers.ts` within the `runPhp` and `runLaravel` functions to execute PHP code within the user's Laravel project.
    3. A malicious actor or a compromised user can modify the `LaravelExtraIntellisense.phpCommand` setting in VSCode's `settings.json` to inject arbitrary system commands. For example, setting it to `php -r "{code}" && malicious_command`.
    4. When the extension subsequently attempts to gather autocompletion data (which happens automatically and periodically as the user works), it executes PHP code using the manipulated `phpCommand`. This execution is performed via `child_process.exec`.
    5. Consequently, the injected malicious commands are executed on the developer's machine with the privileges of the VSCode process, leading to arbitrary code execution.
- **Impact:**
    - **Critical**: Successful exploitation allows for arbitrary code execution on the developer's machine.
    - This can lead to severe consequences such as:
        - **Data theft**: Access to sensitive project files, environment variables, and credentials.
        - **Malware installation**: Introduction of viruses, ransomware, or other malicious software.
        - **System compromise**: Full control over the developer's machine, potentially pivoting to internal networks.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - **Security Note in README.md**: The extension's README.md includes a "Security Note" advising users to be cautious due to the extension's execution of Laravel application code. It suggests temporarily disabling the extension when working with sensitive code.
        - **Location:** `README.md` - Security Note section.
        - **Effectiveness:** This is a documentation-level warning and does not provide any technical mitigation within the code itself. It relies on the user's awareness and vigilance.
- **Missing Mitigations:**
    - **Input Validation and Sanitization for `phpCommand`**: The extension should validate and sanitize the `LaravelExtraIntellisense.phpCommand` setting to prevent the injection of arbitrary commands. This could include:
        - **Allowlisting**: Restricting the allowed characters or commands within the setting.
        - **Parsing and validation**: Parsing the provided command to ensure it adheres to an expected format and does not contain potentially harmful components.
    - **Warning Message on `phpCommand` Modification**: Display a prominent warning message to the user when they attempt to modify the `LaravelExtraIntellisense.phpCommand` setting, especially if it deviates from the default or a set of known safe configurations.
    - **Sandboxed Execution Environment**: Consider executing the PHP commands in a sandboxed environment or using more secure alternatives to `child_process.exec` if possible, to limit the potential impact of command injection vulnerabilities.
- **Preconditions:**
    - **User Modification of `phpCommand`**: The attacker needs to be able to modify the `LaravelExtraIntellisense.phpCommand` setting in the user's VSCode configuration. This can be achieved through:
        - **Local Access**: Direct access to the developer's machine to modify the `settings.json` file.
        - **Social Engineering**: Tricking the user into manually changing the setting, for example, by providing malicious configuration snippets disguised as performance optimizations or Docker setup instructions.
- **Source Code Analysis:**
    1. **`src/helpers.ts` - `runPhp` function:**
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

                cp.exec(command, // Vulnerable code: command is constructed from user-provided setting
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
        - The `commandTemplate` variable directly retrieves the value of the `LaravelExtraIntellisense.phpCommand` configuration setting without any validation or sanitization.
        - The `command` variable is then constructed by simply replacing the `{code}` placeholder in the `commandTemplate` with the PHP code generated by the extension.
        - `cp.exec(command, ...)` executes the constructed `command` using the Node.js `child_process.exec` function. This function directly executes shell commands, making it vulnerable to command injection if the `command` variable contains malicious shell code.
        - The code includes escaping for double quotes and some platform-specific characters within the `code` variable, but this escaping is insufficient to prevent command injection because the `commandTemplate` itself is not validated and can contain arbitrary commands.
    2. **`src/helpers.ts` - `runLaravel` function:**
        - This function builds a more complex PHP command string that includes Laravel bootstrapping code and then appends the `$code` to be executed within the Laravel environment.
        - It subsequently calls the `runPhp` function to execute this constructed command.
        - Because `runLaravel` relies on `runPhp` and does not implement any additional sanitization of the `phpCommand` setting, it is also vulnerable to command injection.

- **Security Test Case:**
    1. **Precondition:** Ensure you have VSCode installed with the "Laravel Extra Intellisense" extension, and you have a Laravel project open in VSCode.
    2. **Steps:**
        a. Open VSCode settings: `File` -> `Preferences` -> `Settings` (or `Code` -> `Settings` on macOS).
        b. Navigate to `Extensions` -> `Laravel Extra Intellisense` or search for "LaravelExtraIntellisense: Php Command" in the settings search bar.
        c. Modify the `Laravel Extra Intellisense: Php Command` setting to the following malicious command:
           ```json
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}' && touch /tmp/vuln_test_file_by_vscode_extension"
           ```
           This command will execute the extension's intended PHP code and, upon successful execution, will also create a file named `vuln_test_file_by_vscode_extension` in the `/tmp/` directory (on Linux/macOS). On Windows, you can use `type nul > C:\\vuln_test_file_by_vscode_extension`.
        d. Open any PHP or Blade file within your Laravel project in VSCode.
        e. Trigger autocompletion to force the extension to run PHP code. For example, in a Blade file, type `route('` or in a PHP file, type `Config::get(`.
    3. **Expected Result:**
        - The autocompletion feature should still function as expected (though it might be slightly delayed due to the added command).
        - **Vulnerability Confirmation**: The file `/tmp/vuln_test_file_by_vscode_extension` (or `C:\\vuln_test_file_by_vscode_extension` on Windows) should be created. This confirms that the injected command `touch /tmp/vuln_test_file_by_vscode_extension` was executed successfully alongside the extension's PHP code, demonstrating arbitrary command execution.
