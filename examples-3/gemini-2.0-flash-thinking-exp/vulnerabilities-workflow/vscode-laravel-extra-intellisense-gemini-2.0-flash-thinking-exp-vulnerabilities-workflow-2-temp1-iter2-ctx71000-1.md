### Vulnerability List

- **Vulnerability Name:** Command Injection via `LaravelExtraIntellisense.phpCommand` setting

- **Description:**
    1. A developer installs the "Laravel Extra Intellisense" VSCode extension.
    2. The developer opens a Laravel project in VSCode.
    3. An attacker, through social engineering or other means, persuades the developer to modify the `LaravelExtraIntellisense.phpCommand` setting in VSCode.
    4. The attacker crafts a malicious command and sets it as the value for `LaravelExtraIntellisense.phpCommand`. For example, the attacker could set it to `bash -c "{code}"`.
    5. When the extension attempts to gather autocompletion data (which happens automatically and periodically, or when the developer is editing code that triggers autocompletion), it executes a PHP command using the configured `LaravelExtraIntellisense.phpCommand`.
    6. Because the `LaravelExtraIntellisense.phpCommand` is now under the attacker's control, the malicious command is executed on the developer's machine instead of the intended PHP code. The `{code}` part is replaced by the extension with generated PHP code, but even if the generated code is safe, the attacker controls the initial command (e.g., `bash -c`).

- **Impact:**
    - **Critical Impact:** Successful exploitation allows the attacker to execute arbitrary system commands on the developer's machine with the privileges of the user running VSCode. This could lead to:
        - **Data Theft:** The attacker could steal sensitive files, source code, credentials, or other data from the developer's machine or the Laravel project.
        - **Malware Installation:** The attacker could install malware, backdoors, or other malicious software on the developer's system.
        - **System Compromise:** In a worst-case scenario, the attacker could gain complete control over the developer's machine, potentially pivoting to other systems on the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** The extension's README.md includes a "Security Note" section that warns users about the extension running their Laravel application automatically and periodically. It advises users to be cautious and temporarily disable the extension if they are writing sensitive code in service providers. It also provides sample configurations for Docker and Laravel Sail, implying that these are safer configurations without explicitly stating why or how to configure securely.
    - **Location:** `README.md` file in the project repository.
    - **Effectiveness:** Low. The security note is essentially a warning and not a technical mitigation. It relies on the developer reading and understanding the security implications, and then manually configuring the extension securely. It does not prevent command injection if a user naively sets a malicious `phpCommand`.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The extension should validate and sanitize the `LaravelExtraIntellisense.phpCommand` setting to ensure it only contains safe characters and commands. Ideally, it should verify that the command is indeed intended to execute PHP and reject any potentially malicious commands. However, reliably sanitizing against all possible command injection attempts is extremely difficult and might not be fully effective.
    - **Restrict Customization:** Consider removing or significantly restricting the ability to customize the `LaravelExtraIntellisense.phpCommand`. If customization is necessary, provide a very limited and safe way to modify it, perhaps through predefined options or by only allowing modifications to specific parts of the command, and disallowing execution of arbitrary external commands.
    - **Principle of Least Privilege:**  The extension could explore alternative methods to obtain Laravel application data that do not involve executing arbitrary PHP code using a user-configurable command.  If executing PHP code is unavoidable, it should be done in the most secure way possible, minimizing the risk of command injection.
    - **User Warning on Modification:** If the `phpCommand` setting is to be kept customizable, the extension should display a prominent warning to the user whenever they attempt to modify it, especially if the new value deviates significantly from the default or is considered potentially unsafe. This warning should clearly explain the security risks associated with modifying this setting.

- **Preconditions:**
    1. The developer has installed the "Laravel Extra Intellisense" VSCode extension.
    2. The developer has opened a Laravel project in VSCode.
    3. The attacker is able to somehow influence the developer to change the `LaravelExtraIntellisense.phpCommand` setting to a malicious value. This could be through social engineering, phishing, or by exploiting another vulnerability in the developer's system to modify VSCode settings.

- **Source Code Analysis:**
    1. **File:** `src/helpers.ts`
    2. **Function:** `runPhp(code: string, description: string|null = null)`
    3. **Code Snippet:**
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
    4. **Analysis:**
        - The `runPhp` function is responsible for executing PHP code to gather autocompletion data.
        - It retrieves the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - The default value for `phpCommand` is `"php -r \"{code}\""`.
        - The function then constructs the actual command to execute by replacing the `{code}` placeholder in the `commandTemplate` with the `$code` argument provided to `runPhp`.
        - `cp.exec(command, ...)` is used to execute the constructed command on the system.
        - **Vulnerability:** The crucial point is that the `phpCommand` setting, which is user-configurable, is directly used to construct the command executed by `cp.exec`. If an attacker can modify this setting to include malicious commands, they can achieve command injection. The limited escaping performed in the `runPhp` function (escaping double quotes and backslashes) is insufficient to prevent command injection when the base command itself is under attacker control.

- **Security Test Case:**
    1. **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Open a new or existing Laravel project in VSCode.
        - Open the VSCode settings (JSON format).
    2. **Modify `phpCommand` setting:**
        - Add or modify the `LaravelExtraIntellisense.phpCommand` setting to the following malicious command:
          ```json
          "LaravelExtraIntellisense.phpCommand": "touch /tmp/pwned_by_vscode_extension_{code}"
          ```
          *(For Windows, you could use `powershell -Command "New-Item -ItemType File -Path C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}"`)*
    3. **Trigger Extension Activity:**
        - Open a PHP file (e.g., a controller or route file).
        - Start typing a Laravel function that would trigger autocompletion, such as `route('`. This action will cause the extension to execute a PHP command in the background to fetch route information.
    4. **Verify Exploitation:**
        - After typing `route('` and giving the extension a moment to run, check if the file `/tmp/pwned_by_vscode_extension_{code}` (or `C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}` on Windows) has been created.
        - **Success Condition:** If the file `pwned_by_vscode_extension_{code}` is created in `/tmp` (or `C:\\Windows\\Temp` on Windows), it indicates that the `touch` command (or `New-Item` on Windows) was successfully executed as part of the `LaravelExtraIntellisense.phpCommand` setting, proving command injection.
    5. **Cleanup:**
        - Remove the malicious `LaravelExtraIntellisense.phpCommand` setting from VSCode settings to restore normal extension functionality and remove the vulnerability.
        - Delete the created file `/tmp/pwned_by_vscode_extension_{code}` (or `C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}` on Windows).

This test case demonstrates that by modifying the `LaravelExtraIntellisense.phpCommand` setting, an attacker can indeed inject and execute arbitrary commands on the developer's machine when the extension attempts to run PHP code.
