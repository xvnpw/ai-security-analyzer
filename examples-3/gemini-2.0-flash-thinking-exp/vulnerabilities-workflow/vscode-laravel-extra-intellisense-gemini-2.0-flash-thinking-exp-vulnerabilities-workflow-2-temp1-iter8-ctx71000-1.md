### Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via Malicious `phpCommand` Configuration

- Description:
    1. A threat actor creates a malicious Laravel project.
    2. Within this project, the attacker includes a `.vscode/settings.json` file.
    3. This `settings.json` file is crafted to override the `LaravelExtraIntellisense.phpCommand` setting with a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "echo 'Malicious code executed!' && touch malicious.txt"`.
    4. A developer, unaware of the malicious nature of the project, opens this project in Visual Studio Code with the "Laravel Extra Intellisense" extension installed and enabled.
    5. Upon opening the project, the extension automatically attempts to gather Laravel project information to provide autocompletion features.
    6. To do this, the extension uses the `Helpers.runLaravel()` function, which in turn utilizes the configured `phpCommand` from the project's settings.
    7. Because the attacker has replaced the default `phpCommand` with a malicious one in the project's settings, the `cp.exec()` function in `Helpers.runPhp()` executes the attacker's arbitrary command instead of the intended PHP analysis code.
    8. This results in arbitrary code execution on the developer's machine, with the privileges of the user running VS Code.

- Impact: Critical. Successful exploitation allows the attacker to execute arbitrary commands on the developer's machine. This can lead to:
    - Data theft: Sensitive information, including source code, credentials, and personal files, can be exfiltrated.
    - Malware installation: The attacker can install malware, backdoors, or ransomware on the developer's system.
    - System compromise: The attacker can gain full control of the developer's machine, potentially pivoting to internal networks and other systems.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - Documentation Warning: The extension's README.md includes a "Security Note" that warns users about the potential risks of executing the Laravel application automatically and advises caution when writing sensitive code.
    - Location: README.md file, section "Security Note".
    - Effectiveness: This mitigation is weak as it relies solely on the user reading and understanding the security implications in the documentation. It does not prevent the vulnerability itself.

- Missing Mitigations:
    - Input Sanitization: Lack of sanitization of the `code` parameter passed to `Helpers.runLaravel()` and ultimately executed by `cp.exec()`.
    - `phpCommand` Validation: No validation or restriction on the `LaravelExtraIntellisense.phpCommand` setting to prevent execution of arbitrary and potentially harmful commands.
    - Sandboxing/Isolation: The PHP code is executed directly in the user's environment without any sandboxing or isolation to limit the impact of malicious code.
    - User Confirmation: No user confirmation or warning is presented before executing PHP code, especially when the `phpCommand` setting deviates from the default or when project settings are modified.

- Preconditions:
    1. The "Laravel Extra Intellisense" VS Code extension is installed and enabled.
    2. A developer opens a malicious Laravel project in VS Code.
    3. The malicious project contains a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` with a malicious command.

- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Vulnerable Code Snippet:
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code); // [VULNERABILITY]: Unsafe substitution of 'code' into 'commandTemplate'
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABILITY]: Executes the constructed command, which can be malicious.
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
    - Visualization:
    ```mermaid
    graph LR
        A[Extension Activation/Autocompletion Trigger] --> B(Helpers.runLaravel(code));
        B --> C(Helpers.runPhp(code));
        C --> D{Construct Command from phpCommand setting and code};
        D --> E{cp.exec(command)};
        E --> F{Malicious Code Execution on Developer Machine};
    ```

- Security Test Case:
    1. **Setup:**
        - Create a new directory named `malicious-laravel-project`.
        - Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
        - Within `.vscode`, create a file named `settings.json` with the following content:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "node -e \"require('fs').writeFileSync('pwned.txt', 'You have been PWNED by Laravel Extra Intellisense extension!')\""
        }
        ```
        - Ensure you have the "Laravel Extra Intellisense" extension installed and enabled in VS Code.
    2. **Execution:**
        - Open the `malicious-laravel-project` directory in VS Code.
        - Open an empty file or any file within the project (this triggers the extension's analysis).
    3. **Verification:**
        - Check the `malicious-laravel-project` directory.
        - Verify that a new file named `pwned.txt` has been created.
        - Open `pwned.txt` and confirm it contains the message "You have been PWNED by Laravel Extra Intellisense extension!".
    4. **Expected Result:** The creation of `pwned.txt` file demonstrates successful arbitrary code execution. The `node -e` command, injected via the `phpCommand` setting, was executed by the extension, proving the vulnerability. This test case uses `node` as an example, but any system command could be executed.
