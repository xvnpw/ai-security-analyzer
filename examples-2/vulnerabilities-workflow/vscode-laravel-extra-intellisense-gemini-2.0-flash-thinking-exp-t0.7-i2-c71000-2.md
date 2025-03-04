* Vulnerability Name: Command Injection via `phpCommand` configuration
* Description:
    1. The `Laravel Extra Intellisense` extension allows users to configure the `phpCommand` setting, which specifies the command used to execute PHP code. This setting is intended to allow users to customize the PHP execution environment, for example, to use Docker or other specific PHP setups.
    2. The extension uses the configured `phpCommand` in the `Helpers.runPhp` function to execute arbitrary PHP code to gather information about the Laravel project for autocompletion features.
    3. The `runPhp` function takes a PHP code snippet as input and substitutes it into the `{code}` placeholder within the configured `phpCommand`.
    4. **Vulnerability:** If the `phpCommand` configuration is not properly sanitized or validated, a malicious user can inject arbitrary shell commands by manipulating the `phpCommand` setting. When the extension executes PHP code using `runPhp`, these injected commands will also be executed by the system.
    5. To trigger this vulnerability, an attacker can provide a malicious Laravel repository to a victim. The attacker can instruct the victim to open this repository in VSCode.
    6. Once the repository is opened, the attacker can trick the victim into configuring a malicious `phpCommand` in their VSCode settings for the workspace. This could be done through social engineering or by including instructions in the repository's README.md.
    7. When the extension attempts to gather autocompletion data (which happens automatically and periodically), it will execute the malicious `phpCommand`, leading to command injection.

* Impact:
    - **Remote Code Execution (RCE):** Successful exploitation of this vulnerability allows the attacker to execute arbitrary commands on the victim's machine with the same privileges as the VSCode process. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further attacks.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - None. The extension directly uses the user-provided `phpCommand` configuration without any sanitization or validation. The "Security Note" in the README.md warns users about potential issues but does not prevent the vulnerability.

* Missing Mitigations:
    - **Input Sanitization/Validation:** The extension should sanitize or validate the `phpCommand` configuration to prevent the injection of malicious commands. This could involve:
        - Restricting the allowed characters in `phpCommand`.
        - Parsing the `phpCommand` to ensure it conforms to an expected structure.
        - Whitelisting specific commands or arguments.
        - Escaping shell metacharacters in the user-provided `phpCommand` before executing it.
    - **Parameter Escaping:** When substituting the `{code}` placeholder in `runPhp`, the extension should properly escape the PHP code to prevent it from being interpreted as shell commands. While some escaping is present, it's not sufficient to prevent all injection scenarios, especially when the base `phpCommand` itself is malicious.

* Preconditions:
    1. The victim must have the `Laravel Extra Intellisense` extension installed in VSCode.
    2. The victim must open a workspace in VSCode that is a Laravel project (or is perceived as such by the extension).
    3. The victim must be tricked into configuring a malicious `phpCommand` setting for the workspace.

* Source Code Analysis:
    1. **File: `src/helpers.ts` Function: `runPhp(code: string, description: string|null = null)`**
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\""); // Basic escaping of double quotes
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code); // Vulnerable substitution
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Command execution
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ...
                }
            );
        });
        return out;
    }
    ```
    - The code retrieves the `phpCommand` from the configuration or uses a default value.
    - It performs basic escaping of double quotes and some platform-specific escaping. However, this escaping is insufficient to prevent command injection when the `commandTemplate` itself is malicious.
    - The `{code}` placeholder is directly replaced with the provided `code` string without proper sanitization within the context of the shell command.
    - `cp.exec(command, ...)` executes the constructed command directly in the shell.

    2. **Usage across Providers:** Files like `AuthProvider.ts`, `ConfigProvider.ts`, `RouteProvider.ts`, `ViewProvider.ts`, etc., call `Helpers.runLaravel`, which in turn calls `Helpers.runPhp` with PHP code snippets. These code snippets are generally safe, but the vulnerability lies in the user-controlled `phpCommand` which can wrap these safe snippets in malicious shell commands.

* Security Test Case:
    1. **Setup:**
        - Create a new directory to act as a malicious Laravel project (you don't need a fully functional Laravel app for this test).
        - Open this directory as a workspace in VSCode.
        - Ensure the `Laravel Extra Intellisense` extension is installed and activated.

    2. **Configure Malicious `phpCommand`:**
        - Open VSCode settings (File -> Preferences -> Settings, or Code -> Settings -> Settings on macOS).
        - Go to Workspace Settings (important: exploit relies on workspace settings).
        - Search for `LaravelExtraIntellisense: Php Command`.
        - In the "Workspace" tab, override the `phpCommand` setting with the following malicious command:
          ```
          php -r "{code}"; touch /tmp/pwned
          ```
          or for windows:
          ```
          php -r "{code}"; echo pwned > %TEMP%/pwned.txt
          ```
          **Explanation:** This command attempts to execute the intended PHP code (`{code}`) and then, regardless of the PHP code's outcome, it injects a shell command. In this case, `touch /tmp/pwned` (or `echo pwned > %TEMP%/pwned.txt` on Windows) will create a file named `pwned` in the `/tmp` directory (or `%TEMP%` directory on Windows) if the command injection is successful.

    3. **Trigger Autocompletion:**
        - Open any PHP file in the workspace (or create a new one, e.g., `test.php`).
        - Type `config('app.` and wait for the autocompletion suggestions to appear (or any other autocompletion feature that triggers `runLaravel`/`runPhp`). This action will cause the extension to execute PHP code to fetch configuration data.

    4. **Verify Command Injection:**
        - After triggering autocompletion, check if the injected command was executed:
            - **Linux/macOS:** Open a terminal and check if the file `/tmp/pwned` exists using `ls /tmp/pwned`. If the file exists, the command injection was successful.
            - **Windows:** Open a command prompt or PowerShell and check if the file `%TEMP%/pwned.txt` exists. You can use `dir %TEMP%\pwned.txt`. If the file exists, the command injection was successful.

    5. **Expected Result:** If the vulnerability exists, the `pwned` file (or `pwned.txt` on Windows) will be created, indicating that the injected command was executed.

This test case demonstrates that a malicious user can inject arbitrary shell commands via the `phpCommand` configuration, leading to command injection and potential RCE.
