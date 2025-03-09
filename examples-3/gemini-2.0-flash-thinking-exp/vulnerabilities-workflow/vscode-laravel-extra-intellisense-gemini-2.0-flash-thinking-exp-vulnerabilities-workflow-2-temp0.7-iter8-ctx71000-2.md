- **Vulnerability Name:** Arbitrary PHP Code Execution via `phpCommand` Configuration
- **Description:**
    1.  The "Laravel Extra Intellisense" extension for VSCode allows users to customize the PHP command used to interact with their Laravel application via the `LaravelExtraIntellisense.phpCommand` setting.
    2.  This setting is intended to allow users to configure the extension for different environments, such as Docker or Laravel Sail, by modifying the command used to execute PHP scripts.
    3.  The extension uses this configured command to execute PHP code snippets to gather information about routes, views, configurations, and other Laravel-specific data required for autocompletion.
    4.  A malicious actor can exploit this configuration by modifying the `LaravelExtraIntellensense.phpCommand` setting to inject arbitrary PHP code.
    5.  When the extension attempts to gather autocompletion data, it will execute the modified `phpCommand` including the injected malicious PHP code on the developer's machine.
- **Impact:**
    - Arbitrary PHP code execution on the developer's machine with the privileges of the user running VSCode.
    - This can lead to a wide range of attacks, including:
        - **Data theft:** Access to sensitive files, environment variables, and other data on the developer's machine.
        - **System compromise:** Installation of malware, backdoors, or other malicious software.
        - **Remote code execution:** Potential for further exploitation and control of the developer's machine.
        - **Denial of Service:** Crashing the developer's machine or disrupting their workflow.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** The extension's README.md includes a "Security Note" that warns users about the potential risks of running the extension and executing their Laravel application automatically. This note advises users to be cautious and temporarily disable the extension if they are writing sensitive code in service providers.
    - **Location:** [README.md#security-note](..\vscode-laravel-extra-intellisense\README.md#security-note)
    - **Effectiveness:** This mitigation is weak and relies solely on the user's awareness and caution. It does not prevent the vulnerability but merely informs users of the risk.
- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The extension should validate and sanitize the `phpCommand` setting to prevent the injection of arbitrary commands or code. This could include:
        - Whitelisting allowed commands or command patterns.
        - Escaping special characters in user-provided input.
        - Preventing the use of shell operators or redirects.
    - **Restricting Execution Environment:** The extension could attempt to restrict the execution environment of the PHP code to minimize the potential impact of code injection. This might involve using sandboxing techniques or running the PHP process with reduced privileges.
    - **Alternative Data Gathering Mechanisms:** The extension could explore safer alternatives to executing arbitrary PHP code for gathering autocompletion data. This could involve:
        - Static analysis of Laravel project files to extract relevant information.
        - Using Laravel's built-in reflection capabilities in a more controlled manner, without executing the entire application.
    - **Principle of Least Privilege:** The extension's design should be reviewed to ensure that it truly requires the execution of arbitrary PHP code. If not, the functionality should be refactored to eliminate this risky requirement.
- **Preconditions:**
    1.  The user has installed the "Laravel Extra Intellisense" extension in VSCode.
    2.  The user has opened a Laravel project in VSCode.
    3.  An attacker has the ability to modify the user's VSCode settings, either through local access to the machine or by social engineering techniques (e.g., tricking the user into pasting malicious settings).
- **Source Code Analysis:**
    1.  **`helpers.ts` - `Helpers.runPhp(code: string, description: string|null = null)` function:**
        - This function is responsible for executing PHP code.
        - It takes a string `code` as input, which represents the PHP code to be executed.
        - It retrieves the PHP command template from the `LaravelExtraIntellisense.phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It replaces the `{code}` placeholder in the command template with the provided `code` using `commandTemplate.replace("{code}", code)`.
        - It uses `child_process.exec(command, ...)` to execute the constructed command.
        - **Vulnerability Point:** The `code` variable, which is directly derived from the extension's internal logic and potentially user configurations, is directly embedded into the shell command without any sanitization or validation. This allows for command injection if the `phpCommand` setting is maliciously modified.

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\""); // Basic escaping for double quotes
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$"); // Basic escaping for dollar signs on Unix-like systems
            code = code.replace(/\\\\'/g, '\\\\\\\\\''); // More escaping
            code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // More escaping
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code); // Vulnerable point: code is directly inserted
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Executing the unsanitized command
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ... error handling and output processing ...
                }
            );
        });
        return out;
    }
    ```
    2.  **Various Provider Files (`AuthProvider.ts`, `BladeProvider.ts`, `ConfigProvider.ts`, etc.):**
        - These provider files use `Helpers.runLaravel()` and indirectly `Helpers.runPhp()` to execute PHP code for different features like autocompleting routes, views, configs, etc.
        - For example, in `ConfigProvider.ts`, `Helpers.runLaravel("echo json_encode(config()->all());", "Configs")` is used to fetch configuration data.
        - If the `phpCommand` is compromised, every feature that relies on these providers becomes a potential trigger for malicious code execution.

- **Security Test Case:**
    1.  **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Open any Laravel project in VSCode.
    2.  **Modify `phpCommand` setting:**
        - Go to VSCode settings (File > Preferences > Settings or Code > Settings > Settings).
        - Search for "LaravelExtraIntellisense: Php Command".
        - In the "Value" field, replace the default command (e.g., `php -r "{code}"`) with a malicious command.
            - **Windows Example (launches calculator):** `php -r "system('calc.exe');"`
            - **Linux/macOS Example (launches calculator or displays a message):** `php -r "system('gnome-calculator &');"` or `php -r "system('osascript -e \\'display notification \\"Vulnerability Triggered\\" with title \\"Laravel Extension\\"\\'');"`
        - Ensure the modified setting is saved.
    3.  **Trigger Autocompletion:**
        - Open any PHP file (e.g., a controller or blade template) in your Laravel project.
        - Start typing a Laravel function that triggers the extension's autocompletion (e.g., `route('`, `view('`, `config('`).
        - For example, type `config('ap` in a PHP file. This should trigger the ConfigProvider.
    4.  **Verify Code Execution:**
        - Observe if the injected malicious code is executed.
            - On Windows, the Calculator application (`calc.exe`) should launch.
            - On Linux/macOS, the Calculator application (`gnome-calculator`) should launch or a notification with "Vulnerability Triggered" should appear.
    5.  **Expected Result:** The successful execution of the injected command (e.g., calculator launching) confirms the Arbitrary PHP Code Execution vulnerability. This demonstrates that a malicious actor who can modify the `phpCommand` setting can execute arbitrary code on the developer's machine whenever the extension attempts to use the configured PHP command.
