- Vulnerability name: Remote Code Execution via `phpCommand` configuration
- Description:
    1. An attacker convinces a developer to install the "Laravel Extra Intellisense" VSCode extension.
    2. The attacker encourages the developer to open a Laravel project in VSCode.
    3. The attacker tricks the developer into setting a malicious `phpCommand` in the extension's configuration. For example, a malicious command could be: `"php -r \\"{code}; system(\$_GET[cmd]);\\""`.
    4. The extension, when activated, executes PHP code using the configured `phpCommand` to gather autocompletion data. This happens automatically in background when developer is working on project.
    5. If the malicious `phpCommand` is set, the attacker can inject arbitrary system commands via `cmd` GET parameter that will be executed on the developer's machine.
    6. For example, with `php -r "{code}; system(\$_GET[cmd]);"` as `phpCommand`, sending a request like `curl "http://localhost:8000/?cmd=whoami"` will execute the `whoami` command on the developer's machine.
- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the developer's machine with the privileges of the user running VSCode. This can lead to full system compromise, data theft, malware installation, and other malicious activities.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. While the README.md includes a "Security Note" warning users about potential risks, there are no code-level mitigations to prevent the vulnerability. The warning in documentation is not a sufficient mitigation.
- Missing mitigations:
    - Input validation and sanitization of the `phpCommand` configuration. The extension should validate and sanitize the `phpCommand` to prevent the injection of malicious commands. However, this is complex and might not be fully effective.
    - Principle of least privilege. The extension could potentially run the PHP commands in a more restricted environment, although this might be challenging to implement within a VSCode extension context.
    - User awareness and stronger warnings. Displaying a more prominent warning within VSCode itself when a user modifies the `phpCommand` configuration to highlight the security risks.
- Preconditions:
    1. The developer has installed the "Laravel Extra Intellisense" VSCode extension.
    2. The developer has opened a Laravel project in VSCode.
    3. The developer has configured a malicious `phpCommand` in the extension's settings, either intentionally or unintentionally (e.g., through social engineering or supply chain attack).
- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Step-by-step analysis:
        1. The function retrieves the `phpCommand` template from the extension's configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        2. It replaces the placeholder `{code}` in the `phpCommand` template with the `$code` argument passed to the `runPhp` function using `commandTemplate.replace("{code}", code)`.
        3. The resulting `command` string, which now includes the potentially unsanitized `$code`, is executed using `cp.exec(command, ...)`.
        4. The `cp.exec` function executes the constructed command directly in the system shell without any sanitization or sandboxing.
    - Visualization:
        ```
        User Configuration (phpCommand) --> Helpers.runPhp(code) --> commandTemplate.replace("{code}", code) --> cp.exec(command) --> System Shell (RCE)
        ```
    - Code snippet from `src/helpers.ts`:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Basic escaping, not sufficient for security
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$"); // More escaping for unix-like systems, still not sufficient
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // Embedding user-provided code into command
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Executing the command in system shell
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
- Security test case:
    1. Open VSCode and load any Laravel project.
    2. Navigate to VSCode settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
    3. Search for "Laravel Extra Intellisense phpCommand".
    4. Modify the `LaravelExtraIntellisense: Php Command` setting to the following malicious command:
        ```
        php -r "{code}; system(\$_GET['cmd']);"
        ```
    5. Open any PHP file (e.g., a controller, model, or blade template) within the Laravel project. This action will trigger the extension to run PHP commands in the background.
    6. Open a terminal and execute the following `curl` command (or use any HTTP client) to send a request to a dummy address, exploiting the injected `system()` call:
        ```bash
        curl "http://localhost:8000/?cmd=whoami"
        ```
        Note: The URL and port are dummy and irrelevant because the PHP code is executed locally via CLI and not through a web server. The important part is the `cmd` parameter.
    7. Observe the output of the `whoami` command in your terminal or potentially in the VSCode output channel ("Laravel Extra Intellisense"). This confirms that the `system()` command was executed with the `cmd` parameter provided in the URL, demonstrating Remote Code Execution.
    8. To further verify arbitrary command execution and potential for harm, try a command like creating a file in the `/tmp` directory (Linux/macOS) or `C:\TEMP` (Windows):
        ```bash
        curl "http://localhost:8000/?cmd=touch /tmp/pwned.txt" # Linux/macOS
        curl "http://localhost:8000/?cmd=echo pwned > C:\\TEMP\\pwned.txt" # Windows
        ```
    9. Check if the file `pwned.txt` has been created in the specified directory. Successful file creation further confirms arbitrary command execution.
