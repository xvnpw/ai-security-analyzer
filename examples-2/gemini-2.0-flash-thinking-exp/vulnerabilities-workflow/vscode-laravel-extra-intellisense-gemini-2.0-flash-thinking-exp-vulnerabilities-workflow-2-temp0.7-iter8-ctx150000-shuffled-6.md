- Vulnerability Name: Configuration Injection in `phpCommand`
- Description:
    1. An attacker can modify the `LaravelExtraIntellisense.phpCommand` setting within the VS Code workspace configuration.
    2. This setting is used by the extension to construct and execute PHP commands in the user's Laravel application context.
    3. By altering this setting, the attacker can inject arbitrary PHP code.
    4. When the extension subsequently triggers a feature that relies on executing PHP code (e.g., autocompletion for routes, views, configs, etc.), the injected code will be executed.
    5. This execution happens within the security context of the user's Laravel application, potentially allowing the attacker to perform unauthorized actions.
- Impact:
    - Arbitrary PHP code execution within the Laravel application.
    - This can lead to a wide range of security issues, including:
        - Data breaches: Accessing and exfiltrating sensitive application data.
        - Application compromise: Modifying application logic, creating backdoors, or taking over the application.
        - Server compromise: In some scenarios, gaining shell access to the server hosting the Laravel application, depending on server configurations and PHP permissions.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Security Note in `README.md`: The README.md file contains a "Security Note" section that warns users about the extension executing their Laravel application and advises caution with sensitive code in service providers.
    - Location: `README.md` file, under the "Security Note" heading.
    - Description: This mitigation is purely informational and relies on the user reading and understanding the security implications. It does not prevent the vulnerability but aims to raise awareness.
- Missing Mitigations:
    - Input validation and sanitization for `LaravelExtraIntellisense.phpCommand`: The extension lacks any validation or sanitization of the `phpCommand` setting. It directly uses the user-provided string to construct shell commands.
    - Secure command execution: Instead of directly executing the user-provided command string, the extension could use safer methods to execute PHP code, potentially with restrictions on the executed commands or sandboxing. However, due to the nature of the extension needing to interact with the Laravel application, sandboxing might be challenging to implement effectively without breaking functionality.
- Preconditions:
    1. Attacker's ability to modify VS Code workspace settings: The attacker needs a way to modify the `.vscode/settings.json` file in the user's workspace or the user's global VS Code settings that apply to the workspace. This could be achieved through:
        - Social engineering: Tricking the user into manually changing the setting.
        - Phishing or malware: Automatically modifying the settings file without the user's explicit consent.
        - Compromised workspace: If the user opens a workspace from an untrusted source that already contains a malicious `.vscode/settings.json`.
    2. Laravel Extra Intellisense extension installed and activated: The user must have the "Laravel Extra Intellisense" extension installed and activated in their VS Code environment, and be working on a Laravel project.
    3. Extension trigger: The vulnerability is triggered when the extension attempts to execute a PHP command using the `runLaravel` function. This occurs automatically when the extension's autocompletion or other features are used in a Laravel project.
- Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Code snippet:
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
    4. Analysis:
        - The `runPhp` function retrieves the `phpCommand` setting from the VS Code configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It uses a default value `"php -r \"{code}\""` if the setting is not configured.
        - It replaces the `{code}` placeholder in the `phpCommand` template with the `$code` argument, which contains the PHP code to be executed by the extension.
        - Critically, it directly executes the resulting command string using `cp.exec(command, ...)`. There is no validation or sanitization of the `phpCommand` setting itself. This allows an attacker to inject arbitrary shell commands by modifying the `phpCommand` setting.
- Security Test Case:
    1. Prerequisites:
        - VS Code installed with Laravel Extra Intellisense extension.
        - A Laravel project opened in VS Code.
        - Web server running the Laravel project (e.g., using `php artisan serve` or Docker).
    2. Steps:
        - Open the workspace settings of your Laravel project in VS Code (`.vscode/settings.json` or Workspace Settings UI).
        - Add or modify the `LaravelExtraIntellisense.phpCommand` setting to inject malicious PHP code:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "echo '; system($_GET[\"cmd\"]); // ' php -r \"{code}\""
          }
          ```
          This command will first echo an empty string (to make the JSON valid), then execute the `system($_GET["cmd"])` function, which allows executing shell commands via the `cmd` GET parameter. The original `php -r \"{code}\"` part is commented out using `//` to prevent errors from the original intended command.
        - Open any PHP file within your Laravel project (e.g., a controller or a blade template).
        - Trigger any autocompletion feature provided by the extension. For example, in a PHP file, type `config('` to trigger config autocompletion, or in a Blade file, type `@lang('` to trigger translation autocompletion. This action will cause the extension to execute `runLaravel` and consequently `runPhp` with the modified `phpCommand`.
        - Open a web browser and navigate to the URL of your Laravel application.
        - Append the `?cmd=whoami` parameter to the URL to execute the `whoami` shell command (e.g., `http://localhost:8000/?cmd=whoami`).
    3. Expected Result:
        - The web page will display the output of the `whoami` command. This output is the username of the user under which the PHP process is running on the server.
        - This confirms that the injected `system($_GET["cmd"])` code was successfully executed by the extension due to the configuration injection vulnerability in `LaravelExtraIntellisense.phpCommand`. The attacker can now execute arbitrary shell commands on the server by changing the `cmd` parameter in the URL.
