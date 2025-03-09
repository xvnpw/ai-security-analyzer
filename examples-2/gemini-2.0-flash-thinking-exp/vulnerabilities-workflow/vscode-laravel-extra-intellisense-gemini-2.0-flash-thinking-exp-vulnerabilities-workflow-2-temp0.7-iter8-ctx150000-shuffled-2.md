- Vulnerability name: Command Injection via `phpCommand` setting

- Description:
    1. The `LaravelExtraIntellisense` extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code for Laravel project analysis.
    2. This setting is intended to allow customization for different environments like Docker or Sail.
    3. However, the extension directly uses the value of this setting to execute PHP code without any sanitization or validation.
    4. A malicious actor can modify the `LaravelExtraIntellisense.phpCommand` setting in the VS Code settings (workspace or user settings) to inject arbitrary PHP code or system commands.
    5. When the extension attempts to gather autocompletion data (e.g., for routes, views, configs), it uses the configured `phpCommand` to execute PHP code.
    6. If the `phpCommand` setting has been tampered with, the injected commands will be executed on the developer's machine with the privileges of the VS Code process.

- Impact:
    - **Arbitrary Code Execution:** Successful exploitation allows an attacker to execute arbitrary PHP code or system commands on the developer's machine.
    - **Data Theft:** An attacker could potentially access and exfiltrate sensitive data, including source code, environment variables, credentials, and other files accessible to the user running VS Code.
    - **System Compromise:** The attacker could install malware, create backdoors, or modify system configurations, leading to a complete compromise of the developer's machine.

- Vulnerability rank: Critical

- Currently implemented mitigations:
    - **Security Note in README:** The README.md file includes a "Security Note" section that warns users about the risks of running the extension and executing their Laravel application automatically. It advises users to be cautious and temporarily disable the extension if they are working with sensitive code in service providers.
    - **No Code-Level Mitigation:** There are no input validation, sanitization, or restrictions implemented in the extension's code to prevent command injection through the `phpCommand` setting.

- Missing mitigations:
    - **Input Validation and Sanitization:** Implement strict validation and sanitization for the `phpCommand` setting to prevent the injection of malicious commands. This could include:
        - Whitelisting allowed commands or command components.
        - Escaping special characters in user-provided input before executing the command.
        - Using secure command execution methods that limit shell interpretation.
    - **Principle of Least Privilege:** Consider if the extension needs to execute arbitrary PHP code at all. If possible, explore alternative methods to gather autocompletion data that do not involve executing user-defined commands.
    - **User Warning within VS Code:** Display a prominent warning message within VS Code when a user modifies the `phpCommand` setting, highlighting the security risks involved and advising caution.

- Preconditions:
    - **Extension Installation:** The victim must have the `Laravel Extra Intellisense` extension installed in VS Code.
    - **Configuration Modification:** The attacker needs to be able to modify the `LaravelExtraIntellisense.phpCommand` setting. This could be achieved through:
        - **Local Access:** If the attacker has local access to the developer's machine, they can directly modify the workspace or user settings.
        - **Workspace Sharing/Collaboration:** If the developer shares their workspace settings (e.g., through Git, shared workspace environments), an attacker with access to these shared settings could inject malicious commands.
        - **Settings Synchronization:** If VS Code settings synchronization is enabled and an attacker compromises the user's settings synchronization account, they could potentially inject malicious settings.

- Source code analysis:
    1. **`helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Reads phpCommand config directly
            let command = commandTemplate.replace("{code}", code); // Vulnerable line: Constructs command by simple string replacement
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Vulnerable line: Executes command without sanitization
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
        - The `runPhp` function is responsible for executing PHP code.
        - It retrieves the `phpCommand` setting directly from the VS Code configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It constructs the final command by simply replacing the `{code}` placeholder in the `commandTemplate` with the provided `code` argument.
        - It uses `child_process.exec` to execute the constructed `command` without any sanitization or validation of the `phpCommand` setting itself.
        - The code performs some escaping on the `code` argument, but this is insufficient to prevent command injection if the `phpCommand` itself is malicious.

    2. **`helpers.ts` - `runLaravel` function:**
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
            if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                var command = // Constructs PHP code to bootstrap Laravel and execute provided 'code'
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    "... " + // Laravel bootstrap code
                    "echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code + // Injects user-provided 'code' into Laravel execution context
                    "echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "...";

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // Calls runPhp to execute the constructed Laravel code
                        .then(function (result: string) { ... });
                });
            }
            return new Promise((resolve, error) => resolve(""));
        }
        ```
        - The `runLaravel` function constructs a PHP script that bootstraps a Laravel application and then executes the provided `code` within the Laravel environment.
        - It calls `runPhp` to execute this constructed PHP script.
        - While `runLaravel` adds Laravel bootstrapping, the actual command execution still relies on the vulnerable `runPhp` function and the `phpCommand` setting.

    3. **Extension components using `runLaravel` and `runPhp`:**
        - Several provider files (e.g., `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, etc.) use `Helpers.runLaravel` or indirectly `Helpers.runPhp` to execute PHP code for data gathering.
        - This means that any of these features could trigger the command injection vulnerability if the `phpCommand` setting is malicious.

- Security test case:
    1. **Prerequisites:**
        - Install the `Laravel Extra Intellisense` extension in VS Code.
        - Open a Laravel project in VS Code (a basic Laravel project is sufficient).
    2. **Modify `phpCommand` setting:**
        - Go to VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS).
        - Search for `LaravelExtraIntellisense.phpCommand`.
        - In "Workspace Settings" or "User Settings", override the default `phpCommand` with a malicious command. For example, to execute a system command and write the output to a file, use:
          ```json
          "laravel-extra-intellisense.phpCommand": "php -r \"{code}; system('whoami > /tmp/vscode-laravel-ext-pwned.txt');\""
          ```
          or to execute arbitrary php code:
          ```json
          "laravel-extra-intellisense.phpCommand": "php -r \"{code}; file_put_contents('/tmp/vscode-laravel-ext-pwned-php.txt', 'pwned');\""
          ```
        - **Note:** The exact path `/tmp/` might need to be adjusted based on your operating system. Choose a path where you have write permissions.
    3. **Trigger extension functionality:**
        - Open any PHP file within your Laravel project.
        - Start typing a Laravel function that triggers autocompletion from the extension, such as `route('`. This will cause the extension to run PHP code to fetch route information.
    4. **Verify command execution:**
        - After triggering the autocompletion, check if the injected command was executed.
        - For the `whoami` example, check if the file `/tmp/vscode-laravel-ext-pwned.txt` was created and contains the output of the `whoami` command.
        - For the `file_put_contents` example, check if the file `/tmp/vscode-laravel-ext-pwned-php.txt` was created and contains the text "pwned".
    5. **Expected result:**
        - The injected system command (`whoami`) or PHP code (`file_put_contents`) should be successfully executed when the extension attempts to gather autocompletion data, demonstrating command injection.
