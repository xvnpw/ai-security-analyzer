- Vulnerability name: Arbitrary PHP Code Execution via Misconfigured `phpCommand`
- Description:
    1. The "Laravel Extra Intellisense" VSCode extension uses the `phpCommand` setting to execute PHP code in the user's workspace to provide Laravel-specific autocompletion features.
    2. Users can configure the `phpCommand` setting in the VSCode settings panel, allowing them to customize the command used to execute PHP.
    3. If a user intentionally or unintentionally configures `phpCommand` to execute a malicious PHP script or a command that introduces security risks (e.g., by pointing to an untrusted PHP binary or a script that performs unintended actions), the extension will use this command.
    4. When the extension needs to fetch data for autocompletion (e.g., route lists, view names, configurations), it dynamically generates PHP code and executes it using the user-defined `phpCommand`.
    5. If `phpCommand` is set to a malicious script or command, this will lead to the execution of arbitrary PHP code within the user's development environment, whenever the extension attempts to gather autocompletion data.
- Impact:
    - Successful exploitation allows for arbitrary PHP code execution within the user's development environment.
    - This can lead to various malicious outcomes, including:
        - Unauthorized access to or modification of project files.
        - Execution of system commands on the user's machine with the permissions of the VSCode process.
        - Exfiltration of sensitive information, such as environment variables, source code, or database credentials, if accessible by the malicious script or command.
        - Potential compromise of the user's development environment and potentially the wider system, depending on the nature of the malicious code and system permissions.
- Vulnerability rank: High
- Currently implemented mitigations:
    - A "Security Note" in the `README.md` file advises users to "read the [security note](#security-note) and [how to configure](#sample-config-to-use-docker) before using the extension."
    - The security note warns that "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete." and advises users to "make sure the extension not causing it" if they see "unknown errors in your log". It also suggests to "disable the extension temporarily to prevent unwanted application executing" when writing "sensitive code in your service providers".
    - Sample configurations for Docker and Laravel Sail are provided in `README.md` to encourage using isolated environments, although these are presented as configuration examples rather than security mitigations.
- Missing mitigations:
    - Input validation or sanitization of the `phpCommand` setting. While fully preventing malicious commands might be challenging, basic checks for obviously dangerous patterns or path traversals could be implemented.
    - Sandboxing or isolation of the PHP execution environment. This is complex for a VSCode extension but could involve using containerization or other isolation techniques to limit the impact of a compromised `phpCommand`.
    - More prominent and in-product security warnings. Displaying a clear warning within VSCode when the `phpCommand` setting is modified or when the extension detects a potentially risky configuration could improve user awareness.
    - Enhanced documentation with more detailed security guidance and best practices for configuring `phpCommand` securely. This should include explicit warnings about the risks of using untrusted commands and recommendations for using isolated environments like Docker.
- Preconditions:
    - The "Laravel Extra Intellisense" extension must be installed and activated in VSCode.
    - A Laravel project must be opened in the VSCode workspace.
    - The user must have the ability to modify VSCode settings and must misconfigure the `LaravelExtraIntellisense.phpCommand` setting. This misconfiguration could be unintentional (e.g., misunderstanding the setting) or intentional (e.g., a malicious user trying to exploit the extension or testing its security).
    - The user must trigger the extension to perform autocompletion, which causes the extension to execute PHP code using the misconfigured `phpCommand`. This can happen automatically when opening or editing PHP or Blade files within a Laravel project.
- Source code analysis:
    1. File: `src/helpers.ts`
        - Function: `runPhp(code: string, description: string|null = null)`
            ```typescript
            static async runPhp(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/\"/g, "\\\"");
                // ... platform specific escaping ...
                let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
                let command = commandTemplate.replace("{code}", code);
                let out = new Promise<string>(function (resolve, error) {
                    // ... logging ...
                    cp.exec(command,
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) {
                            // ... error handling and resolve ...
                        }
                    );
                });
                return out;
            }
            ```
            - The `runPhp` function retrieves the `phpCommand` from VSCode configuration without any validation or sanitization.
            - It uses `child_process.exec(command, ...)` to execute the command, where `command` is directly constructed by replacing `{code}` in the user-provided `phpCommand` template.
            - There is no mechanism to prevent the user from setting a malicious command.
        - Function: `runLaravel(code: string, description: string|null = null)`
            ```typescript
            static runLaravel(code: string, description: string|null = null) : Promise<string> {
                // ... Laravel bootstrap code ...
                var command =
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    // ... service provider registration to prevent log errors ...
                    "$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);" +
                    // ... command execution and output capture ...
                    "if ($status == 0) {" +
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code + // User-provided code executed here within Laravel context
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "}" +
                    "$kernel->terminate($input, $status);" +
                    "exit($status);"

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // Calls runPhp with the constructed command
                        .then(function (result: string) {
                            // ... output parsing ...
                        })
                        .catch(function (e : Error) {
                            error(e);
                        });
                });
            }
            ```
            - `runLaravel` constructs a PHP script that bootstraps a Laravel application and includes the user-provided `code` within the Laravel execution context.
            - It then calls `runPhp` to execute this entire script using the potentially malicious `phpCommand`.
            - This means that even if the extension's generated code is safe, a malicious `phpCommand` can still compromise the environment.

    2. Provider files (`src/*Provider.ts`):
        - Files like `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, etc., use `Helpers.runLaravel()` to execute PHP code to retrieve data for autocompletion.
        - For example, in `src/ConfigProvider.ts`:
            ```typescript
            loadConfigs() {
                try {
                    var self = this;
                    Helpers.runLaravel("echo json_encode(config()->all());", "Configs") // Calls runLaravel to get config data
                        .then(function (result) {
                            var configs = JSON.parse(result);
                            self.configs = self.getConfigs(configs);
                        });
                } catch (exception) {
                    console.error(exception);
                }
            }
            ```
        - These providers depend on `runLaravel` and indirectly `runPhp`, making them vulnerable if `phpCommand` is misconfigured.

- Security test case:
    1. Precondition: Ensure you have a Laravel project opened in VSCode and the "Laravel Extra Intellisense" extension is installed and activated.
    2. Create a file named `malicious.php` in your Laravel project's root directory with the following content:
        ```php
        <?php
        file_put_contents('pwned.txt', 'You have been pwned by Laravel Extra Intellisense!');
        ```
    3. Open VSCode settings (File > Preferences > Settings > Settings or Code > Settings > Settings).
    4. Search for "LaravelExtraIntellisense: Php Command".
    5. Modify the `phpCommand` setting to execute the malicious PHP script you created:
        ```json
        "LaravelExtraIntellisense.phpCommand": "php ${workspaceFolder}/malicious.php"
        ```
    6. Open any PHP file within your Laravel project (e.g., a controller or a route file).
    7. In the PHP file, start typing `route('` or `config('` to trigger autocompletion. This will cause the extension to execute PHP code.
    8. After triggering autocompletion, check your Laravel project's root directory. You should find a new file named `pwned.txt` with the content "You have been pwned by Laravel Extra Intellisense!". This confirms that the malicious PHP script specified in `phpCommand` was executed by the extension.
