### Vulnerability List:

- Vulnerability Name: Arbitrary Code Execution via `phpCommand`

- Description:
    1. A developer installs the "Laravel Extra Intellisense" VSCode extension.
    2. The extension requires a PHP command to be configured in the settings (`LaravelExtraIntellisense.phpCommand`) to interact with the Laravel project. This command is used to execute PHP scripts to gather information about routes, views, configurations, etc., for autocompletion features.
    3. A malicious actor tricks the developer into using a malicious PHP command in the extension's settings. This could be achieved through social engineering, by providing a compromised workspace configuration file (e.g., through a Git repository), or by other means of influencing the developer's VSCode settings.
    4. When the extension attempts to provide autocompletion, it executes the configured `phpCommand`, replacing the `{code}` placeholder with PHP code generated by the extension.
    5. If the `phpCommand` is malicious, it will execute arbitrary commands on the developer's machine, in addition to the intended PHP code.

- Impact:
    - Arbitrary code execution on the developer's machine with the privileges of the VSCode process.
    - Complete compromise of the developer's workstation.
    - Potential data theft, including source code, credentials, and other sensitive information accessible on the developer's machine.
    - Installation of malware or backdoors on the developer's system.
    - Lateral movement within the developer's network if the workstation is part of a larger network.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - Security Note in README.md: The README.md file includes a "Security Note" that warns users about the execution of Laravel application code and advises caution regarding sensitive code in service providers. However, this is only a documentation-level mitigation and does not prevent the vulnerability.

- Missing Mitigations:
    - Input validation and sanitization: The extension lacks any validation or sanitization of the `phpCommand` setting provided by the user. It should validate that the command is a legitimate PHP command and prevent the injection of arbitrary shell commands.
    - Sandboxing or isolation: The execution of the PHP code should be sandboxed or isolated to prevent it from accessing or modifying system resources outside of a defined scope. However, given the nature of VSCode extensions and the need to interact with the project files, full sandboxing might be complex.
    - Principle of least privilege: The extension should ideally operate with the minimum necessary privileges. However, this is inherent to VSCode extension architecture where extensions run with the same privileges as the VSCode editor.
    - User awareness and secure defaults: While the extension warns about security, it could provide more secure default configurations or guide users towards safer setups, like using Docker or similar containerization to isolate the execution environment.

- Preconditions:
    - The "Laravel Extra Intellisense" VSCode extension is installed and activated.
    - The developer has a Laravel project opened in VSCode.
    - The developer is either tricked into manually configuring a malicious `phpCommand` or opens a workspace with a malicious `.vscode/settings.json` file that sets a malicious `phpCommand`.

- Source Code Analysis:
    1. **`helpers.ts` - `runPhp` function**:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // [CRITICAL]: User-controlled phpCommand is directly used here
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // [CRITICAL]: Executing the command without sanitization
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
        - The `runPhp` function retrieves the `phpCommand` from the configuration.
        - It replaces the `{code}` placeholder with the PHP code to be executed.
        - **Critically**, it directly executes the resulting `command` using `cp.exec` without any sanitization or validation of the `phpCommand` itself. This allows for arbitrary command injection if the user provides a malicious `phpCommand`.

    2. **`helpers.ts` - `runLaravel` function**:
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
            if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                var command = // [INFO]: Constructing the PHP command to execute Laravel code
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    "class VscodeLaravelExtraIntellisenseProvider extends \\Illuminate\\Support\\ServiceProvider" +
                    "{" +
                    "   public function register() {}" +
                    "	public function boot()" +
                    "	{" +
                    "       if (method_exists($this->app['log'], 'setHandlers')) {" +
                    "			$this->app['log']->setHandlers([new \\Monolog\\Handler\\ProcessHandler()]);" +
                    "		}" +
                    "	}" +
                    "}" +
                    "$app->register(new VscodeLaravelExtraIntellisenseProvider($app));" +
                    "$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);" +

                    "$status = $kernel->handle(" +
                        "$input = new Symfony\\Component\\Console\\Input\\ArgvInput," +
                        "new Symfony\\Component\\Console\\Output\\ConsoleOutput" +
                    ");" +
                    "if ($status == 0) {" +
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code + // [INFO]: PHP code generated by the extension
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "}" +
                    "$kernel->terminate($input, $status);" +
                    "exit($status);"

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // [CALL]: Calls runPhp to execute the constructed command
                        .then(function (result: string) {
                            var out : string | null | RegExpExecArray = result;
                            out = /___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___(.*)___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___/g.exec(out);
                            if (out) {
                                resolve(out[1]);
                            } else {
                                error("PARSE ERROR: " + result);

                                Helpers.outputChannel?.error("Laravel Extra Intellisense Parse Error:\n " + (description ?? '') + '\n\n' + result);
                                Helpers.showErrorPopup();
                            }
                        })
                        .catch(function (e : Error) {
                            error(e);
                        });
                });
            }
            return new Promise((resolve, error) => resolve(""));
        }
        ```
        - `runLaravel` constructs a PHP script that boots the Laravel application and then executes the provided `$code`.
        - It then calls `runPhp` to execute this constructed command.
        - The vulnerability stems from `runPhp`'s unsanitized execution of the user-configured `phpCommand`.

    3. **Provider Files (e.g., `RouteProvider.ts`, `ViewProvider.ts`)**:
        - These files use `Helpers.runLaravel()` to fetch data from the Laravel application. For example, `RouteProvider.ts` uses it to get route information:
        ```typescript
        Helpers.runLaravel(
            "echo json_encode(array_map(function ($route) {" +
            "    return ['method' => implode('|', array_filter($route->methods(), function ($method) {" +
            "        return $method != 'HEAD';" +
            "    })), 'uri' => $route->uri(), 'name' => $route->getName(), 'action' => str_replace('App\\\\Http\\\\Controllers\\\\', '', $route->getActionName()), 'parameters' => $route->parameterNames()];" +
            "}, app('router')->getRoutes()->getRoutes()));",
            "HTTP Routes"
        )
        ```
        - This demonstrates how the extension relies on executing PHP code via `runLaravel` and consequently `runPhp`, making it vulnerable if a malicious `phpCommand` is configured.

- Security Test Case:
    1. **Prerequisites**:
        - VSCode with the "Laravel Extra Intellisense" extension installed.
        - A Laravel project opened in VSCode (a basic Laravel project is sufficient).
    2. **Malicious Workspace Configuration**:
        - Create a `.vscode` directory at the root of your Laravel project if it doesn't exist.
        - Inside the `.vscode` directory, create a `settings.json` file with the following content:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "echo '; touch /tmp/pwned; '; php -r \"{code}\""
        }
        ```
        - This malicious `phpCommand` first executes `touch /tmp/pwned` (which creates an empty file named `pwned` in the `/tmp` directory on Linux/macOS systems) and then executes the original PHP code provided by the extension. For Windows, you could use `echo '; type nul > C:\\Windows\\Temp\\pwned; '; php -r "{code}"`
    3. **Trigger Extension Activity**:
        - Open any PHP file within the Laravel project (e.g., a controller, route file, or blade template).
        - Start typing code that triggers the autocompletion features of the extension, such as `route('`, `view('`, `config('`, etc. This will cause the extension to execute the configured `phpCommand`.
    4. **Verify Code Execution**:
        - Check if the file `/tmp/pwned` (or `C:\\Windows\\Temp\\pwned` on Windows) has been created.
        - If the file exists, it confirms that the arbitrary command `touch /tmp/pwned` from the malicious `phpCommand` was executed, demonstrating arbitrary code execution vulnerability.

This test case proves that a malicious `phpCommand` can lead to arbitrary code execution when the extension attempts to use it.
