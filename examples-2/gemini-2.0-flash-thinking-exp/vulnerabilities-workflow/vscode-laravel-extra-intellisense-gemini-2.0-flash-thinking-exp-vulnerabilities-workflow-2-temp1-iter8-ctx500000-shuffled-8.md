### Vulnerability List

- Vulnerability Name: Arbitrary PHP Code Execution via Malicious Project Files
- Description:
    1. A developer installs the "Laravel Extra Intellisense" extension in Visual Studio Code.
    2. An attacker crafts a malicious Laravel project.
    3. The attacker embeds malicious PHP code within the Laravel project files, such as in route definitions, view files, configuration files, models, or service providers. This code could be designed to execute arbitrary commands, read sensitive files, or perform other malicious actions.
    4. The attacker tricks the developer into opening the malicious Laravel project in VSCode.
    5. Upon opening the project, the "Laravel Extra Intellisense" extension automatically activates and attempts to gather data for autocompletion.
    6. To gather this data, the extension executes PHP code using the `runLaravel` function in `helpers.ts`, which boots the Laravel application.
    7. As the Laravel application boots, the embedded malicious PHP code within the project files is executed by the PHP interpreter as part of the application's normal execution flow.
    8. This results in arbitrary PHP code execution on the developer's machine, initiated by simply opening a malicious project in VSCode with the extension installed.
- Impact: Arbitrary code execution on the developer's machine. This can lead to:
    - Full control over the developer's workstation.
    - Stealing of sensitive data, including code, credentials, and personal information.
    - Installation of malware, backdoors, or ransomware.
    - Compromise of development environment and potentially further systems accessible from it.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Security Note in `README.md`: The README.md includes a "Security Note" that warns users about the extension running their Laravel application and suggests disabling the extension if sensitive code is in service providers.
    - Location: `README.md` file in the project root.
    - Effectiveness: This mitigation is weak as it relies on the developer understanding the risk and manually disabling the extension, which is unlikely for most users. It does not prevent the vulnerability, only warns about potential risks.
- Missing Mitigations:
    - Input sanitization: The extension lacks any sanitization or validation of the Laravel project files before executing them.
    - Sandboxing: The PHP code execution is not sandboxed or isolated, allowing it full access to the developer's system resources and file system.
    - User confirmation: There is no user confirmation or warning before the extension executes PHP code from the opened project, especially for new or untrusted projects.
    - Static analysis: Implementing static analysis to detect potentially malicious code within project files before execution.
- Preconditions:
    - The "Laravel Extra Intellisense" extension is installed in VSCode.
    - A developer opens a malicious Laravel project in VSCode.
    - The malicious Laravel project contains embedded PHP code that gets executed when the Laravel application is booted or when project files are parsed.
- Source Code Analysis:
    - `src/helpers.ts`: The `runLaravel` function is responsible for executing the Laravel application.
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
            if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                var command =
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    "class VscodeLaravelExtraIntellisenseProvider extends \\\\Illuminate\\\\Support\\\\ServiceProvider" +
                    "{" +
                    "   public function register() {}" +
                    "	public function boot()" +
                    "	{" +
                    "       if (method_exists($this->app['log'], 'setHandlers')) {" +
                    "			$this->app['log']->setHandlers([new \\\\Monolog\\\\Handler\\\\ProcessHandler()]);" +
                    "		}" +
                    "	}" +
                    "}" +
                    "$app->register(new VscodeLaravelExtraIntellisenseProvider($app));" +
                    "$kernel = $app->make(Illuminate\\\\Contracts\\\\Console\\\\Kernel::class);" +

                    "$status = $kernel->handle(" +
                        "$input = new Symfony\\\\Component\\\\Console\\\\Input\\\\ArgvInput," +
                        "new Symfony\\\\Component\\\\Console\\\\Output\\\\ConsoleOutput" +
                    ");" +
                    "if ($status == 0) {" +
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code +
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "}" +
                    "$kernel->terminate($input, $status);" +
                    "exit($status);"

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description)
                        .then(function (result: string) {
                            var out : string | null | RegExpExecArray = result;
                            out = /___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___(.*)___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___/g.exec(out);
                            if (out) {
                                resolve(out[1]);
                            } else {
                                error("PARSE ERROR: " + result);

                                Helpers.outputChannel?.error("Laravel Extra Intellisense Parse Error:\n " + (description ?? '') + '\\n\\n' + result);
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
        - The code directly executes `require_once` on `vendor/autoload.php` and `bootstrap/app.php` from the opened project. This bootstraps the entire Laravel application.
        - Any code present in service providers, routes, configuration, or other parts of the Laravel application will be executed as part of this bootstrapping process.
        - If a malicious project is opened, and these files are tampered with to include malicious PHP code, that code will be executed.
    - Many providers (e.g., `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, `EloquentProvider.ts`, `TranslationProvider.ts`, `BladeProvider.ts`) call `Helpers.runLaravel` to fetch data for autocompletion, thus triggering the application bootstrap and potential malicious code execution.

        ```typescript
    // Example from src/RouteProvider.ts
    loadRoutes() {
        if (vscode.workspace.workspaceFolders instanceof Array && vscode.workspace.workspaceFolders.length > 0) {
            try {
                var self = this;
                Helpers.runLaravel(
                        "echo json_encode(array_map(function ($route) {" +
                        "    return ['method' => implode('|', array_filter($route->methods(), function ($method) {" +
                        "        return $method != 'HEAD';" +
                        "    })), 'uri' => $route->uri(), 'name' => $route->getName(), 'action' => str_replace('App\\\\Http\\\\Controllers\\\\', '', $route->getActionName()), 'parameters' => $route->parameterNames()];" +
                        "}, app('router')->getRoutes()->getRoutes()));",
                        "HTTP Routes"
                    )
                    .then(function (result) {
                        var routes = JSON.parse(result);
                        routes = routes.filter((route: any) => route !== 'null');
                        self.routes = routes;
                    });
            } catch (exception) {
                console.error(exception);
            }
        }
    }
    ```
- Security Test Case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a file named `routes/web.php` with the following content:
        ```php
        <?php

        use Illuminate\Support\Facades\Route;

        Route::get('/', function () {
            file_put_contents(__DIR__ . '/../../../pwned.txt', 'You have been pwned by Laravel Extra Intellisense!');
            return view('welcome');
        });
        ```
    3. In the root of `malicious-laravel-project`, create minimal `composer.json` and `artisan` files to simulate a Laravel project (or copy from a real Laravel project and modify `routes/web.php`). Ensure `vendor/autoload.php` and `bootstrap/app.php` exist or are simulated to be found by the extension. A full Laravel installation is not strictly required, just enough files to satisfy the extension's checks.
    4. Open Visual Studio Code.
    5. Install the "Laravel Extra Intellisense" extension if not already installed.
    6. Open the `malicious-laravel-project` folder in VSCode.
    7. Wait for the extension to activate and gather data (this might take a few seconds).
    8. Check the `malicious-laravel-project` directory (or its parent directories, depending on where `__DIR__` resolves in the executed context).
    9. Observe that a file named `pwned.txt` has been created with the content "You have been pwned by Laravel Extra Intellisense!".
    10. This confirms that arbitrary PHP code (in this case, writing to a file) has been executed simply by opening the malicious project, demonstrating the vulnerability.

- Vulnerability Name: Command Injection via `phpCommand` Configuration
- Description:
    1. A developer installs the "Laravel Extra Intellisense" extension in Visual Studio Code.
    2. An attacker attempts to control or influence the `LaravelExtraIntellisense.phpCommand` setting in the developer's VSCode configuration. This could be achieved by:
        - Social engineering the developer to manually change the setting.
        - Providing a malicious workspace configuration file (`.vscode/settings.json`) within a project, and tricking the developer into opening this project.
    3. The attacker injects malicious commands into the `phpCommand` setting. For example, they might change it to `php -r "{code}"; malicious_command`.
    4. When the "Laravel Extra Intellisense" extension needs to execute PHP code (e.g., to gather autocompletion data), it uses the `runPhp` function in `helpers.ts`.
    5. The `runPhp` function uses the configured `phpCommand` to execute the PHP code using `child_process.exec`.
    6. Due to insufficient sanitization of the `phpCommand` setting, the injected malicious commands are executed by the system shell along with the intended PHP command.
    7. This results in arbitrary command execution on the developer's machine, controlled by the attacker through the manipulated `phpCommand` setting.
- Impact: Arbitrary command execution on the developer's machine. This can lead to:
    - Full control over the developer's workstation.
    - Stealing of sensitive data, including code, credentials, and personal information.
    - Installation of malware, backdoors, or ransomware.
    - Compromise of development environment and potentially further systems accessible from it.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The extension does not implement any specific mitigations against command injection in the `phpCommand` setting. The README.md provides configuration examples but no security warnings about modifying this setting.
- Missing Mitigations:
    - Input sanitization: The extension should sanitize the `phpCommand` setting to remove or escape potentially harmful characters that could be used for command injection.
    - Validation: Validate the `phpCommand` setting to ensure it conforms to expected formats and does not contain malicious patterns.
    - Restrict characters: Limit the set of allowed characters in the `phpCommand` setting to prevent injection attempts.
    - Warning message: Display a clear warning message to users when they modify the `phpCommand` setting, informing them about the potential security risks of using untrusted or modified commands.
- Preconditions:
    - The "Laravel Extra Intellisense" extension is installed in VSCode.
    - An attacker can influence or modify the `LaravelExtraIntellisense.phpCommand` setting in the developer's VSCode configuration, for example by providing a malicious `.vscode/settings.json` file in a project.
- Source Code Analysis:
    - `src/helpers.ts`: The `runPhp` function directly uses the `phpCommand` configuration setting in `child_process.exec`.
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
                            Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\\n\\n' + errorOutput);
                            Helpers.showErrorPopup();
                            error(errorOutput);
                        }
                    }
                );
            });
            return out;
        }
        ```
        - `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` retrieves the user-configurable `phpCommand`.
        - `let command = commandTemplate.replace("{code}", code);` substitutes `{code}` with the PHP code to be executed.
        - `cp.exec(command, ...)` executes the constructed command string directly using `child_process.exec`.
        - There is no sanitization of `commandTemplate` before it is used in `cp.exec`, making it vulnerable to command injection if an attacker can control the `phpCommand` setting.

- Security Test Case:
    1. Create a new directory named `command-injection-project`.
    2. Inside `command-injection-project`, create a `.vscode` directory and within it, a `settings.json` file.
    3. In `settings.json`, add the following configuration to set a malicious `phpCommand`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; calc.exe"
        }
        ```
    4. Open Visual Studio Code.
    5. Install the "Laravel Extra Intellisense" extension if not already installed.
    6. Open the `command-injection-project` folder in VSCode.
    7. Wait for the extension to activate and attempt to gather data (this might take a few seconds). The extension will try to fetch routes, views, configs etc., which will trigger the execution of `runPhp`.
    8. Observe if the `calc.exe` application (or calculator on your OS) is launched.
    9. If `calc.exe` is launched, it indicates that the command injection vulnerability is successfully exploited through the malicious `phpCommand` setting. The `calc.exe` command was executed after the intended PHP command due to the injected command separator `;`.
