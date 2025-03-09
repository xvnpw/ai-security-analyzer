* Vulnerability name: Command Injection via `phpCommand` configuration
* Description:
    1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code. This setting can be modified in the workspace settings (`.vscode/settings.json`).
    2. The extension uses this `phpCommand` setting in `src/helpers.ts` to execute arbitrary PHP code provided by the extension itself to gather Laravel project information for autocompletion features (routes, views, configs, etc.).
    3. The `runPhp` function in `src/helpers.ts` directly uses `child_process.exec` to execute the command defined in `phpCommand`, without any sanitization of the `phpCommand` setting or the PHP code being executed.
    4. A threat actor can create a malicious Laravel project and include a `.vscode/settings.json` file in the project root that modifies the `LaravelExtraIntellisense.phpCommand` setting to inject malicious commands.
    5. When a victim opens this malicious project in VSCode with the "Laravel Extra Intellisense" extension installed, the extension will attempt to gather project data.
    6. During this data gathering process, the extension will execute the user-configured `phpCommand`. Because the threat actor has modified this setting, the malicious commands injected by the threat actor will be executed on the victim's machine with the privileges of the VSCode process.

* Impact:
    - Remote Code Execution (RCE) on the victim's machine.
    - A threat actor can execute arbitrary commands on the developer's machine when they open a malicious Laravel project in VSCode.
    - This can lead to complete compromise of the developer's workstation, including data theft, installation of malware, and further attacks on internal networks if the developer's machine is connected to one.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    - None in the code itself.
    - The README.md contains a "Security Note" warning users: "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. So if you have any unknown errors in your log make sure the extension not causing it. Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing."
    - This security note is insufficient as it relies on the user to understand the risk and manually mitigate it, rather than implementing secure coding practices in the extension itself. It's more of a disclaimer than a real mitigation.

* Missing mitigations:
    - Input sanitization of the `LaravelExtraIntellisense.phpCommand` setting. The extension should validate and sanitize the user-provided command to prevent injection of arbitrary commands. Ideally, the extension should not allow users to configure the entire command, but only parameters, or use a safer method than `child_process.exec` if command customization is required.
    - Sandboxing or isolation of the command execution environment. Running the PHP commands in a sandboxed environment could limit the impact of command injection vulnerabilities.
    - Principle of least privilege. The extension should ideally run with the minimum necessary privileges.

* Preconditions:
    - Victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - Victim opens a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file.
    - The malicious `.vscode/settings.json` file must modify the `LaravelExtraIntellisense.phpCommand` setting to include malicious commands.

* Source code analysis:
    1. **`src/helpers.ts` - `runPhp` function:**
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable setting is retrieved here
        let command = commandTemplate.replace("{code}", code); // User controlled setting is directly used to construct command
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Command is executed without sanitization
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
    - The code retrieves the `phpCommand` configuration from VSCode settings.
    - It then constructs the command string by simply replacing `{code}` in the `phpCommand` template with the provided `$code`.
    - `child_process.exec` is used to execute the constructed command.
    - **Crucially, there is no sanitization or validation of either the `phpCommand` setting or the `$code` variable before executing the command.** This allows for command injection if a malicious user can control the `phpCommand` setting.

    2. **`src/helpers.ts` - `runLaravel` function:**
    ```typescript
    static runLaravel(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
        if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
            var command =
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
                    code + // PHP code to be executed is inserted here
                "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                "}" +
                "$kernel->terminate($input, $status);" +
                "exit($status);"

            var self = this;

            return new Promise(function (resolve, error) {
                self.runPhp(command, description) // Calls runPhp to execute the generated PHP code
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
    - `runLaravel` generates a PHP script that boots the Laravel application and then executes the provided `$code` within the Laravel environment.
    - It then calls `runPhp` to execute this generated PHP script.
    - If `phpCommand` is maliciously configured, `runPhp` will execute the malicious command along with the intended PHP script, leading to command injection.

* Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a file named `.vscode` and inside it create `settings.json`.
    3. In `.vscode/settings.json`, add the following configuration to override the `phpCommand` setting with a malicious command. This example will create a file named `pwned.txt` on the victim's system root:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '$cmd = \\\"{code}\\\"; shell_exec(\\\"touch /tmp/pwned.txt && php -r \\\"\\\" . str_replace(\\\"{code}\\\", $cmd, \\\"eval(base64_decode(\\\\\".base64_encode(\\\"{code}\\\")).\\\\"));\\\"\\\");'"
    }
    ```
    *(Explanation of the malicious command: This command is designed to first execute `touch /tmp/pwned.txt` to demonstrate command execution, and then to execute the original PHP code intended by the extension.  It uses `shell_exec` to execute system commands and then attempts to re-execute the original PHP code to avoid breaking the extension's functionality completely and making the attack less obvious. The complex escaping and base64 encoding are used to handle potential issues with quotes and special characters within the command string.)*

    4.  Initialize a basic Laravel project inside `malicious-laravel-project` (you can use `laravel new .` command if you have Laravel installer, or manually create basic files). It does not need to be a fully functional Laravel application for this test case to work, just enough to trigger the extension's data gathering. A basic `artisan` file and `composer.json` is sufficient.
    5.  Open the `malicious-laravel-project` directory in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    6.  Observe the system. After a short delay (or upon opening a PHP or Blade file), the command injected via `phpCommand` should execute. In this test case, check if the file `/tmp/pwned.txt` has been created. If the file exists, it confirms successful command injection and RCE.
    7.  **Important:** For testing on Windows, you would need to modify the command to a Windows-compatible command, e.g.,  `"cmd /c echo pwned > pwned.txt & php -r \\\"{code}\\\""` and check for `pwned.txt` in the project root or a writable directory. For cross-platform testing, a safer and more portable test command would be to use `php -r 'file_put_contents("pwned.txt", "pwned");'` and check for `pwned.txt` in the project root.

This vulnerability allows for critical impact due to the possibility of arbitrary code execution. It is ranked as critical because it is easily exploitable, requires minimal user interaction (just opening a malicious project), and can lead to full system compromise. The lack of input sanitization on a user-configurable command execution path is a severe security flaw.
