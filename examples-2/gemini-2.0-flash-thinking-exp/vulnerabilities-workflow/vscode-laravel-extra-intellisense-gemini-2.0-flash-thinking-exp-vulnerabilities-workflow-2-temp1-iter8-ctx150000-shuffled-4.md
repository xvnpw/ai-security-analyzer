### Vulnerability List

#### Vulnerability 1

* Vulnerability Name: Arbitrary Command Execution via `phpCommand` Configuration
* Description:
    1. An attacker persuades a developer to install the "Laravel Extra Intellisense" VSCode extension.
    2. The attacker tricks the developer into configuring the `LaravelExtraIntellisense.phpCommand` setting to a malicious command. For example, a command that downloads and executes a script from a remote server, or simply creates a file to prove code execution, such as: `bash -c "touch /tmp/pwned"`. This could be achieved through social engineering, supply chain attacks, or by compromising documentation/tutorials that recommend specific extension settings.
    3. The extension automatically attempts to gather Laravel application data to provide autocompletion features. This is done periodically or when certain files are opened or edited. This process involves executing PHP code by using the configured `phpCommand`.
    4. The extension executes the malicious command specified in `phpCommand` on the developer's machine as part of its normal operation, specifically when it tries to provide autocompletion features (e.g., when autocompletion for routes, views, configs, etc., is triggered).
* Impact: Arbitrary command execution on the developer's machine. This can have severe consequences, including:
    * **Data exfiltration**: Sensitive data like source code, database credentials, environment variables, and SSH keys can be stolen.
    * **Malware installation**: The attacker can install malware, backdoors, or ransomware on the developer's system.
    * **Lateral movement**: If the developer's machine has access to internal networks or other systems, the attacker can use the compromised machine to pivot and gain further access.
    * **Supply chain compromise**: If the developer's machine is used to build and deploy software, the attacker might be able to inject malicious code into the software supply chain.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * None in the code itself.
    * The `README.md` file includes a "Security Note" that warns users: "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. So if you have any unknown errors in your log make sure the extension not causing it. Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing." This warning is present in the `README.md` but is not a technical mitigation and relies on the user reading and understanding the security implications.
* Missing Mitigations:
    * **Input validation and sanitization for `phpCommand`**: The extension should validate and sanitize the `phpCommand` setting to prevent the execution of arbitrary commands. This could include:
        * **Whitelisting allowed commands**: Restrict `phpCommand` to only allow the `php` executable and specific flags.
        * **Blacklisting dangerous characters and commands**: Filter out characters and command patterns known to be used for command injection, such as shell redirection (`>`, `|`), command chaining (`&&`, `;`), and execution of external commands (`bash`, `sh`, `curl`, `wget`, etc.).
        * **Using secure command execution methods**: Instead of `child_process.exec`, consider using `child_process.spawn` with more controlled argument passing to avoid shell injection vulnerabilities.
    * **Principle of least privilege**: The extension should ideally not require arbitrary command execution at all. If it's unavoidable, it should explore safer alternatives for data retrieval.
    * **Enhanced Security Warning in Settings UI**: Display a more prominent and explicit security warning within the VSCode settings UI when users configure the `phpCommand` setting. This warning should clearly explain the risks of arbitrary code execution and advise users to only use trusted commands.
* Preconditions:
    * The "Laravel Extra Intellisense" extension is installed in VSCode.
    * The developer has a Laravel project opened in VSCode workspace.
    * The developer, either unknowingly or through malicious guidance, configures the `LaravelExtraIntellisense.phpCommand` setting to include a malicious system command.
* Source Code Analysis:
    1. **`src/helpers.ts:runPhp(code: string, description: string|null = null)` function**:
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

                cp.exec(command, // Vulnerable function: child_process.exec
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
        - The `runPhp` function in `helpers.ts` retrieves the `phpCommand` from the extension's configuration.
        - It uses `child_process.exec(command, ...)` to execute the command. The `child_process.exec` function is known to be vulnerable to command injection if the command string is constructed from untrusted input without proper sanitization.
        - The `{code}` placeholder in the configured `phpCommand` is replaced with the PHP code that the extension needs to execute. While the PHP code itself is generated by the extension, the surrounding `phpCommand` is user-configurable and not validated.
        - The code performs minimal escaping of double quotes and dollar signs, but this is insufficient to prevent command injection, especially when users can define the entire command structure.

    2. **`src/helpers.ts:runLaravel(code: string, description: string|null = null)` function**:
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
                        code +
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "}" +
                    "$kernel->terminate($input, $status);" +
                    "exit($status);"

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // Calls runPhp to execute the constructed command
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
        - `runLaravel` constructs a complete PHP script to bootstrap Laravel and execute the provided `$code`.
        - It then calls `runPhp` to actually execute this script. This means any vulnerability in `runPhp` is directly exploitable by `runLaravel` calls.
        - All data fetching operations in the extension (for routes, views, configs, etc.) use `runLaravel`, making them all potential triggers for this vulnerability.

    3. **`src/*Provider.ts` files**:
        - Files like `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, etc., use `Helpers.runLaravel()` to fetch data required for autocompletion. For example, `ConfigProvider.ts` uses:
        ```typescript
        Helpers.runLaravel("echo json_encode(config()->all());", "Configs")
        ```
        - If `phpCommand` is maliciously configured, every time these providers attempt to refresh their data (periodically or on file changes), the malicious command will be executed.

* Security Test Case:
    1. **Prerequisites**:
        * VSCode installed.
        * Laravel Extra Intellisense extension installed and activated.
        * A Laravel project opened in VSCode.
    2. **Steps**:
        * Open VSCode settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        * Search for "LaravelExtraIntellisense: Php Command".
        * Modify the `LaravelExtraIntellisense.phpCommand` setting to the following malicious command: `bash -c "touch /tmp/pwned_laravel_intellisense"`.
        * Open any file in the Laravel project that might trigger autocompletion (e.g., a Blade template or a PHP file where route or view functions are used). Simply opening a file is often enough as the extension proactively fetches data.
        * Wait a few seconds for the extension to initialize and attempt to fetch data.
        * Open a terminal and check if the file `/tmp/pwned_laravel_intellisense` exists by running the command `ls /tmp/pwned_laravel_intellisense`.
    3. **Expected Result**:
        * If the file `/tmp/pwned_laravel_intellisense` exists in the `/tmp/` directory, it confirms that the command injection vulnerability is present and arbitrary commands can be executed via the `phpCommand` configuration.
