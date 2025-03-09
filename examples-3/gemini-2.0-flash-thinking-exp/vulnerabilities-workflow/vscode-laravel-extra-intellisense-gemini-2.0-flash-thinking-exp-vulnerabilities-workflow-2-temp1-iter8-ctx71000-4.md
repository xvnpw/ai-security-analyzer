- Vulnerability Name: Arbitrary PHP Code Execution via `phpCommand` Setting

- Description:
    1. A malicious actor crafts a Laravel project.
    2. The actor creates or modifies the `.vscode/settings.json` file within the project directory.
    3. In this `.vscode/settings.json`, the actor sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious PHP command. For example: `"LaravelExtraIntellisense.phpCommand": "php -r \\"system($_GET['cmd']);\\""`. This command allows executing arbitrary system commands through the `cmd` GET parameter.
    4. The actor distributes or convinces a developer to open this Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension initializes or periodically refreshes its autocompletion data (e.g., routes, views, configs), it executes PHP code by calling the `runLaravel` function in `helpers.ts`.
    6. The `runLaravel` function, in turn, uses the configured `LaravelExtraIntellisense.phpCommand` setting, which is now under the attacker's control, to execute PHP commands.
    7. Because the `phpCommand` is set to a malicious command, arbitrary PHP code (in this example, code that executes system commands based on the `cmd` GET parameter) is executed on the developer's machine with the privileges of the VSCode process.
    8. The attacker can then trigger arbitrary code execution by making requests that would cause the extension to run PHP code, effectively running the malicious payload defined in `phpCommand`.

- Impact:
    - **Critical**: Successful exploitation allows the attacker to execute arbitrary PHP code on the developer's machine. This can lead to:
        - **पूर्ण system compromise**: The attacker can gain complete control over the developer's machine, potentially stealing sensitive data, installing malware, or using the machine as a point of further attack.
        - **Data breach**: Access to source code, credentials, and other sensitive project-related data stored on the developer's machine.
        - **Supply chain attack**: If the compromised developer commits and pushes changes, the malicious code or its effects could propagate to the project repository and potentially to other developers or production environments.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - The `README.md` file includes a "Security Note" section that warns users about the risks of executing Laravel application code automatically and suggests temporarily disabling the extension when working with sensitive code in service providers. This is a documentation-based mitigation, not a technical one, and relies on the user understanding and following the advice.

- Missing Mitigations:
    - **Input sanitization/validation**: The extension does not validate or sanitize the `LaravelExtraIntellisense.phpCommand` setting. It should check if the command is safe or at least warn the user about the potential risks of modifying it from untrusted sources.
    - **Secure default command**: While the default `phpCommand` (`php -r "{code}"`) is relatively safe on its own, the extension could explore safer ways to execute necessary PHP code, perhaps by using specific PHP functions or a sandboxed environment.
    - **Workspace trust**: VSCode's workspace trust feature could be leveraged to warn users when opening workspaces with potentially malicious settings. The extension could provide guidance on how workspace trust interacts with its settings.
    - **Principle of least privilege**: The extension executes PHP code with the privileges of the VSCode process. Exploring ways to reduce the privileges required for PHP code execution could limit the impact of this vulnerability.

- Preconditions:
    - The victim developer must have the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim developer must open a Laravel project that contains a malicious `.vscode/settings.json` file.
    - The attacker needs to be able to deliver or convince the developer to open the malicious Laravel project.

- Source Code Analysis:
    1. **`helpers.ts` - `runPhp` function:**
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
        - This function retrieves the `phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It then uses `commandTemplate.replace("{code}", code)` to construct the final command to be executed, directly embedding the provided `code` into the user-defined command template.
        - `cp.exec(command, ...)` executes the constructed command without any validation or sanitization of the `command` variable, which can be fully controlled by the `phpCommand` setting in `.vscode/settings.json`.

    2. **`helpers.ts` - `runLaravel` function:**
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
                    self.runPhp(command, description)
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
        - This function constructs a standard Laravel bootstrapping script and embeds the provided `code` argument directly into it.
        - It then calls `runPhp` with this script, effectively executing the user-provided `code` within a Laravel environment using the potentially malicious `phpCommand`.

- Security Test Case:
    1. **Setup:**
        - Create a new empty directory for a Laravel project (no need to actually bootstrap Laravel for this test).
        - Create a `.vscode` directory inside the project directory.
        - Create a `settings.json` file inside `.vscode` with the following content:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"whoami > output.txt\");'"
          }
          ```
        - Ensure you have the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    2. **Execution:**
        - Open the newly created project directory in VSCode.
        - Wait for a short period (or trigger any autocompletion feature of the extension) to ensure the extension executes PHP code.
    3. **Verification:**
        - Check the project directory for a file named `output.txt`.
        - If `output.txt` exists and contains the output of the `whoami` command (your username), then the vulnerability is confirmed. This demonstrates that arbitrary system commands can be executed via the malicious `phpCommand` setting.

This test case proves that by manipulating the `LaravelExtraIntellisense.phpCommand` setting within the `.vscode/settings.json` file of a Laravel project, an attacker can achieve arbitrary command execution on a developer's machine when the project is opened in VSCode with the extension installed.
