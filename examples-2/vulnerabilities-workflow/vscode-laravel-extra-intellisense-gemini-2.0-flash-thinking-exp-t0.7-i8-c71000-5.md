## Vulnerability List

### 1. Command Injection vulnerability in `phpCommand` setting

*   **Vulnerability Name:** Command Injection in `phpCommand` setting
*   **Description:**
    The `LaravelExtraIntellisense.phpCommand` setting allows users to configure the command used to execute PHP code. This setting is directly used in `child_process.exec` in `helpers.ts` without sufficient sanitization. A malicious user who can convince a victim to open a workspace containing a crafted `.vscode/settings.json` file (or through other VSCode settings manipulation mechanisms) can inject arbitrary commands into the `phpCommand`. When the extension executes PHP code using `Helpers.runPhp` or `Helpers.runLaravel`, the injected commands will be executed by the system.
    Steps to trigger the vulnerability:
    1.  Attacker creates a malicious Laravel repository.
    2.  Attacker crafts a `.vscode/settings.json` file within the malicious repository that sets `LaravelExtraIntellisense.phpCommand` to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "bash -c \\"touch /tmp/pwned\\""`.
    3.  Victim clones the malicious repository and opens it in VSCode with the Laravel Extra Intellisense extension installed.
    4.  The extension attempts to gather Laravel project information by executing PHP code using `Helpers.runLaravel` or `Helpers.runPhp`.
    5.  The configured `phpCommand` is executed by `child_process.exec`, including the injected malicious command (`bash -c "touch /tmp/pwned"` in the example).
    6.  The malicious command is executed on the victim's system. In the example, this creates a file `/tmp/pwned`.
*   **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further propagation of attacks.
*   **Vulnerability Rank:** critical
*   **Currently implemented mitigations:**
    No input sanitization or validation is performed on the `phpCommand` setting before passing it to `child_process.exec`. The extension relies on the user to provide a safe command. The README.md contains a "Security Note" that warns users about potential risks, but this is not a technical mitigation.
*   **Missing mitigations:**
    *   Input sanitization and validation for the `phpCommand` setting.
        *   Restrict allowed characters in `phpCommand`.
        *   Use parameterized execution or shell-escape the command arguments to prevent command injection. However, given the complexity of shell escaping and the need to execute arbitrary PHP code, sanitization might be challenging to implement securely.
    *   Principle of least privilege: If possible, reduce the privileges required to execute the PHP commands. However, VSCode extensions typically run with the user's privileges.
    *   Warning to the user: When the extension detects a modified `phpCommand` setting, display a prominent warning to the user about the potential security risks and ask for confirmation before using the custom command.
*   **Preconditions:**
    1.  Victim has the Laravel Extra Intellisense extension installed in VSCode.
    2.  Victim opens a workspace in VSCode that contains a malicious `.vscode/settings.json` file (or settings are manipulated through other means).
    3.  The malicious `.vscode/settings.json` file (or manipulated settings) configures `LaravelExtraIntellisense.phpCommand` with injected commands.
    4.  The extension attempts to execute PHP code using `Helpers.runLaravel` or `Helpers.runPhp`. This happens automatically when the extension is activated and periodically afterward to refresh data.
*   **Source Code Analysis:**
    1.  **File: `src/helpers.ts` function `runPhp`:**
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

                cp.exec(command, // <-- Command injection vulnerability here
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
        The `runPhp` function retrieves the `phpCommand` setting from VSCode configuration and uses it as a template. It replaces `{code}` in the template with the provided PHP code and then executes the resulting command using `cp.exec`. There is no sanitization of the `phpCommand` setting itself, allowing for command injection. The provided `code` is escaped to some extent, but the vulnerability lies in the user-configurable `phpCommand` itself.
    2.  **File: `src/helpers.ts` function `runLaravel`:**
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
                    self.runPhp(command, description) // <-- Calls runPhp, propagating the vulnerability
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
        `runLaravel` function constructs a PHP script and then calls `runPhp` to execute it. This means that the command injection vulnerability in `runPhp` is directly exploitable through any function in the extension that uses `runLaravel`.

*   **Security Test Case:**
    1.  **Setup:**
        *   Install the Laravel Extra Intellisense extension in VSCode.
        *   Create a new empty directory.
        *   Inside the directory, create a `.vscode` folder and within it, create a `settings.json` file.
        *   In `settings.json`, add the following configuration:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c \\"touch /tmp/pwned_laravel_extension\\""
            }
            ```
        *   Open the empty directory as a workspace in VSCode.
    2.  **Execution:**
        *   Activate the Laravel Extra Intellisense extension (it usually activates on workspace open if a Laravel project is detected, but in this case, it might activate when a PHP or blade file is opened, or on extension activation).
        *   Wait for a short period (e.g., 1 minute) to ensure the extension attempts to run Laravel commands in the background as part of its routine operations.
    3.  **Verification:**
        *   Check if the file `/tmp/pwned_laravel_extension` exists on the system. If the file exists, it indicates that the command injected through `phpCommand` was executed, confirming the command injection vulnerability.
