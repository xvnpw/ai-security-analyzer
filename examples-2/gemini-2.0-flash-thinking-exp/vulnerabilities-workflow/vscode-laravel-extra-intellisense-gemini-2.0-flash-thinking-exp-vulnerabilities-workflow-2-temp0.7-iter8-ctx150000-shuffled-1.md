- Vulnerability name: Remote Code Execution via `phpCommand` setting
- Description:
    1. The "Laravel Extra Intellisense" extension allows users to customize the command used to execute PHP code through the `LaravelExtraIntellisense.phpCommand` setting.
    2. This setting is intended to allow users to configure how the extension interacts with their Laravel application, especially in environments like Docker or Laravel Sail.
    3. However, the extension does not properly sanitize or validate the `phpCommand` setting.
    4. A malicious user can configure `phpCommand` to inject arbitrary PHP code or system commands. For example, setting `phpCommand` to `php -r "{code}; system('malicious_command')"` or even directly to a command like `bash -c "malicious_command"`.
    5. When the extension attempts to gather information from the Laravel application (e.g., routes, views, configs), it constructs a PHP code snippet (`{code}`) and executes it using the user-defined `phpCommand`.
    6. If the `phpCommand` is malicious, the injected code or system commands will be executed on the developer's machine with the privileges of the user running VS Code.
    7. This can lead to Remote Code Execution (RCE) because the attacker, by controlling the `phpCommand` setting (e.g., by tricking a user into importing malicious settings or through a workspace configuration vulnerability), can execute arbitrary commands on the developer's machine whenever the extension tries to run PHP code.
- Impact:
    - **Critical**: Full Remote Code Execution on the developer's machine.
    - An attacker can gain complete control over the developer's workstation.
    - This can lead to:
        - Data theft: Access to source code, environment variables, credentials, and other sensitive information stored on the developer's machine or within the Laravel project.
        - Malware installation: Installation of viruses, ransomware, or other malicious software.
        - Lateral movement: Using the compromised developer machine as a stepping stone to attack other systems within the developer's network.
        - Denial of Service: Crashing the developer's machine or preventing them from working.
        - Modification of project files: Injecting backdoors or malicious code directly into the Laravel project.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - The `runPhp` function in `src/helpers.ts` performs some escaping of double quotes (`"`) and backslashes (`\`) in the PHP code snippet that is passed to the `phpCommand`.
    - For Unix-like systems, it also escapes dollar signs (`$`), single quotes (`'`) and double quotes (`"`) again with backslashes.
    - The README.md contains a "Security Note" warning users about potential security risks and advising them to disable the extension if they have sensitive code in service providers. This is a documentation-level mitigation, not a code-level one and relies on user awareness and action.
- Missing mitigations:
    - **Input sanitization and validation for `phpCommand` setting**: The extension should validate and sanitize the `phpCommand` setting to ensure it only contains the expected `php` command and safe options.  It should prevent users from injecting arbitrary commands or modifying the execution flow. A whitelist approach for allowed characters and command structure would be beneficial.
    - **Parameterization of commands**: Instead of string concatenation to build the command with the `{code}` placeholder, the extension should use parameterized command execution if possible. However, `child_process.exec` in Node.js does not directly support parameterization in the same way as database queries.
    - **Sandboxing or isolation**: Executing the PHP code in a sandboxed environment or a more isolated process could limit the impact of potential RCE. However, this might be complex to implement for a VS Code extension.
    - **Principle of least privilege**: While not directly a mitigation for RCE, running the PHP command with the least necessary privileges would reduce the potential damage. However, this is mostly dependent on the user's environment and how PHP is set up.
    - **Content Security Policy (CSP) for extension settings**: VS Code extensions can use CSP to restrict the capabilities of extension settings. While CSP is more relevant to web contexts, exploring if VS Code provides mechanisms to limit the execution context of extension settings could be considered.
- Preconditions:
    - The user must have the "Laravel Extra Intellisense" extension installed and activated in VS Code.
    - The user or an attacker must be able to modify the `LaravelExtraIntellisense.phpCommand` setting. This could be through:
        - Direct user configuration (unlikely to be intentionally malicious by the user, but possible if misinformed or following malicious instructions).
        - Workspace settings: A malicious user could provide a Laravel project with a `.vscode/settings.json` file that contains a malicious `phpCommand`. If the developer opens this project and trusts workspace settings, the malicious command will be configured.
        - Extension setting synchronization: If VS Code setting synchronization is enabled and an attacker gains access to the user's settings, they could modify the `phpCommand` remotely.
- Source code analysis:
    1. **`src/helpers.ts` - `runPhp` function**:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Escape double quotes in code
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$"); // Escape dollar signs for Unix-like systems
                code = code.replace(/\\\\'/g, '\\\\\\\\\''); // Escape escaped single quotes (over-escaping)
                code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // Escape escaped double quotes (over-escaping)
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // Command is built by string replacement
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Command execution using child_process.exec
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) {
                        // ... error handling ...
                    }
                );
            });
            return out;
        }
        ```
        - The code performs basic escaping on the `code` variable, but it does not validate or sanitize the `commandTemplate` (which comes directly from the `phpCommand` setting).
        - The `command` is constructed by simple string replacement, making it vulnerable to injection if `commandTemplate` is malicious.
        - `cp.exec(command, ...)` executes the constructed command, allowing for RCE if the command is crafted maliciously.

    2. **`src/helpers.ts` - `runLaravel` function**:
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/(?:\r\n|\r|\n)/g, ' '); // Remove newlines from code
            if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                var command = // PHP script constructed as a string
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    // ... Laravel bootstrapping code ...
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code + // User-provided code is embedded here
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    // ... Laravel termination code ...

                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // Executes the constructed PHP script using runPhp
                        // ... result parsing ...
                });
            }
            return new Promise((resolve, error) => resolve(""));
        }
        ```
        - `runLaravel` constructs a complete PHP script, embedding the user-provided `code` within it.
        - It then calls `runPhp` to execute this script.
        - If `phpCommand` is malicious, even though `runLaravel` constructs a Laravel bootstrapping script, the malicious command from `phpCommand` will still be executed by `runPhp`.
- Security test case:
    1. **Pre-requisites**:
        - Install "Laravel Extra Intellisense" extension in VS Code.
        - Open a Laravel project in VS Code (or any folder, as Laravel project is not strictly needed to trigger the vulnerability).
    2. **Modify `phpCommand` setting**:
        - Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - Go to Extension settings for "Laravel Extra Intellisense".
        - Find the `Php Command` setting (`LaravelExtraIntellisense.phpCommand`).
        - Change the setting to a malicious command. For example, to execute `calc.exe` on Windows or `gnome-calculator` on Linux, set it to:
            - Windows: `php -r "{code}; system('calc.exe');"`
            - Linux: `php -r "{code}; system('gnome-calculator');"` or `bash -c "gnome-calculator"` (if you want to test non-php command injection, in this case remove `php -r "{code};"` from the beginning)
        - For a more benign test, to simply output a message, you can use: `php -r "echo 'Vulnerable!'; {code}"`
    3. **Trigger extension functionality**:
        - Open any PHP or Blade file in the project.
        - Trigger any autocompletion feature provided by the extension that relies on PHP execution. For example, in a Blade file, type `route('` to trigger route autocompletion, or `config('` to trigger config autocompletion, or `trans('` for translation autocompletion, or even just open a blade or php file which might trigger some background process in the extension.
    4. **Observe the result**:
        - If the vulnerability is successfully triggered, you should observe:
            - For calculator example: The calculator application (`calc.exe` or `gnome-calculator`) should launch.
            - For "Vulnerable!" message: In the "Laravel Extra Intellisense" output channel in VS Code (View -> Output, select "Laravel Extra Intellisense" from the dropdown), you should see the "Vulnerable!" message printed, potentially along with other output from the extension.
        - If you used a command like `bash -c "touch /tmp/pwned"`, check if the file `/tmp/pwned` was created.
    5. **Cleanup**:
        - After testing, remember to revert the `phpCommand` setting back to its default value (`php -r "{code}"`) to avoid further risks.

This test case demonstrates that by modifying the `phpCommand` setting, an attacker can indeed achieve Remote Code Execution when the extension attempts to run PHP code.
