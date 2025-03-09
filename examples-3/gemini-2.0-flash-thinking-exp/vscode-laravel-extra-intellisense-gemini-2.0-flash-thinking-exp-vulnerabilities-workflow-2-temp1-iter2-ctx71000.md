### Vulnerability: Command/PHP Code Injection via `phpCommand` setting

- **Description:**
    1. A developer installs the "Laravel Extra Intellisense" VSCode extension.
    2. The developer opens a Laravel project in VSCode.
    3. An attacker persuades the developer (via social engineering, phishing, or other means) to modify the `LaravelExtraIntellisense.phpCommand` setting in VSCode.
    4. The attacker crafts a malicious command or PHP script path and sets it as the value for `LaravelExtraIntellisense.phpCommand`. For example, the attacker could set it to `bash -c "{code}"` or point to a malicious PHP script like `${workspaceFolder}/malicious.php`.
    5. When the extension attempts to gather autocompletion data (automatically, periodically, or when the developer edits code triggering autocompletion), it executes a command using the configured `phpCommand`.
    6. Because the `phpCommand` is attacker-controlled, the malicious command or script is executed on the developer's machine instead of the intended safe PHP code. The `{code}` placeholder is replaced by the extension with generated PHP code, but the attacker controls the initial command structure, leading to command or PHP code injection.

- **Impact:**
    - **Critical Impact:** Successful exploitation allows the attacker to execute arbitrary system commands or PHP code on the developer's machine with the privileges of the user running VSCode. This can result in:
        - **Data Theft:** Stealing sensitive files, source code, credentials, or other data from the developer's machine or Laravel project.
        - **Malware Installation:** Installing malware, backdoors, or other malicious software.
        - **System Compromise:** Gaining complete control over the developer's machine, potentially pivoting to other systems on the network.
        - **Unauthorized access or modification of project files.**
        - **Exfiltration of sensitive information** like environment variables, source code, or database credentials.
        - **Compromise of the development environment and potentially the wider system.**

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** The extension's `README.md` contains a "Security Note" section warning about the extension automatically and periodically running the Laravel application. It advises caution, suggesting temporary disabling when writing sensitive code in service providers and recommending reviewing configuration examples for Docker and Laravel Sail.
        - **Location:** `README.md` file in the project repository.
        - **Effectiveness:** Low. The security note is merely a warning, not a technical mitigation. It depends on the developer's awareness and manual secure configuration, failing to prevent command injection if a malicious `phpCommand` is naively set.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Validate and sanitize the `phpCommand` setting to permit only safe characters and commands, ideally verifying it executes PHP and rejecting potentially malicious commands. However, reliably preventing all command injection through sanitization is challenging.
    - **Restrict Customization:** Limit or remove customization of `phpCommand`. If necessary, offer limited, safe modification via predefined options or specific part modifications, disallowing arbitrary external command execution.
    - **Principle of Least Privilege:** Explore alternative, secure methods for obtaining Laravel application data that avoid executing arbitrary PHP code with a user-configurable command. If execution is essential, minimize command injection risks through secure practices.
    - **User Warning on Modification:** Display prominent warnings in VSCode when users modify `phpCommand`, especially for deviations from defaults or potentially unsafe values, clearly explaining associated security risks.
    - **Sandboxing or Isolation:** Isolate the PHP execution environment to limit the impact of compromised `phpCommand` settings, potentially using containerization or similar techniques.
    - **Enhanced Documentation:** Provide detailed security guidance and best practices for secure `phpCommand` configuration, explicitly warning about risks of untrusted commands and recommending isolated environments like Docker.

- **Preconditions:**
    1. The "Laravel Extra Intellisense" VSCode extension is installed.
    2. A Laravel project is opened in VSCode.
    3. An attacker can influence the developer to change the `LaravelExtraIntellisense.phpCommand` setting to a malicious value via social engineering, phishing, or exploiting other system vulnerabilities.
    4. The user triggers extension activity requiring PHP execution, such as opening/editing PHP/Blade files or triggering autocompletion.

- **Source Code Analysis:**
    1. **File:** `src/helpers.ts`
    2. **Function:** `runPhp(code: string, description: string|null = null)`
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
        - The `runPhp` function executes PHP code for autocompletion data.
        - It fetches the `phpCommand` setting from VSCode configuration without validation: `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - Default `phpCommand` is `"php -r \"{code}\""`.
        - It constructs the command by replacing `{code}` in `commandTemplate` with the provided `$code`.
        - `cp.exec(command, ...)` executes the constructed command.
        - **Vulnerability:** The user-configurable `phpCommand` setting is directly used in `cp.exec`, leading to command injection if an attacker modifies it. Inadequate escaping (quotes, backslashes) fails to prevent injection when the base command is attacker-controlled.

    3. **File:** `src/helpers.ts`
    4. **Function:** `runLaravel(code: string, description: string|null = null)`
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
        - `runLaravel` constructs a PHP script bootstrapping Laravel and includes user-provided `code` within Laravel context.
        - It calls `runPhp` to execute the entire script using the potentially malicious `phpCommand`.
        - Even if extension-generated code is safe, a malicious `phpCommand` can compromise the environment.

    5. Provider files (`src/*Provider.ts` like `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`):
        - Providers use `Helpers.runLaravel()` to execute PHP for autocompletion data.
        - Example from `src/ConfigProvider.ts`:
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
        - Providers depend on `runLaravel` and `runPhp`, making them vulnerable if `phpCommand` is misconfigured.

- **Security Test Case:**
    1. **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Open a new or existing Laravel project.
        - Open VSCode settings (JSON format).
    2. **Modify `phpCommand` setting for Command Injection:**
        - Add or modify `LaravelExtraIntellisense.phpCommand` to:
          ```json
          "LaravelExtraIntellisense.phpCommand": "touch /tmp/pwned_by_vscode_extension_{code}"
          ```
          *(Windows: `"powershell -Command "New-Item -ItemType File -Path C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}"`)*
    3. **Modify `phpCommand` setting for PHP Code Execution:**
        - Create `malicious.php` in project root:
          ```php
          <?php
          file_put_contents('pwned.txt', 'You have been pwned by Laravel Extra Intellisense!');
          ```
        - Set `phpCommand` to execute this script:
          ```json
          "LaravelExtraIntellisense.phpCommand": "php ${workspaceFolder}/malicious.php"
          ```
    4. **Trigger Extension Activity:**
        - Open a PHP file (e.g., controller, route).
        - Type Laravel function for autocompletion (e.g., `route('`, `config('`).
    5. **Verify Exploitation (Command Injection):**
        - Check if `/tmp/pwned_by_vscode_extension_{code}` (or `C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}` on Windows) is created after typing and extension activity.
        - **Success:** File creation indicates `touch` (or `New-Item`) execution, proving command injection.
    6. **Verify Exploitation (PHP Code Execution):**
        - Check project root for `pwned.txt`.
        - **Success:** `pwned.txt` with "You have been pwned by Laravel Extra Intellisense!" confirms malicious PHP script execution.
    7. **Cleanup:**
        - Remove malicious `LaravelExtraIntellisense.phpCommand` setting.
        - Delete created files (`/tmp/pwned_by_vscode_extension_{code}`, `C:\\Windows\\Temp\\pwned_by_vscode_extension_{code}`, `pwned.txt`).

This test case demonstrates successful command and PHP code injection via `LaravelExtraIntellisense.phpCommand` modification, leading to arbitrary command/code execution during extension's PHP execution attempts.
