### Vulnerability List

- **Vulnerability Name:** Arbitrary PHP Code Execution via Malicious Laravel Project Files

- **Description:**
    1. An attacker crafts a malicious Laravel project.
    2. Within this project, the attacker modifies a file that is parsed by the extension during its operation. This could be a route file (e.g., `routes/web.php`), a configuration file (e.g., `config/app.php`), a service provider, or any other PHP file loaded during the Laravel application's bootstrap or when data is gathered by the extension.
    3. The attacker injects malicious PHP code into this modified file. For example, inserting `<?php system('calc.exe'); ?>` or more sophisticated reverse shell code.
    4. A developer, with the "Laravel Extra Intellisense" extension installed in VSCode, opens the malicious Laravel project.
    5. When the extension activates, it automatically runs PHP code within the context of the opened Laravel project to gather autocompletion data (e.g., routes, views, configs). This is done by executing commands like `php -r "..."` using the configured `phpCommand`.
    6. As part of this process, the Laravel application is bootstrapped, which involves loading and executing project files, including the attacker-modified file containing the malicious PHP code.
    7. The injected malicious PHP code is executed on the developer's machine with the privileges of the VSCode process.

- **Impact:**
    - **Arbitrary Code Execution:** Successful exploitation allows the attacker to execute arbitrary PHP code on the developer's machine.
    - **Account Compromise:** Depending on the injected code, the attacker could potentially gain complete control over the developer's system, steal credentials, install malware, or pivot to other systems accessible from the developer's machine.
    - **Data Breach:**  The attacker could exfiltrate sensitive data from the developer's machine or the opened project.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** The README.md file includes a "Security Note" that warns users about the extension executing their Laravel application and suggests temporarily disabling the extension when writing sensitive code in service providers.
    - **Location:** `README.md` file in the project repository.
    - **Effectiveness:** This mitigation is weak and relies entirely on the developer reading and heeding the warning. It does not prevent the vulnerability from being exploited and offers no technical protection.

- **Missing Mitigations:**
    - **Sandboxing or Isolation:** Executing the PHP code in a sandboxed or isolated environment could limit the impact of arbitrary code execution. For example, using Docker or a similar containerization technology to run the PHP commands in a restricted environment.
    - **Code Review and Hardening:**  A thorough security code review of the PHP code executed by the extension is necessary. This includes ensuring that the extension's PHP scripts are robust and do not inadvertently execute user-supplied data as code.
    - **Input Validation and Sanitization:** While challenging in this context, exploring methods to validate or sanitize the data retrieved from the Laravel project before using it could help mitigate risks. However, this is difficult as the vulnerability lies in the execution of project code itself, not necessarily the *data* returned.
    - **User Warnings:** Displaying a clear warning to the user when opening a new Laravel project, especially if the extension detects potential risks or if the project is not from a trusted source, could increase awareness.
    - **Permissions Reduction:** Running the extension's PHP execution with the least necessary privileges could limit the impact of a successful attack.

- **Preconditions:**
    - The "Laravel Extra Intellisense" VSCode extension must be installed and activated.
    - The developer must open a malicious Laravel project in VSCode.
    - The malicious Laravel project must contain PHP code crafted by the attacker in a file parsed by the extension during its normal operation.

- **Source Code Analysis:**
    1. **`helpers.ts:runLaravel(code: string, description: string|null = null)`:**
        ```typescript
        static runLaravel(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
            if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                var command =
                    "define('LARAVEL_START', microtime(true));" +
                    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
                    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
                    "..." // Service provider registration and kernel handling
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
                        code + // <--- User-controlled code injected here (indirectly through project files)
                    "	echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
                    "}" +
                    "..."
                var self = this;

                return new Promise(function (resolve, error) {
                    self.runPhp(command, description) // Executes the constructed PHP command
                        .then(...)
                        .catch(...);
                });
            }
            return new Promise((resolve, error) => resolve(""));
        }
        ```
        - This function constructs a PHP script that bootstraps a Laravel application.
        - Critically, the `code` parameter, which is generated by the extension to gather data, is embedded directly into this script and executed within the Laravel application's context using `runPhp`.
        - The `code` itself is intended to be safe data-fetching code. However, if a malicious project modifies files that are loaded during the Laravel bootstrap process (e.g., `bootstrap/app.php`, service providers, route files, config files), then arbitrary PHP code can be injected and executed *before* the extension's intended data-fetching code runs.

    2. **`helpers.ts:runPhp(code: string, description: string|null = null)`:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Minimal escaping - insufficient for security
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // Injects 'code' into the phpCommand
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Executes the final command using child_process.exec
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
        - This function takes the PHP `code` and executes it using the configured `phpCommand` (defaulting to `php -r "{code}"`).
        - The minimal escaping performed here is insufficient to prevent code injection if the `code` itself is malicious or influenced by malicious project files.

    3. **Providers (e.g., `RouteProvider.ts`, `ConfigProvider.ts`, `ViewProvider.ts`):**
        - These providers use `Helpers.runLaravel()` to fetch data necessary for autocompletion.
        - For example, `RouteProvider` uses code to fetch route information, `ConfigProvider` fetches configuration values, and `ViewProvider` fetches view paths.
        - The PHP code executed by these providers, while seemingly safe, runs within the application context. If the application itself has been compromised by malicious code in project files, the extension will inadvertently trigger this malicious code execution.

    **Visualization:**

    ```
    [Developer opens malicious Laravel Project in VSCode]
        |
        v
    [Extension Activation]
        |
        v
    [Providers (e.g., RouteProvider) trigger data fetching]
        |
        v
    [Helpers.runLaravel() is called with extension's PHP code]
        |
        v
    [runLaravel() constructs PHP script including:
        - Laravel Bootstrap (`vendor/autoload.php`, `bootstrap/app.php`)
        - Extension's data-fetching PHP code
        - POTENTIALLY MALICIOUS CODE from modified project files (e.g., routes/web.php)]
        |
        v
    [runPhp() executes the constructed PHP script using 'php -r "{script}"']
        |
        v
    [PHP interpreter executes script]
        |
        v
    [MALICIOUS PHP CODE FROM PROJECT FILES IS EXECUTED] <-- Vulnerability triggered here
        |
        v
    [Extension's data-fetching code runs (after malicious code)]
        |
        v
    [Autocompletion features provided (but system potentially compromised)]
    ```

- **Security Test Case:**
    1. **Setup:**
        - Ensure the "Laravel Extra Intellisense" extension is installed and enabled in VSCode.
        - Create a new Laravel project using `composer create-project laravel/laravel malicious-project`.
        - Navigate into the `malicious-project` directory: `cd malicious-project`.

    2. **Inject Malicious Code:**
        - Modify the `routes/web.php` file in the `malicious-project` directory. Add the following PHP code at the very top of the file, before the `<?php` opening tag if it exists, or simply as the first line if the file is empty or starts with `<?php`:
          ```php
          <?php system('calc.exe'); ?>
          ```
          (For Linux/macOS, use `<?php system('gnome-calculator'); ?>` or similar calculator application command.)

    3. **Open Project in VSCode:**
        - Open VSCode.
        - Open the `malicious-project` folder in VSCode (`File` -> `Open Folder...` and select the `malicious-project` directory).

    4. **Trigger Extension Activation:**
        - Wait a few seconds for the extension to activate and start its background processes. Opening a PHP or Blade file in the project can speed up the activation if necessary.

    5. **Observe Code Execution:**
        - Observe if the calculator application (`calc.exe` or `gnome-calculator`) launches on your system.
        - If the calculator application launches, this confirms that the `system()` command within the `routes/web.php` file was executed, demonstrating arbitrary PHP code execution.

    6. **Clean up (Important):**
        - Close VSCode.
        - Delete the `malicious-project` folder to remove the test project.

This test case demonstrates that simply opening a Laravel project with malicious PHP code in a parsed file will trigger arbitrary code execution via the "Laravel Extra Intellisense" extension. This confirms the vulnerability.
