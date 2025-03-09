### Vulnerability List

- Vulnerability Name: Command Injection via `phpCommand` setting
- Description:
    1. The "Laravel Extra Intellisense" extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code within the user's Laravel project.
    2. This setting is intended to allow customization for different environments (e.g., Docker, Sail).
    3. However, the extension directly substitutes the `{code}` placeholder in this setting with the PHP code it needs to execute, without proper sanitization or validation of the `phpCommand` itself.
    4. A malicious user can modify the `phpCommand` setting to inject arbitrary shell commands.
    5. When the extension attempts to gather autocompletion data (e.g., for routes, views, configs), it will execute the crafted `phpCommand` setting, leading to command injection.
- Impact:
    - Arbitrary command execution on the system where VSCode is running.
    - An attacker could gain full control over the developer's machine, potentially leading to data theft, malware installation, or further attacks on internal networks.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension directly uses the user-provided `phpCommand` setting without any validation or sanitization.
- Missing Mitigations:
    - Input validation and sanitization for the `phpCommand` setting.
    - Restricting the characters allowed in the `phpCommand` setting to prevent command injection.
    - Displaying a warning to the user when they modify the `phpCommand` setting, emphasizing the security risks.
    - Using a safer method for executing PHP code that does not involve shell command execution if possible.
- Preconditions:
    - The user must modify the `LaravelExtraIntellisense.phpCommand` setting in VSCode's settings.json or workspace settings.
    - The attacker needs to convince the developer to use a malicious workspace configuration file or manually change the setting.
- Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `Helpers.runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` setting.
    4. Line: `let command = commandTemplate.replace("{code}", code);` - Directly substitutes `{code}` with the PHP code without any sanitization.
    5. Line: `cp.exec(command, ...)` - Executes the constructed command using `child_process.exec`.

    ```
    // Visualization of code flow in Helpers.runPhp

    +---------------------+      getConfiguration('phpCommand')      +------------------------+      replace("{code}", code)     +-------------------+      cp.exec(command, ...)     +-----------------------+
    | VSCode Configuration| -------------------------------------> |  Get phpCommand Setting | -----------------------------------> | Construct Command | -------------------------> | Execute Shell Command |
    +---------------------+                                        +------------------------+                                    +-------------------+                                +-----------------------+
    ```

- Security Test Case:
    1. Open VSCode with a Laravel project.
    2. Modify the workspace settings (or user settings) to set `LaravelExtraIntellisense.phpCommand` to: `php -r 'echo \"[Laravel Extra Intellisense] Command Injection Test\"; system($_GET["cmd"]);'`. This injects `system($_GET["cmd"])` into the PHP command.
    3. Open any PHP or Blade file in the project to trigger the extension's autocompletion features (e.g., start typing `route('`). This will cause the extension to execute PHP code.
    4. In a terminal, execute a curl command (or open in a browser) to the workspace path (you can find workspace path in VSCode window title) with the injected command, for example: `curl "file:///path/to/your/laravel/project?cmd=whoami"`. Replace `/path/to/your/laravel/project` with the actual workspace file path.
    5. Observe that the output of the `whoami` command is displayed, demonstrating arbitrary command execution. You might see the output in the terminal where you executed curl or in VSCode output if the command produces visible output within the extension's execution context.
    6. For a more obvious demonstration, try `curl "file:///path/to/your/laravel/project?cmd=calc"` (on Windows) or `curl "file:///path/to/your/laravel/project?cmd=open%20/Applications/Calculator.app"` (on macOS) to see if the calculator application opens, confirming command execution.

- Vulnerability Name: Unintended Code Execution in User's Laravel Project
- Description:
    1. The "Laravel Extra Intellisense" extension executes PHP code within the user's Laravel application context to gather data for autocompletion.
    2. This is achieved by bootstrapping the Laravel application and then executing specific PHP commands using `php -r`.
    3. If the user's Laravel project contains existing vulnerabilities (e.g., insecure deserialization, SQL injection, Remote Code Execution vulnerabilities in routes or controllers), the extension's automated PHP code execution could inadvertently trigger these vulnerabilities.
    4. For example, if the extension's code execution path triggers a vulnerable route or controller in the user's application, it could lead to unintended actions or information disclosure.
- Impact:
    - The impact depends on the specific vulnerabilities present in the user's Laravel application.
    - It could range from information disclosure (if vulnerable code paths expose sensitive data) to remote code execution within the context of the Laravel application.
    - This could potentially allow an attacker to manipulate data, gain unauthorized access, or further compromise the Laravel application.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The "Security Note" in the README.md warns users about potential unwanted application execution and advises disabling the extension temporarily if sensitive code is present in service providers. This is a documentation-based mitigation and not a technical mitigation in the code.
- Missing Mitigations:
    - Sandboxing or isolating the extension's PHP code execution environment from the user's Laravel application as much as possible.
    - Analyzing the PHP code executed by the extension to ensure it does not trigger common vulnerability patterns in Laravel applications.
    - Providing configuration options to limit the scope of the extension's code execution or disable features that are considered risky.
    - Clearer warnings and guidance to users about the security implications of running arbitrary PHP code from their projects.
- Preconditions:
    - The user's Laravel project must contain exploitable vulnerabilities that can be triggered by the PHP code executed by the extension.
    - The extension's code execution paths must interact with these vulnerable parts of the Laravel application.
- Source Code Analysis:
    1. Multiple files in `src/` directory (e.g., `ConfigProvider.ts`, `RouteProvider.ts`, `ViewProvider.ts`, etc.) use `Helpers.runLaravel()` to execute PHP code.
    2. `Helpers.runLaravel()` bootstraps the user's Laravel application using `vendor/autoload.php` and `bootstrap/app.php`.
    3. The executed PHP code runs within the context of this bootstrapped Laravel application, meaning it has access to all application configurations, routes, controllers, models, and services.
    4. Example in `ConfigProvider.ts`: `Helpers.runLaravel("echo json_encode(config()->all());", "Configs")` - This executes `config()->all()` within the user's Laravel application.

    ```
    // Visualization of code flow in Helpers.runLaravel

    +---------------------+      bootstrap Laravel app      +-----------------------+      execute PHP code (e.g., config()->all())     +-----------------------+
    | Extension Feature | ----------------------------------> | Bootstrap Laravel App | ---------------------------------------------------> | Execute User Project Code |
    +---------------------+                                   +-----------------------+                                                   +-----------------------+

    // User Project Code context:
    // - Application configuration loaded
    // - Service Providers booted
    // - Routes defined
    // - Controllers available
    // - Models accessible
    // - Database connection (if configured)
    ```

- Security Test Case:
    1. Create a vulnerable Laravel application. For example, create a route in `routes/web.php` that is vulnerable to insecure deserialization or SQL injection. A simple example for demonstration (INSECURE CODE - DO NOT USE IN PRODUCTION):
        ```php
        <?php
        use Illuminate\Support\Facades\Route;
        use Illuminate\Http\Request;
        use Illuminate\Support\Facades\DB;

        Route::get('/vulnerable-sql', function (Request $request) {
            $query = "SELECT * FROM users WHERE id = " . $request->input('id'); // SQL Injection Vulnerability
            $results = DB::select($query);
            return response()->json($results);
        });
        ```
    2. Configure the Laravel application and database (if needed for the vulnerability).
    3. Open the vulnerable Laravel project in VSCode with the "Laravel Extra Intellisense" extension enabled.
    4. Trigger a feature of the extension that causes it to execute PHP code. For instance, open a Blade file and start typing `config('app.name')`. This will trigger `ConfigProvider` and execute PHP code in the background.
    5. While the extension is active, access the vulnerable route directly in a browser or using curl, exploiting the vulnerability. For example, `http://your-laravel-app.test/vulnerable-sql?id=1%20OR%201=1`. Replace `http://your-laravel-app.test` with your Laravel application's URL.
    6. Observe that the vulnerability is triggered even though you are only using the VSCode extension for autocompletion and not directly interacting with the vulnerable route through the browser. This demonstrates that the extension's background code execution can inadvertently trigger vulnerabilities in the user's project.
    7. Note: This test case requires a user to intentionally create a vulnerable Laravel application for demonstration purposes. In a real-world scenario, the vulnerability would already exist in the user's project, and the extension would unknowingly trigger it.
