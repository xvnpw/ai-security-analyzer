- Vulnerability Name: Remote Code Execution through Malicious Laravel Project
- Description:
    1. A developer installs the "Laravel Extra Intellisense" VSCode extension.
    2. An attacker creates a malicious Laravel project. This project contains modified Laravel application code (e.g., in `AppServiceProvider.php`, `routes/web.php`, or a controller) to execute arbitrary PHP commands when the Laravel application is booted or certain components are accessed. For example, the attacker could add `exec('touch /tmp/pwned');` in the `boot` method of `AppServiceProvider.php`.
    3. The attacker tricks the developer into opening this malicious Laravel project in VSCode.
    4. Upon opening the project, the "Laravel Extra Intellisense" extension activates.
    5. The extension, to provide autocompletion features, automatically and periodically executes PHP code from the opened Laravel project using the `Helpers.runLaravel` function. This execution is triggered by various completion providers (e.g., `ConfigProvider`, `RouteProvider`, `ViewProvider`) when autocompletion is needed for configs, routes, views, etc.
    6. Because the malicious project has modified its Laravel application code, when the extension executes commands like `config()->all()`, `app('router')->getRoutes()->getRoutes()`, or other Laravel commands to gather data, the malicious code embedded within the project (e.g., `exec('touch /tmp/pwned');` in `AppServiceProvider.php`) is executed as part of the Laravel application's bootstrap process or during the execution of Laravel commands.
    7. This results in Remote Code Execution on the developer's machine, as arbitrary PHP commands provided by the attacker within the malicious Laravel project are executed in the context of the developer's VSCode environment.
- Impact:
    - Complete control over the developer's machine with the permissions of the user running VSCode.
    - An attacker can read and exfiltrate sensitive files from the developer's machine, including SSH keys, credentials, and source code.
    - An attacker can install malware, backdoors, or ransomware on the developer's machine.
    - An attacker can pivot to other systems accessible from the developer's network.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - Security Note in `README.md`: The extension's `README.md` includes a "Security Note" that warns users about the extension running their Laravel application automatically and periodically. It advises users to be cautious and temporarily disable the extension when working with sensitive code or if they observe unknown errors in their logs.
    - This mitigation is insufficient as it relies solely on the user's awareness and manual action, and does not prevent the vulnerability from being exploited.
- Missing mitigations:
    - Sandboxing: Implement sandboxing for the PHP execution environment. Run the PHP code in a restricted environment with limited permissions to minimize the impact of potential RCE. This could involve using containers or other isolation techniques.
    - Static Analysis Fallback: Where feasible, implement static analysis as a fallback mechanism. Attempt to parse Laravel project files statically to extract information (e.g., routes, views) without executing PHP code. This could reduce reliance on dynamic execution, although it might not be possible for all features.
    - User Confirmation: Implement a user confirmation prompt when the extension is activated in a new workspace or when it detects significant changes in the project's configuration. This prompt should warn the user about the potential risks of executing project code and ask for explicit permission before enabling full functionality.
    - Code Review and Hardening: Conduct a thorough code review of the extension, specifically focusing on the `Helpers.runLaravel` function and all completion providers that use it. Harden the code to prevent any unintended code injection vulnerabilities within the extension itself.
- Preconditions:
    - The developer has installed the "Laravel Extra Intellisense" VSCode extension.
    - The developer opens a malicious Laravel project in VSCode.
    - The "Laravel Extra Intellisense" extension is enabled and active in the opened workspace.
- Source code analysis:
    1. `src/helpers.ts`: The `Helpers.runLaravel(code: string, description: string|null = null)` function is responsible for executing PHP code. It constructs a command using the `phpCommand` configuration setting (defaulting to `php -r "{code}"`) and executes it using `child_process.exec`. The provided `$code` argument is directly embedded into the command.
    2. Completion Providers (e.g., `src/ConfigProvider.ts`, `src/RouteProvider.ts`, `src/ViewProvider.ts`, etc.): These providers use `Helpers.runLaravel()` to execute various Laravel commands to gather data for autocompletion. For example, `ConfigProvider.ts` uses `Helpers.runLaravel("echo json_encode(config()->all());", "Configs")`.
    3. Project Code Execution: The executed PHP code, although seemingly safe within the extension's context, is designed to interact with the Laravel application. This means it boots the Laravel application, loads configurations, routes, service providers, and other components of the opened Laravel project.
    4. Malicious Project Influence: A malicious Laravel project can modify its own project files to inject arbitrary PHP code into the application's lifecycle. This can be done by modifying service providers, routes, controllers, or any other part of the Laravel application that gets executed during the extension's data gathering process.
    5. RCE Trigger: When the extension calls `Helpers.runLaravel()` to fetch data, it inadvertently triggers the execution of the malicious code embedded within the opened Laravel project, leading to Remote Code Execution on the developer's machine.

- Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a basic Laravel project using `composer create-project --prefer-dist laravel/laravel:^9.0 .` (or any Laravel version).
    3. Modify `malicious-laravel-project/app/Providers/AppServiceProvider.php`. In the `boot()` method, add the following line: `exec('touch /tmp/pwned-by-laravel-intellisense');`. The `boot()` method should look like this:
    ```php
    public function boot()
    {
        exec('touch /tmp/pwned-by-laravel-intellisense');
        // ... rest of the original boot method ...
    }
    ```
    4. Open VSCode and install the "Laravel Extra Intellisense" extension if not already installed.
    5. Open the `malicious-laravel-project` folder in VSCode.
    6. Wait for a few seconds to allow the "Laravel Extra Intellisense" extension to activate and perform its initial data gathering. Trigger autocompletion in a blade or php file to ensure the extension is actively working. For example, open `resources/views/welcome.blade.php` and type `config('app.name')` and wait for autocompletion suggestions.
    7. After a short period (give it a minute to be sure), check if the file `/tmp/pwned-by-laravel-intellisense` exists on your system. Open a terminal and run `ls /tmp/pwned-by-laravel-intellisense`.
    8. If the file `/tmp/pwned-by-laravel-intellisense` exists, this confirms that the `exec('touch /tmp/pwned-by-laravel-intellisense')` command injected into `AppServiceProvider.php` was executed by the "Laravel Extra Intellisense" extension, demonstrating Remote Code Execution.
    9. Clean up the test by deleting the `/tmp/pwned-by-laravel-intellisense` file and the `malicious-laravel-project` directory if needed.
