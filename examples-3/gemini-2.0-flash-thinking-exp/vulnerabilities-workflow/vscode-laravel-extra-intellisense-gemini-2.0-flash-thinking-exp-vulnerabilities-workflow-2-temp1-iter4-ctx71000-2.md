- Vulnerability Name: Unsafe execution of user-defined PHP code leading to potential vulnerability trigger in Laravel projects
- Description:
    1. The VSCode Laravel Extra Intellisense extension is designed to enhance Laravel development by providing autocompletion for routes, views, configurations, and other Laravel-specific features.
    2. To achieve this, the extension executes PHP code from the user's workspace using the `Helpers.runLaravel()` function. This function effectively boots up the Laravel application's environment to extract necessary information such as routes, views, configs, translations, etc.
    3. This design introduces a security risk: if the opened Laravel project contains existing vulnerabilities (e.g., in routes, controllers, service providers, or configuration), the extension's background PHP code execution to gather autocompletion data could inadvertently trigger these vulnerabilities.
    4. For example, a vulnerable route might expose sensitive data or perform unintended actions when accessed. If the extension, during its routine data gathering process, triggers execution paths that involve this vulnerable route (even without directly calling it, but indirectly via service container resolution, event listeners, etc. during Laravel bootstrap), it could lead to the exposure of sensitive information within the extension's output logs or cause unintended side effects in the developer's environment.
    5. This risk is amplified because the extension automatically and periodically executes PHP code in the background without explicit user consent for each execution, increasing the likelihood of inadvertently triggering vulnerabilities present in the workspace.
- Impact:
    - Execution of user-defined PHP code within the context of the developer's Laravel application.
    - If the Laravel project contains vulnerabilities, the extension's automated PHP execution could trigger these vulnerabilities.
    - Potential impacts include:
        - **Information Disclosure:** Sensitive data (e.g., database credentials, environment variables, application secrets) could be exposed if a triggered vulnerability leads to their output, and this output is captured by the extension's execution logs (visible in the VSCode output panel).
        - **Unintended Application Behavior:** Triggering vulnerable code might lead to unintended side effects within the development environment, such as database modifications, file system changes, or unexpected application states, disrupting the developer's workflow or environment stability.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - A "Security Note" is included in the `README.md` file, advising users to be aware that the extension executes their Laravel application automatically.
    - The note suggests that users should monitor their logs for unknown errors potentially caused by the extension and to temporarily disable the extension when working on sensitive code in service providers.
    - This mitigation is purely informational and relies on the user's awareness and proactive actions. It does not technically prevent the vulnerability.
- Missing mitigations:
    - **Sandboxing PHP execution:** Executing the Laravel application in a sandboxed environment could limit the impact of triggered vulnerabilities, preventing them from affecting the developer's system or network beyond the sandbox.
    - **Input sanitization and output validation:** While directly sanitizing the user's Laravel code is infeasible and counterproductive, validating the output of the executed PHP code and sanitizing any data displayed to the user (e.g., in autocomplete suggestions or output logs) could mitigate information disclosure risks.
    - **User confirmation:** Requiring explicit user confirmation before executing PHP code, especially for operations that might have side effects, would give developers more control and awareness, reducing the chance of unintended vulnerability triggering. However, this might hinder the extension's core autocompletion functionality, which relies on background data gathering.
    - **Static analysis:** Performing static analysis of the user's Laravel project to identify potential vulnerabilities before executing any code could allow the extension to warn users about risks or adjust its behavior to minimize the chance of triggering them. This is complex and might produce false positives.
    - **Least privilege execution:** Running the PHP commands with the least necessary privileges could limit the damage from potential vulnerabilities. However, for accurate Laravel environment booting and data extraction, the executed code likely needs access to application configurations and potentially database connections.
- Preconditions:
    - A developer is using VSCode with the Laravel Extra Intellisense extension installed.
    - The developer has opened a workspace containing a Laravel project.
    - The Laravel project contains at least one vulnerability that can be triggered by PHP code execution, either directly or indirectly through framework bootstrap processes.
    - The extension is active and attempts to gather data for autocompletion features, which involves executing PHP code from the Laravel project.
- Source code analysis:
    - The core of the vulnerability lies in the `Helpers.runLaravel(code: string, description: string|null = null)` function located in `src\helpers.ts`.
    - This function constructs a PHP command that includes the provided `code` and executes it using `child_process.exec()`.
    - The executed PHP code boots the Laravel application and then runs the provided code snippet within the application's context.
    - Multiple provider classes (e.g., `AuthProvider.ts`, `BladeProvider.ts`, `ConfigProvider.ts`, `EloquentProvider.ts`, `MiddlewareProvider.ts`, `RouteProvider.ts`, `TranslationProvider.ts`, `ViewProvider.ts`) use `Helpers.runLaravel()` to fetch data required for autocompletion.
    - For example, `AuthProvider.ts` uses `Helpers.runLaravel()` to execute PHP code that retrieves Gate abilities and policies:
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
    - Similarly, `RouteProvider.ts` uses `Helpers.runLaravel()` to fetch route information:
    ```typescript
    Helpers.runLaravel(
        "echo json_encode(array_map(function ($route) {" +
        "    return ['method' => implode('|', array_filter($route->methods(), function ($method) {" +
        "        return $method != 'HEAD';" +
        "    })), 'uri' => $route->uri(), 'name' => $route->getName(), 'action' => str_replace('App\\\\Http\\\\Controllers\\\\', '', $route->getActionName()), 'parameters' => $route->parameterNames()];" +
        "}, app('router')->getRoutes()->getRoutes()));",
        "HTTP Routes"
    )
    ```
    - In all these cases, the extension constructs PHP code that interacts with the Laravel application's components, potentially triggering any existing vulnerabilities within the application's logic during the bootstrap or data retrieval process.
    - The extension does not perform any sanitization or security checks on the user's Laravel project code before executing these PHP commands.
- Security test case:
    1. Create a new Laravel project (e.g., using `laravel new vulnerable-project`).
    2. Introduce an information disclosure vulnerability in a route. In `routes/web.php`, add the following route:
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
    This route `/sensitive-config` intentionally exposes the database password from the Laravel configuration.
    3. Open the `vulnerable-project` folder in VSCode.
    4. Install the "Laravel Extra Intellisense" extension in VSCode if not already installed.
    5. Open any PHP file within the Laravel project in VSCode (e.g., `routes/web.php`).
    6. In the opened file, start typing `route('test'`. This action should trigger the extension to fetch route information for autocompletion suggestions.
    7. Open the VSCode Output panel (View -> Output) and select "Laravel Extra Intellisense" from the dropdown menu in the Output panel.
    8. Observe the logs in the Output panel. Examine the output for any unexpected information. Due to the nature of Laravel's bootstrap process and route collection, it's possible that the extension's route fetching process might indirectly trigger parts of the application's service container resolution or other bootstrapping steps that could, in a more complex vulnerable application, lead to side effects or information leaks. *In this simplified test case, direct information disclosure of the database password via route listing is less likely as the extension aims to list route names and parameters, not execute route actions during route listing. However, the underlying risk of triggering application code remains relevant.*

    9. **To demonstrate a more direct trigger, although not directly related to route autocompletion, consider a vulnerability in a service provider that is always executed during Laravel bootstrap.** Create a service provider (e.g., `app/Providers/VulnerableServiceProvider.php`):
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
    Register this provider in `config/app.php` in the `providers` array.
    10. Modify the `Helpers.runLaravel` function in `src\helpers.ts` temporarily to append a query parameter to the application URL when executing PHP code. For example, in `src\helpers.ts`, inside `runLaravel` function, modify the command construction:
    ```javascript
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    // Append query parameter to trigger the vuln. This is just for testing, NOT a real fix.
    commandTemplate += "?trigger_vuln=1";
    let command = commandTemplate.replace("{code}", code);
    ```
    **Note:** This modification is solely for demonstration purposes to easily trigger the vulnerable service provider. In a real-world scenario, vulnerabilities might be triggered without such direct query parameter manipulation, simply by the extension's regular Laravel bootstrapping during data gathering.

    11. Re-open VSCode with the vulnerable Laravel project. The extension will automatically start fetching data.
    12. Check the `storage/` directory of your Laravel project. If the vulnerability in `VulnerableServiceProvider` was triggered by the extension's execution, you will find a file named `vuln_triggered.txt` created in the `storage/` directory, containing the message 'Vulnerability triggered by Laravel Extra Intellisense'.
    13. This demonstrates that the extension's background PHP execution can indeed trigger code within the Laravel application, and if that code is vulnerable, it can lead to unintended consequences. This test case shows a file write, but the impact could be more severe depending on the nature of the vulnerability in the Laravel project.
