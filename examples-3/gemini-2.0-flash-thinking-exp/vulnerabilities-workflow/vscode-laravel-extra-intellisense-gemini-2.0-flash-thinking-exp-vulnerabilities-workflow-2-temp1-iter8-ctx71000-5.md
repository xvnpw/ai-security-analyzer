- Vulnerability Name: PHP Code Injection via `phpCommand` Configuration
  - Description:
    1. The extension allows users to configure the `phpCommand` setting, which specifies the command used to execute PHP code.
    2. This setting is used by the extension to run PHP scripts in the user's Laravel project to gather autocompletion data.
    3. The extension replaces the `{code}` placeholder in the `phpCommand` with dynamically generated PHP code and executes it.
    4. If a user, acting as an attacker, modifies the `phpCommand` in their VSCode settings to inject malicious PHP code alongside the `{code}` placeholder, the extension will execute this malicious code when it attempts to gather autocompletion data.
    5. For example, an attacker could set `phpCommand` to `php -r "{code}; system('malicious_command');"`. When the extension runs a PHP script, it will execute both the intended code and the attacker's injected command.
  - Impact: Arbitrary PHP code execution on the developer's machine, potentially leading to:
    -  Reading sensitive files from the developer's system.
    -  Modifying or deleting files.
    -  Executing system commands.
    -  Compromising the developer's environment and potentially their accounts if credentials are exposed.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - None. The extension directly uses the `phpCommand` setting without any sanitization or validation.
  - Missing Mitigations:
    - Input sanitization and validation for the `phpCommand` setting. The extension should prevent users from injecting arbitrary commands.
    -  Restrict the characters allowed in the `phpCommand` setting, or escape potentially harmful characters before executing the command.
    -  Display a security warning when the user modifies the `phpCommand` setting, highlighting the risks of arbitrary code execution.
    -  Consider alternative approaches to execute PHP code that do not involve user-configurable commands, if feasible.
  - Preconditions:
    - The attacker needs to convince a developer to open a malicious Laravel project in VSCode and use the Laravel Extra Intellisense extension.
    - The developer must have the Laravel Extra Intellisense extension installed and activated.
    - The attacker must be able to modify the `.vscode/settings.json` file in the malicious Laravel project or convince the developer to manually change their user or workspace settings to include a malicious `phpCommand`.
  - Source Code Analysis:
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
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Retrieves user-configurable phpCommand without sanitization
        let command = commandTemplate.replace("{code}", code); // Vulnerable line: Replaces placeholder with code, but user can inject code outside placeholder
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Vulnerable line: Executes the command, including potentially malicious user-injected parts
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
    - The `runPhp` function retrieves the `phpCommand` from the configuration without any sanitization.
    - It then uses `replace("{code}", code)` which is vulnerable because the user-controlled `commandTemplate` string is not validated and can contain arbitrary commands surrounding the `{code}` placeholder.
    - The `cp.exec(command, ...)` then executes this potentially malicious command string.
  - Security Test Case:
    1. Create a new Laravel project.
    2. Open the project in VSCode and ensure the Laravel Extra Intellisense extension is activated.
    3. In the project's `.vscode/settings.json` file, add or modify the `LaravelExtraIntellisense.phpCommand` setting to:
       ```json
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; file_put_contents('pwned.txt', 'You have been PWNED!'); \""
       ```
    4. Open any PHP or Blade file in the project to trigger the extension's autocompletion features. This will cause the extension to execute a PHP command.
    5. Check the project root directory. A file named `pwned.txt` should be created with the content "You have been PWNED!", demonstrating arbitrary code execution.
    6. Alternatively, to verify more directly in the output, you could modify the command to output to stdout:
       ```json
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; echo 'PWNED!'; \""
       ```
    7. After step 4, check the "Laravel Extra Intellisense" output channel in VSCode. It should contain the "PWNED!" string, confirming code injection.

- Vulnerability Name: PHP Code Injection via Malicious Project Files
  - Description:
    1. The extension executes PHP code to gather autocompletion data by running Laravel commands and parsing project files.
    2. Several providers (`ConfigProvider`, `EloquentProvider`, `RouteProvider`, `TranslationProvider`, `ViewProvider`) use `Helpers.runLaravel` to execute PHP code that interacts with the Laravel application.
    3. The executed PHP code, in some instances, includes file paths or configuration values that are derived from the user's Laravel project.
    4. An attacker can craft a malicious Laravel project where configuration files (e.g., `config/*.php`, `routes/*.php`, `views/*.blade.php`, translation files, model files) or other project files contain PHP code that will be executed when the extension tries to parse them.
    5. For instance, a malicious `config/app.php` could contain PHP code that gets executed when `ConfigProvider` runs `config()->all()`. Similarly, a malicious view file could execute when `ViewProvider` tries to parse view variables.
    6. This allows the attacker to achieve arbitrary PHP code execution when the extension processes the malicious project.
  - Impact: Arbitrary PHP code execution on the developer's machine, potentially leading to:
    -  Reading sensitive files from the developer's system.
    -  Modifying or deleting files.
    -  Executing system commands.
    -  Compromising the developer's environment.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - None. The extension directly executes PHP code within the context of the user's Laravel project without proper isolation or sandboxing.
  - Missing Mitigations:
    - Code review and hardening of all PHP code execution paths within the extension to prevent execution of user-controlled project code.
    - Input sanitization for project file content before processing it in PHP.
    - Implement a secure way to fetch Laravel data without executing potentially harmful project code, for example, by using static analysis where possible instead of runtime execution.
    - Consider running the PHP code in a sandboxed environment to limit the impact of potential code injection.
  - Preconditions:
    - The attacker needs to provide a malicious Laravel project to the developer.
    - The developer must open this malicious Laravel project in VSCode and have the Laravel Extra Intellisense extension activated.
    - The extension must attempt to gather autocompletion data from the malicious project, which is a normal extension function when editing Laravel related files.
  - Source Code Analysis:
    - Multiple files, including `ConfigProvider.ts`, `EloquentProvider.ts`, `RouteProvider.ts`, `TranslationProvider.ts`, `ViewProvider.ts`
    - Example from `ConfigProvider.ts`:
    ```typescript
    loadConfigs() {
        try {
            var self = this;
            Helpers.runLaravel("echo json_encode(config()->all());", "Configs") // Vulnerable line: Executes config()->all() which will load and execute project config files.
                .then(function (result) {
                    var configs = JSON.parse(result);
                    self.configs = self.getConfigs(configs);
                });
        } catch (exception) {
            console.error(exception);
        }
    }
    ```
    - In `ConfigProvider.ts`, the `loadConfigs` function executes `config()->all()` using `Helpers.runLaravel`. If a malicious project contains PHP code in its config files (e.g., `config/app.php`), this code will be executed when `config()->all()` is called. Similar vulnerabilities exist in other providers where project code is executed to gather data (e.g., view parsing, route listing, model attribute retrieval).
  - Security Test Case:
    1. Create a new Laravel project.
    2. Open the project in VSCode and ensure the Laravel Extra Intellisense extension is activated.
    3. Modify the `config/app.php` file in the Laravel project and inject malicious PHP code. For example, add the following code at the beginning of the `config/app.php` file, before the `return` statement:
       ```php
       <?php
       file_put_contents('pwned_config.txt', 'Config PWNED!');
       ```
    4. Open any PHP or Blade file in the project to trigger the extension's autocompletion features. This will cause the `ConfigProvider` to load configurations.
    5. Check the project root directory. A file named `pwned_config.txt` should be created with the content "Config PWNED!", demonstrating arbitrary code execution from within a project configuration file.
    6. To verify via output, modify the injected code:
       ```php
       <?php
       echo "CONFIG PWNED!";
       ```
    7. After step 4, check the "Laravel Extra Intellisense" output channel in VSCode. It should contain "CONFIG PWNED!", confirming code injection via project configuration.
    8. Repeat steps 3-7, but instead, inject PHP code into a view file (e.g., `resources/views/welcome.blade.php`), a route file (`routes/web.php`), or a model file (`app/Models/User.php`) to verify code injection via different project file types processed by other providers. For example, for views, the injected code would be in `resources/views/welcome.blade.php`:
        ```blade
        <?php file_put_contents('pwned_view.txt', 'View PWNED!'); ?>
        ```
        and for routes in `routes/web.php` before `Route::get(...)`:
        ```php
        <?php file_put_contents('pwned_route.txt', 'Route PWNED!'); ?>
        ```
        and for models in `app/Models/User.php` before `class User extends ...`:
        ```php
        <?php file_put_contents('pwned_model.txt', 'Model PWNED!'); ?>
        ```
    9.  After triggering the extension by opening a relevant file type (e.g., Blade file for view, PHP file for route or model), check for `pwned_view.txt`, `pwned_route.txt`, `pwned_model.txt` respectively in the project root to confirm code execution in each case.
