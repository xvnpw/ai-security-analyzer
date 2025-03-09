- Vulnerability Name: Remote Code Execution via Malicious Laravel Project
- Description:
    1. An attacker compromises a Laravel project by injecting malicious PHP code into a file that is included during the Laravel bootstrap process. This could be achieved by compromising a dependency, or by tricking a developer into cloning a malicious repository. Example injection points include service providers, configuration files, or models.
    2. A developer opens this compromised Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    3. The extension, in order to provide autocompletion features, executes PHP code from the opened Laravel project. This is done to gather information about routes, views, configurations, and other Laravel-specific data. The extension uses the configured `phpCommand` setting to execute PHP code.
    4. Due to the project being compromised, the injected malicious PHP code is executed on the developer's machine as part of the extension's normal operation of collecting autocompletion data.
    5. The attacker achieves Remote Code Execution (RCE) on the developer's machine with the privileges of the VSCode process.
- Impact: Remote Code Execution (RCE) on the developer's machine. Successful exploitation allows an attacker to execute arbitrary commands on the developer's system. This could lead to serious consequences, including but not limited to:
    - Stealing sensitive data, such as API keys, credentials, and source code.
    - Modifying project files or system configurations.
    - Installing malware or backdoors.
    - Pivoting to internal networks if the developer's machine is connected to one.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Security Note in README.md: The extension's README.md file includes a "Security Note" that warns users about the extension running their Laravel application and advises them to disable the extension if they are writing sensitive code in service providers or encounter unknown errors in logs. This is a documentation-level warning and not a technical mitigation.
- Missing Mitigations:
    - Code Sandboxing or Isolation: The extension currently executes PHP code directly within the user's environment without any sandboxing or isolation. Implementing a secure sandbox or isolation mechanism for the PHP execution environment could limit the impact of malicious code.
    - Input Sanitization/Validation of `phpCommand`: While potentially complex, sanitizing or validating the `phpCommand` configuration could offer some protection. However, this is difficult because users might require flexible commands, especially when using Docker or other containerized environments.
    - User Confirmation for Code Execution: Requiring explicit user confirmation before executing PHP code from the Laravel project could act as a preventative measure. However, this would likely disrupt the intended seamless autocompletion experience of the extension.
    - Static Code Analysis: Implementing static code analysis to detect potentially malicious code within the Laravel project before execution could be explored. However, this is a complex undertaking and might lead to both false positives and false negatives.
- Preconditions:
    - The "Laravel Extra Intellisense" extension must be installed and activated in VSCode.
    - The developer must open a compromised Laravel project in VSCode.
    - The attacker must have the ability to modify files within the Laravel project's directory.
- Source Code Analysis:
    1. `src/helpers.ts`:
        - `Helpers.runPhp(code: string, description: string|null = null)`: This function is responsible for executing arbitrary PHP code. It takes a string `code` as input and uses `child_process.exec` to run this code using the `phpCommand` setting from the extension's configuration. This configuration is user-defined, and the code is executed without any sanitization or security checks on the provided PHP code itself.
        - `Helpers.runLaravel(code: string, description: string|null = null)`: This function constructs a complete Laravel bootstrapping environment within a PHP script. It includes the user's project's `vendor/autoload.php` and `bootstrap/app.php` files. It then registers a service provider and executes the provided PHP code snippet (`code`) within this Laravel application context. It uses `Helpers.runPhp` to perform the actual execution.
    2. `src/extension.ts`:
        - The `activate` function in `extension.ts` is the entry point of the extension. It registers various completion item providers such as `RouteProvider`, `ViewProvider`, `ConfigProvider`, etc.
        - These providers are designed to enhance the developer experience by providing autocompletion for Laravel-specific features.
    3. Provider Files (`src/ConfigProvider.ts`, `src/RouteProvider.ts`, `src/ViewProvider.ts`, etc.):
        - Files like `ConfigProvider.ts`, `RouteProvider.ts`, and `ViewProvider.ts` contain methods (e.g., `loadConfigs`, `loadRoutes`, `loadViews`) that are responsible for fetching data required for autocompletion.
        - These methods use `Helpers.runLaravel` to execute PHP code within the user's Laravel project. For example, `ConfigProvider.loadConfigs` executes `Helpers.runLaravel("echo json_encode(config()->all());", "Configs")` to retrieve all Laravel configurations. Similarly, other providers execute PHP code to fetch routes, views, translations, etc.
        - The vulnerability arises because the extension blindly executes PHP code from the potentially compromised Laravel project without any security considerations beyond a warning in the documentation. If a malicious actor can inject PHP code into the Laravel project, this code will be executed by the extension during its normal operation.
- Security Test Case:
    1. Setup:
        - Create a new Laravel project (or use an existing one for testing purposes, ensuring you back up any important data).
        - Install the "Laravel Extra Intellisense" extension in VSCode and activate it.
    2. Inject Malicious Code:
        - Modify the `app/Providers/AppServiceProvider.php` file in your Laravel project. Within the `boot` method of the `AppServiceProvider`, add the following malicious PHP code:
          ```php
          public function boot()
          {
              if (function_exists('exec')) {
                  exec('touch /tmp/pwned_by_laravel_intellisense');
              }
          }
          ```
          This code snippet attempts to create a file named `pwned_by_laravel_intellisense` in the `/tmp/` directory of the system when the Laravel application boots. The `function_exists('exec')` check is added for robustness, ensuring the code only runs if the `exec` function is available in the PHP environment.
    3. Trigger Extension Activity:
        - Open the modified Laravel project in VSCode.
        - Allow the "Laravel Extra Intellisense" extension to initialize and perform its routine tasks of gathering autocompletion data. This usually happens automatically when you open a Laravel project. You can also trigger it by opening a PHP or Blade file in the project, which might prompt the extension to refresh its data.
    4. Verify Code Execution:
        - After a short period (give the extension time to run its background tasks), check if the file `/tmp/pwned_by_laravel_intellisense` has been created on your system.
        - On Linux/macOS, you can use the command `ls /tmp/pwned_by_laravel_intellisense` in the terminal. On Windows, check the `C:\tmp` directory if it exists, or another temporary directory.
    5. Expected Result:
        - If the file `/tmp/pwned_by_laravel_intellisense` is successfully created, this confirms that the malicious PHP code injected into `AppServiceProvider.php` was executed by the "Laravel Extra Intellisense" extension. This demonstrates the Remote Code Execution vulnerability, as arbitrary code injected into the Laravel project is executed on the developer's machine by the extension.
