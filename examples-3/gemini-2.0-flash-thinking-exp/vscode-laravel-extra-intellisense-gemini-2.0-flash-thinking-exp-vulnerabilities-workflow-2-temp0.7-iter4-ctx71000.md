## Combined Vulnerability List

### 1. Remote Code Execution via Malicious Laravel Project

- **Vulnerability Name:** Remote Code Execution via Malicious Laravel Project
- **Description:**
    1. An attacker compromises a Laravel project by injecting malicious PHP code into a file that is included during the Laravel bootstrap process. This could be achieved by compromising a dependency, or by tricking a developer into cloning a malicious repository. Example injection points include service providers, configuration files, or models.
    2. A developer opens this compromised Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    3. The extension, in order to provide autocompletion features, executes PHP code from the opened Laravel project. This is done to gather information about routes, views, configurations, and other Laravel-specific data. The extension uses the configured `phpCommand` setting to execute PHP code.
    4. Due to the project being compromised, the injected malicious PHP code is executed on the developer's machine as part of the extension's normal operation of collecting autocompletion data.
    5. The attacker achieves Remote Code Execution (RCE) on the developer's machine with the privileges of the VSCode process.
- **Impact:** Remote Code Execution (RCE) on the developer's machine. Successful exploitation allows an attacker to execute arbitrary commands on the developer's system. This could lead to serious consequences, including but not limited to:
    - Stealing sensitive data, such as API keys, credentials, and source code.
    - Modifying project files or system configurations.
    - Installing malware or backdoors.
    - Pivoting to internal networks if the developer's machine is connected to one.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - Security Note in `README.md`: The extension's `README.md` file includes a "Security Note" that warns users about the extension running their Laravel application automatically and periodically. It advises users to be cautious and temporarily disable the extension when working with sensitive code or if they observe unknown errors in their logs. This mitigation is insufficient as it relies solely on the user's awareness and manual action, and does not prevent the vulnerability from being exploited.
- **Missing Mitigations:**
    - Code Sandboxing or Isolation: Implement sandboxing for the PHP execution environment. Run the PHP code in a restricted environment with limited permissions to minimize the impact of potential RCE. This could involve using containers or other isolation techniques.
    - Static Analysis Fallback: Where feasible, implement static analysis as a fallback mechanism. Attempt to parse Laravel project files statically to extract information (e.g., routes, views) without executing PHP code. This could reduce reliance on dynamic execution, although it might not be possible for all features.
    - User Confirmation: Implement a user confirmation prompt when the extension is activated in a new workspace or when it detects significant changes in the project's configuration. This prompt should warn the user about the potential risks of executing project code and ask for explicit permission before enabling full functionality.
    - Code Review and Hardening: Conduct a thorough code review of the extension, specifically focusing on the `Helpers.runLaravel` function and all completion providers that use it. Harden the code to prevent any unintended code injection vulnerabilities within the extension itself.
- **Preconditions:**
    - The "Laravel Extra Intellisense" extension must be installed and activated in VSCode.
    - The developer must open a compromised Laravel project in VSCode.
    - The attacker must have the ability to modify files within the Laravel project's directory.
- **Source Code Analysis:**
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
- **Security Test Case:**
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
    3. Trigger Extension Activity:
        - Open the modified Laravel project in VSCode.
        - Allow the "Laravel Extra Intellisense" extension to initialize and perform its routine tasks of gathering autocompletion data.
    4. Verify Code Execution:
        - After a short period, check if the file `/tmp/pwned_by_laravel_intellisense` has been created on your system using `ls /tmp/pwned_by_laravel_intellisense` (Linux/macOS) or checking `C:\tmp` (Windows).
    5. Expected Result:
        - If the file `/tmp/pwned_by_laravel_intellisense` is successfully created, this confirms the Remote Code Execution vulnerability.

### 2. Command Injection via `phpCommand` Configuration

- **Vulnerability Name:** Command Injection via `phpCommand` Configuration
- **Description:**
    1. The "Laravel Extra Intellisense" extension uses a user-configurable setting `phpCommand` to execute PHP code for gathering autocompletion data from Laravel projects. The default value is `php -r "{code}"`.
    2. The extension directly substitutes the `{code}` placeholder in the configured `phpCommand` with generated PHP code without sufficient sanitization.
    3. An attacker can craft a malicious `phpCommand` configuration that injects shell commands by including shell metacharacters (e.g., `$(...)`, `;`, `&&`, `||`) within the setting. Alternatively, a user might unknowingly configure a vulnerable command like `php -r 'system($_GET["cmd"]); {code}'`.
    4. When the extension executes PHP code using this malicious `phpCommand`, the injected shell commands will also be executed on the developer's machine, or in the case of vulnerable PHP commands, they become exploitable via other means.
    5. This can be triggered automatically and periodically as the user works in a Laravel project, whenever the extension attempts to use `phpCommand` to gather information for autocompletion.
- **Impact:**
    - **Remote Code Execution (RCE):** Successful exploitation allows the attacker to execute arbitrary commands on the developer's machine with the same privileges as the VSCode process.
    - This can lead to:
        - Data Theft: Access to sensitive files, environment variables, and credentials.
        - System Compromise: Installation of malware, backdoors, or ransomware.
        - Lateral Movement: Potential to pivot to other systems accessible from the developer's machine.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - Security Note in `README.md`: The README.md includes a "Security Note" that warns users about the extension running their Laravel application and suggests caution. This is a documentation-level mitigation and does not prevent the vulnerability. There are no code-level mitigations.
- **Missing Mitigations:**
    - Input Sanitization and Validation: Validate the `phpCommand` configuration to ensure it adheres to a safe format and sanitize or escape the `{code}` parameter before embedding it into the `phpCommand` to prevent command injection.
    - Parameterization/Escaping: Use parameterized queries or properly escape shell arguments when constructing the command to be executed by `cp.exec` instead of direct string substitution.
    - Principle of Least Privilege: Explore running PHP commands with reduced privileges if possible.
    - Configuration Warnings: Display prominent security warnings within VSCode when the extension is activated with a potentially insecure `phpCommand` configuration.
- **Preconditions:**
    1. Malicious `phpCommand` Configuration: An attacker needs to influence the user to set a malicious `phpCommand` configuration, potentially through social engineering or malicious workspace settings.
    2. Extension Activation: The "Laravel Extra Intellisense" extension must be activated in a Laravel project in VSCode.
- **Source Code Analysis:**
    1. `src/helpers.ts` - `runPhp` function:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Inadequate escaping
            if (['linux', ...].some(...)) {
                code = code.replace(/\$/g, "\\$"); // Inadequate escaping
                code = code.replace(/\\\\'/g, '\\\\\\\\\''); // Fragile escaping attempts
                code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // Fragile escaping attempts
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // Vulnerable substitution
            cp.exec(command, ...); // Command execution
            return ...;
        }
        ```
        - The `runPhp` function retrieves and uses the `phpCommand` configuration insecurely. The escaping attempts are insufficient to prevent command injection. The direct substitution of `{code}` into the command string is the core issue.
- **Security Test Case:**
    1. Prerequisites: VSCode with "Laravel Extra Intellisense" and a Laravel project.
    2. Vulnerable Configuration: Modify the `phpCommand` setting to: `"php -r $\"system('whoami > /tmp/vscode_vuln.txt 2>&1'); {code}\""`.
    3. Trigger Extension Activity: Open a PHP or Blade file and trigger autocompletion (e.g., type `route('`).
    4. Verify Command Execution: Check if `/tmp/vscode_vuln.txt` is created and contains the output of `whoami` using `cat /tmp/vscode_vuln.txt`. The existence of the file and username confirms the command injection.
