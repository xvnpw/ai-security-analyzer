### Vulnerability List:

- Vulnerability Name: Command Injection via `phpCommand` Configuration
- Description:
    1. The "Laravel Extra Intellisense" extension for VS Code allows users to customize the command used to execute PHP code through the `LaravelExtraIntellisense.phpCommand` setting. This is intended for users who need to configure the extension for environments like Docker or Laravel Sail.
    2. The extension uses this user-configurable `phpCommand` setting to execute PHP scripts for analyzing Laravel projects and providing features such as autocompletion for routes, views, configurations, and translations.
    3. The `runPhp` function in `src/helpers.ts` retrieves the `phpCommand` setting and uses it as a template to execute PHP code.  The extension substitutes the placeholder `{code}` in the `phpCommand` template with the PHP code it intends to execute.
    4.  Critically, the extension does not perform sufficient sanitization or validation of the `phpCommand` setting itself before executing commands.  This allows a malicious user or an attacker who can modify the user's VS Code settings to inject arbitrary system commands into the `phpCommand` configuration.
    5.  When the extension subsequently attempts to gather project information or provide autocompletion, it executes the configured `phpCommand` with the generated PHP code. Due to the lack of sanitization, any injected commands within the `phpCommand` setting will be executed by the system shell.
    6.  The `child_process.exec` function in Node.js is used to execute the constructed command string, which inherently runs commands in a shell environment, making it susceptible to command injection if the command string is not carefully controlled.
    7.  This vulnerability can be exploited if an attacker can trick a user into manually changing the `phpCommand` setting, convince them to open a workspace with a malicious `.vscode/settings.json` file, or compromise the user's VS Code settings synchronization.
- Impact:
    - **Critical**: Successful exploitation allows for arbitrary command execution on the developer's machine with the privileges of the VS Code process.
    - An attacker can gain complete control over the developer's workstation and potentially the Laravel project environment.
    - This can lead to:
        - **Full System Compromise:** Attackers can gain complete control over the developer's machine.
        - **Sensitive Data Theft:** Access and exfiltration of sensitive data, including source code, environment variables, credentials, and other files accessible to the user running VS Code.
        - **Malware Installation:** Installation of viruses, ransomware, or other malicious software.
        - **Lateral Movement:** Using the compromised developer machine as a stepping stone to attack other systems within the developer's network.
        - **Modification of Project Files:** Injecting backdoors or malicious code directly into the Laravel project.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - **Security Note in README.md:** The extension's `README.md` file contains a "Security Note" section that warns users about the potential risks of executing their Laravel application automatically and periodically. It advises users to be cautious and temporarily disable the extension if they are working with sensitive code in service providers.
        - Location: `README.md` file.
        - Effectiveness: Low. This is a documentation-level mitigation only and relies on users reading and understanding the security implications. It does not prevent users from making insecure configurations.
- Missing mitigations:
    - **Input Validation and Sanitization for `phpCommand`:** Implement strict validation and sanitization for the `phpCommand` setting to prevent the injection of malicious commands. This could include:
        - **Whitelisting allowed commands or command components:** Restricting the `phpCommand` to only accept `php` or similar safe executables and a limited set of safe options.
        - **Parameter sanitization:** Ensuring that the `{code}` parameter is properly escaped and that no additional commands can be injected around it.
        - **Command parsing and verification:** Analyzing the configured command to ensure it conforms to expected patterns and does not contain suspicious elements.
        - **Disallowing shell metacharacters:** Preventing the use of shell metacharacters that could be used for command injection within the `phpCommand` setting.
    - **Warning Message on `phpCommand` Modification:** Display a prominent warning message within VS Code when a user modifies the `phpCommand` setting, highlighting the security risks involved and advising caution. This warning should:
        - Be displayed directly in VSCode when the setting is changed.
        - Clearly explain the potential for arbitrary command execution.
        - Recommend using only trusted and necessary commands.
        - Link to a detailed security note in the extension's documentation.
    - **Secure Command Execution Methods:** Instead of using `child_process.exec` with a user-configurable command string, consider safer alternatives such as:
        - Using `child_process.spawn` with arguments array instead of a command string to reduce shell injection risks.
        - Restricting the configurable parts of the command to only the PHP executable path, and hardcoding the `-r "{code}"` part to prevent modification of the command structure.
        - Sandboxing the PHP execution environment to limit the impact of potential vulnerabilities, although this may be complex to implement effectively for a VS Code extension.
    - **Principle of Least Privilege:**  While not directly mitigating the RCE, ensure the extension operates with the minimum necessary privileges. However, this is less applicable to command injection vulnerability itself in this context.
- Preconditions:
    1. **Extension Installation:** The user must have the "Laravel Extra Intellisense" extension installed in VS Code.
    2. **Laravel Project Opened:** The user must have a Laravel project opened in VS Code.
    3. **Configuration Modification:** An attacker needs to be able to modify the `LaravelExtraIntellisense.phpCommand` setting. This could be achieved through:
        - **Social Engineering:** Tricking the developer into manually changing the setting, for example, by providing seemingly helpful configuration instructions that include a malicious command.
        - **Malicious Workspace Settings:**  A malicious user provides a Laravel project with a `.vscode/settings.json` file that contains a malicious `phpCommand`. If the developer opens this project and trusts workspace settings, the malicious command will be configured.
        - **Settings Synchronization Compromise:** If VS Code settings synchronization is enabled and an attacker compromises the user's settings synchronization account, they could modify the `phpCommand` remotely.
        - **Local Access:** If the attacker has local access to the developer's machine, they can directly modify the workspace or user settings.
- Source code analysis:
    1. **File: `src/helpers.ts`**
    2. **Function: `runPhp(code: string, description: string|null = null)`**
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [Vulnerable Line 1]: Retrieves phpCommand config without validation
        let command = commandTemplate.replace("{code}", code); // [Vulnerable Line 2]: Constructs command by simple string replacement
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [Vulnerable Line 3]: Executes command without sanitization
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) { ... }
            );
        });
        return out;
    }
    ```
    - **Analysis:**
        - **Line 10:** `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - This line retrieves the `phpCommand` setting directly from the VS Code configuration without any validation or sanitization. It uses a default value `"php -r \"{code}\""` if the setting is not configured.
        - **Line 11:** `let command = commandTemplate.replace("{code}", code);` - This line constructs the final command string by simply replacing the `{code}` placeholder in the `commandTemplate` with the provided `$code` argument. There is no escaping or sanitization of the `commandTemplate` itself.
        - **Line 16:** `cp.exec(command, ...)` - This line executes the constructed `command` using `child_process.exec`.  `cp.exec` executes a command in a shell, which makes it vulnerable to command injection if the `command` string is not carefully controlled, especially when parts of it are derived from user configuration, as is the case with `phpCommand`. The basic escaping performed on the `$code` argument is insufficient to prevent injection if the `phpCommand` itself is malicious.
    3. **File: `src/helpers.ts`**
    4. **Function: `runLaravel(code: string, description: string|null = null)`**
    - The `runLaravel` function constructs a PHP script that bootstraps a Laravel application and then executes the provided `code` within the Laravel environment. It then calls `runPhp` to execute this constructed PHP script, inheriting the command injection vulnerability from `runPhp`.
    5. **Provider Files (e.g., `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, etc.):** These files use `Helpers.runLaravel()` or indirectly `Helpers.runPhp` to execute PHP code for data gathering, making them all potential triggers for the command injection vulnerability.

- Security test case:
    1. **Prerequisites:**
        - VS Code installed with the "Laravel Extra Intellisense" extension.
        - A Laravel project opened in VS Code.
    2. **Modify `phpCommand` setting:**
        - Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS).
        - Search for `LaravelExtraIntellisense.phpCommand`.
        - In "Workspace Settings" or "User Settings", override the default `phpCommand` with a malicious command. For example, to execute `calc.exe` on Windows or `gnome-calculator` on Linux, use:
            - Windows: `php -r "{code}; system('calc.exe');"`
            - Linux: `php -r "{code}; system('gnome-calculator');"`
        - Alternatively, for a less intrusive test, to create a file, use:
            - Linux/macOS: `bash -c "touch /tmp/pwned_laravel_extension"`
            - Windows Powershell: `powershell -c "New-Item -ItemType File -Path C:\pwned_laravel_extension.txt"`
    3. **Trigger extension functionality:**
        - Open any PHP or Blade file in your Laravel project.
        - Trigger any autocompletion feature provided by the extension that relies on PHP execution. For example, in a Blade file, type `route('` or `config('` or `trans('`.
    4. **Verify command execution:**
        - **Calculator Example:** If the vulnerability is successfully triggered, the calculator application (`calc.exe` or `gnome-calculator`) should launch.
        - **File Creation Example:** Check if the file `/tmp/pwned_laravel_extension` (Linux/macOS) or `C:\pwned_laravel_extension.txt` (Windows) was created.
    5. **Observe Output:** Check the "Laravel Extra Intellisense" output channel (View -> Output -> Laravel Extra Intellisense) for any error messages or output related to the command execution, which might provide further confirmation.
    6. **Cleanup:** After testing, remember to revert the `phpCommand` setting back to its default value (`php -r "{code}"`) to avoid further risks.
