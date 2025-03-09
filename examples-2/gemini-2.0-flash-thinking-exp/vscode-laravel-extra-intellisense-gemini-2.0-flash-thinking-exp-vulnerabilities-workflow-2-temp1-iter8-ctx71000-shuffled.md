## Combined Vulnerability List

### Remote Code Execution via `phpCommand` Configuration

- **Vulnerability Name:** Remote Code Execution via `phpCommand` Configuration
- **Description:**
    - The "Laravel Extra Intellisense" VS Code extension allows users to customize the `phpCommand` setting, which dictates the command used by the extension to execute PHP code for gathering information about Laravel projects, such as routes, configurations, and views, to enhance autocompletion features.
    - This setting is intended for advanced configurations, especially in environments like Docker or Laravel Sail, where the PHP executable might not be directly accessible via the system's default PATH.
    - However, the extension retrieves and uses this user-provided `phpCommand` setting without proper sanitization or validation.
    - A malicious actor can exploit this by crafting a malicious workspace configuration file (`.vscode/settings.json`) within a Laravel project or by tricking a user into modifying their user settings. This malicious configuration modifies the `phpCommand` setting to inject arbitrary system commands alongside the intended PHP execution.
    - When the extension subsequently attempts to gather project data – a process that can be triggered automatically when opening a Laravel project or editing relevant files – it executes the configured `phpCommand`.
    - Due to the lack of sanitization, the injected system commands embedded within the `phpCommand` are executed on the developer's machine with the privileges of the VS Code process. This effectively allows for remote code execution.
- **Impact:**
    - **Critical:** Successful exploitation of this vulnerability results in arbitrary code execution (RCE) on the developer's machine. The impact can be severe and may include:
        - **Complete System Compromise:** An attacker gains the ability to execute arbitrary commands, potentially leading to full control over the developer's workstation.
        - **Data Theft:** Sensitive information, including project source code, environment variables, API keys, credentials, and personal data stored on the machine or accessible from it, can be stolen.
        - **Malware Installation:** Attackers can install malware, ransomware, spyware, or backdoors, leading to persistent compromise and further malicious activities.
        - **Lateral Movement:** In networked environments, a compromised developer machine can be used as a stepping stone to attack internal networks and other systems.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** The extension's `README.md` file contains a "Security Note" section. This note serves as a documentation-level warning, advising users that the extension executes their Laravel application code and suggesting temporary disabling of the extension when working with sensitive code, particularly in service providers.
        - **Location:** `README.md` file in the extension's repository.
        - **Effectiveness:** This is a weak mitigation as it relies solely on user awareness and does not prevent the vulnerability technically. It is essentially security by warning and easily overlooked.
- **Missing Mitigations:**
    - **Input Sanitization and Validation for `phpCommand`:** The extension must implement robust input sanitization and validation for the `phpCommand` setting. This should include:
        - **Allowlisting Safe Characters:** Restricting the allowed characters in the `phpCommand` to a safe subset, preventing the use of shell metacharacters, command separators, and other potentially dangerous elements.
        - **Command Structure Validation:** Validating the overall structure of the command to ensure it adheres to an expected format (e.g., starting with `php` and followed by allowed options).
        - **Parameter Escaping:** If dynamic parts of the command are necessary, proper parameter escaping should be implemented to prevent command injection. However, given the user-controlled nature of the entire command template, sanitization might be more effective than complex escaping.
    - **Warning Message on `phpCommand` Modification:** The extension should display a prominent warning message to the user within VS Code when they attempt to modify the `phpCommand` setting, especially if the new setting deviates from the default or contains suspicious patterns or keywords associated with shell commands (e.g., `system`, `exec`, `bash`, `sh`, `|`, `&`, `;`, `>`, `<`).
    - **Principle of Least Privilege and Sandboxed Execution:** Explore alternatives to `child_process.exec` or methods to sandbox the execution environment for PHP commands. Consider:
        - **Restricting Command Path:** Hardcoding or strictly validating the path to the `php` executable to prevent the execution of arbitrary or malicious binaries.
        - **Sandboxing the PHP Execution:** Running the PHP commands in a more isolated environment, such as a container or a virtual machine, could limit the potential impact of command injection.
    - **User Awareness Enhancement:** Improve the prominence and explicitness of the security warning in the README.md and consider displaying a security warning directly within VS Code upon extension activation if a non-default `phpCommand` is configured.
- **Preconditions:**
    - The victim must have the "Laravel Extra Intellisense" VS Code extension installed and enabled.
    - The attacker needs to be able to modify the VS Code settings configuration that the victim uses for a Laravel project. This can be achieved through:
        - **Malicious Workspace Configuration:** Crafting a malicious Laravel project with a `.vscode/settings.json` file that contains a compromised `phpCommand` setting. The attacker could then distribute this project to the victim (e.g., via social engineering, compromised repository).
        - **Social Engineering:** Tricking the user into manually modifying their user or workspace settings to a malicious `phpCommand` value.
        - **Compromised Settings Synchronization:** If the victim uses VS Code settings synchronization, compromising the victim's settings sync account could allow the attacker to inject malicious settings.
- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `runPhp(code: string, description: string|null = null)`
    - **Code Snippet (Vulnerable Section):**
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

                cp.exec(command, // Vulnerable line: Executes command constructed from user-provided 'phpCommand'
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
    - **Analysis:**
        1. **Configuration Retrieval:** The `runPhp` function retrieves the `phpCommand` setting from VS Code configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. If no custom setting is found, it defaults to `"php -r \"{code}\""`.
        2. **Command Construction:** It constructs the command to be executed by replacing the `{code}` placeholder in the `commandTemplate` with the PHP code provided as the `code` argument.
        3. **Vulnerable Execution:** The constructed `command` is then passed directly to `cp.exec(command, ...)`. The `cp.exec` function executes commands within a system shell, which is susceptible to command injection if the command string, derived from the user-controlled `phpCommand` setting, is not properly sanitized.
        4. **Lack of Sanitization:** There is no validation or sanitization of the `phpCommand` setting before it is used in `cp.exec`. The minimal escaping performed on the `$code` is insufficient to prevent command injection when the entire command template is user-configurable.

    ```
    // Visualization of code execution flow in `helpers.ts` -> `runPhp`

    +---------------------+      getConfiguration('phpCommand')      +-----------------------+      replace("{code}", code)     +------------------------+      cp.exec(command, ...)     +--------------------+
    | VS Code Configuration |----------------------------------------->| helpers.ts - runPhp() |----------------------------------->|  helpers.ts - runPhp()  |----------------------------->| System Shell (bash/cmd) |
    +---------------------+                                           +-----------------------+                                   +------------------------+                                +--------------------+
        ^
        | User-controlled via .vscode/settings.json or User Settings
        +---------------------------------------------------------------------------------------------------------------------------+
    ```

- **Security Test Case:**
    1. **Prerequisites:**
        - VS Code installed with the "Laravel Extra Intellisense" extension.
        - A Laravel project opened in VS Code.
    2. **Attacker Setup (for Workspace Setting Test):**
        - Create a new Laravel project (or use an existing one for testing, but be mindful of potential risks).
        - Create a `.vscode` directory in the project root.
        - Create a `settings.json` file within `.vscode` with the following content:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r '{code}' && touch /tmp/vscode_extension_pwned"
            }
            ```
            (Adjust the command for Windows if needed, e.g., `cmd /c 'php -r "{code}" && echo pwned > C:\\Temp\\vscode_extension_pwned.txt'`)
    3. **Victim Action:**
        - Open the Laravel project in VS Code.
        - Wait for the Laravel Extra Intellisense extension to activate (or trigger autocompletion, e.g., by opening a Blade file and typing `@route(`).
    4. **Verification:**
        - Check for the existence of the file `/tmp/vscode_extension_pwned` (or `C:\Temp\vscode_extension_pwned.txt` on Windows or the path used in your malicious command) on the victim's machine.
        - If the file exists, it confirms that the injected command `touch /tmp/vscode_extension_pwned` was executed, demonstrating successful Remote Code Execution.
    5. **Alternative Test (User Setting Modification):**
        - Instead of using workspace settings, manually modify the User Settings in VS Code (File -> Preferences -> Settings or Code -> Settings -> Settings) and set `LaravelExtraIntellisense.phpCommand` to the malicious command (e.g., `"php -r 'system(\"calc.exe\"); {code}'"`). Then, open any Laravel project and trigger extension features to observe `calc.exe` launching.

---

### Arbitrary PHP Code Execution via Malicious Laravel Project Files

- **Vulnerability Name:** Arbitrary PHP Code Execution via Malicious Laravel Project Files
- **Description:**
    - The "Laravel Extra Intellisense" extension, to provide its features, automatically executes PHP code within the context of the opened Laravel project. This is achieved by bootstrapping the Laravel application and then executing specific PHP snippets to gather data (routes, configurations, etc.).
    - A malicious actor can exploit this behavior by crafting a malicious Laravel project. Within this project, the attacker modifies legitimate project files that are parsed and executed during the Laravel application's bootstrap process. Common files include route files (`routes/web.php`, `routes/api.php`), configuration files (`config/app.php`), service providers, or even the main `bootstrap/app.php` file.
    - The attacker injects arbitrary PHP code into these files. This injected code could range from simple commands like `system('calc.exe')` to more sophisticated malicious payloads designed for data exfiltration, system compromise, or establishing persistence.
    - When a developer opens this maliciously crafted Laravel project in VS Code with the "Laravel Extra Intellisense" extension installed and active, the extension, upon activation or when triggered by user actions (like opening project files or attempting autocompletion), automatically bootstraps the Laravel application.
    - During this bootstrap process, the modified project files, now containing the attacker's malicious PHP code, are loaded and executed by the PHP interpreter.
    - This results in the execution of arbitrary PHP code on the developer's machine with the privileges of the VS Code process, simply by opening a malicious project.
- **Impact:**
    - **Critical:** Exploitation leads to arbitrary PHP code execution on the developer's machine, which can be leveraged for:
        - **Arbitrary Code Execution:** Attackers can execute any PHP code they inject, gaining significant control over the developer's environment.
        - **Account Compromise:** By injecting code to steal credentials, API keys, or session tokens, attackers can compromise developer accounts and potentially gain access to sensitive systems.
        - **Data Breach:** Malicious code can be designed to exfiltrate sensitive data from the project, the developer's machine, or connected systems.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - **Security Note in README.md:** As with the `phpCommand` vulnerability, the extension's `README.md` includes a "Security Note" that warns users about the extension executing Laravel application code and advises caution, suggesting temporary disabling for sensitive code in service providers.
        - **Location:** `README.md` file in the extension's repository.
        - **Effectiveness:** This is a documentation-level warning only and is not an effective technical mitigation against the vulnerability.
- **Missing Mitigations:**
    - **Sandboxing or Isolation:** Executing the Laravel application bootstrap and data-gathering processes in a sandboxed or isolated environment could significantly limit the impact of malicious code execution from project files.
    - **Code Review and Hardening:** A comprehensive security review of the extension's PHP execution logic is crucial. This includes scrutinizing the extension's own PHP code and the way it interacts with the Laravel project's codebase to minimize the attack surface.
    - **Input Validation and Sanitization (Contextual):** While directly sanitizing project files is not feasible, the extension could potentially implement checks or heuristics to detect potentially malicious patterns or unusual code in project files before executing them, though this would be complex and prone to bypasses.
    - **User Warnings and Project Trust Mechanisms:** VS Code could potentially integrate mechanisms to warn users when opening projects from untrusted sources that contain extensions known to execute code, especially if those extensions interact with project files.
    - **Permissions Reduction:** Ensure that the PHP execution processes run with the minimum necessary privileges to reduce the potential damage from successful exploitation.
- **Preconditions:**
    - The victim must have the "Laravel Extra Intellisense" VS Code extension installed and enabled.
    - The victim must open a maliciously crafted Laravel project in VS Code.
    - The malicious Laravel project must contain injected PHP code in files that are loaded and executed during the Laravel application bootstrap process or when the extension gathers data.
- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `runLaravel(code: string, description: string|null = null)`
    - **Code Snippet (Vulnerable Section):**
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
                        code + // <--- Extension's PHP code is injected here
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
    - **Analysis:**
        1. **Laravel Bootstrap Execution:** The `runLaravel` function constructs a PHP command that is designed to bootstrap a Laravel application. This includes requiring `vendor/autoload.php` and `bootstrap/app.php`, which are standard Laravel bootstrap files.
        2. **Extension Code Injection:** The extension's own PHP code (passed as the `code` argument to `runLaravel`) is injected into the constructed PHP script.
        3. **Execution via `runPhp`:** The complete PHP script, including the Laravel bootstrap and the extension's code, is then executed by calling `this.runPhp(command, description)`.
        4. **Vulnerability:** If a malicious Laravel project contains malicious PHP code within files that are loaded during the bootstrap process (e.g., `routes/web.php`, service providers, `bootstrap/app.php`, etc.), this malicious code will be executed as part of the Laravel application bootstrap initiated by the extension. The vulnerability arises because the extension blindly bootstraps and executes code from the opened project without any prior security checks or sandboxing.

    ```
    // Visualization of code execution flow for Malicious Project Files Vulnerability

    [Developer opens malicious Laravel Project in VSCode] --> [Extension Activation & Data Fetching Trigger]
        |
        V
    [helpers.ts - runLaravel()] --> [Construct PHP command including Laravel Bootstrap and Extension's Code]
        |                                 ^
        |                                 | Laravel Bootstrap Loads Project Files (including malicious files)
        V
    [helpers.ts - runPhp()] --> [Execute PHP command (via php -r)] --> [PHP Interpreter] --> [EXECUTE MALICIOUS CODE FROM PROJECT FILES DURING BOOTSTRAP]
    ```

- **Security Test Case:**
    1. **Setup:**
        - Ensure the "Laravel Extra Intellisense" extension is installed and enabled in VS Code.
        - Create a new Laravel project locally using `composer create-project laravel/laravel malicious-project-test`.
        - Navigate into the `malicious-project-test` directory: `cd malicious-project-test`.
    2. **Inject Malicious Code into Project File:**
        - Modify the `routes/web.php` file within the `malicious-project-test` directory. Add the following PHP code at the top of the file (before any existing `<?php` tag if present, or as the first line):
            ```php
            <?php system('calc.exe'); ?>
            ```
            (For macOS or Linux, use `<?php system('open -a Calculator.app'); ?>` or `<?php system('gnome-calculator'); ?>` or `<?php system('xcalc'); ?>` respectively, depending on your OS and available calculator application.)
    3. **Open Malicious Project in VS Code:**
        - Open VS Code.
        - Open the `malicious-project-test` folder in VS Code (File -> Open Folder...).
    4. **Trigger Extension Activation (if needed):**
        - In most cases, simply opening the project is enough. If not, try opening any PHP file in the project (e.g., `routes/web.php` itself) to encourage the extension to activate and start its background processes.
    5. **Observe Code Execution:**
        - Watch for the calculator application (`calc.exe`, `Calculator.app`, `gnome-calculator`, or `xcalc`) to launch on your system.
        - If the calculator application starts, it confirms that the `system('calc.exe')` (or equivalent) command injected into `routes/web.php` was successfully executed when the extension bootstrapped the Laravel application. This demonstrates Arbitrary PHP Code Execution via Malicious Laravel Project Files.
    6. **Cleanup:**
        - Close VS Code.
        - Delete the `malicious-project-test` directory to remove the test project.
