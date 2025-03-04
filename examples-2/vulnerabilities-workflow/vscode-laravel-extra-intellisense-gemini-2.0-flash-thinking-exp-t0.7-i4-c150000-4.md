### Vulnerability List

- Vulnerability Name: Command Injection via `phpCommand` configuration
  - Description: The `LaravelExtraIntellisense.phpCommand` setting, which dictates how the extension executes PHP code, is vulnerable to command injection. A malicious actor can craft a workspace configuration file (`.vscode/settings.json`) within a Laravel project that modifies this setting to inject arbitrary commands. When the extension attempts to gather autocompletion data by executing PHP code (using this user-controlled setting), the injected commands will be executed on the victim's machine.
    - Step-by-step trigger:
      1. An attacker creates a malicious Laravel project.
      2. Within the malicious project, the attacker creates or modifies the `.vscode/settings.json` file.
      3. In `.vscode/settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command template, for example: `"bash -c '{code}'`.
      4. The attacker hosts this malicious Laravel project in a public or private repository and lures a victim to open it in VSCode with the "Laravel Extra Intellisense" extension installed.
      5. Once the victim opens the project, the extension automatically attempts to gather Laravel application data to provide autocompletion features (e.g., route, view, config completion).
      6. The extension uses the user-defined `LaravelExtraIntellisense.phpCommand` from `.vscode/settings.json` to execute PHP code.
      7. Because the `phpCommand` is maliciously crafted (e.g., `"bash -c '{code}'"`), the `{code}` placeholder, intended for PHP code, is now interpreted as a part of a bash command.
      8. When the extension executes a function that triggers PHP code execution (like autocompleting routes), the injected bash command (or any other command based on the malicious template) will be executed on the victim's system with the privileges of the VSCode process.
  - Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine, potentially leading to full system compromise, data theft, malware installation, and other malicious activities.
  - Vulnerability Rank: Critical
  - Currently implemented mitigations: None. The extension directly uses the configured `phpCommand` without any sanitization or validation.
  - Missing mitigations:
    - Input sanitization: The extension should sanitize the `phpCommand` configuration to prevent command injection. Ideally, it should validate that the command is a safe PHP execution command and does not contain any malicious code injection points.
    - Parameterized execution: Instead of directly embedding the PHP code into a string and executing it, the extension should use parameterized execution methods if available in Node.js to avoid command injection. However, for `php -r`, this might not be directly applicable.
    - Restrict command template: The extension could restrict the `phpCommand` template to only allow `php -r "{code}"` and disallow any modification of the base command.
    - User warning: Display a prominent warning to the user if a custom `phpCommand` is detected in the workspace settings, highlighting the security risks associated with it.
    - Principle of least privilege: While not directly a mitigation for this vulnerability, running the extension process with the least necessary privileges can limit the impact of successful RCE.
  - Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file.
    - The victim must trigger a feature of the extension that executes PHP code, such as autocompletion for routes, views, or configs.
  - Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` from the extension's configuration. This configuration is user-controlled via workspace settings.
    - Line: `let command = commandTemplate.replace("{code}", code);` -  Constructs the command string by directly replacing `{code}` in the `commandTemplate` with the provided `$code`. No sanitization is performed here.
    - Line: `cp.exec(command, ...)` - Executes the constructed command using `child_process.exec`. This function executes a command in a shell, making it vulnerable to command injection if the command string is not properly sanitized, which is the case here.

    ```
    // Visualization of vulnerable code path in src/helpers.ts -> runPhp
    runPhp(code: string, description: string|null = null) {
      let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [CONFIGURATION INPUT - User Controlled]
      let command = commandTemplate.replace("{code}", code); // [STRING CONCATENATION - Vulnerable Point]
      cp.exec(command, ...) // [COMMAND EXECUTION - Vulnerable Point]
    }
    ```
  - Security test case:
    1. **Setup Malicious Repository:**
       - Create a new directory for the malicious Laravel project, e.g., `malicious-laravel-project`.
       - Inside `malicious-laravel-project`, create a `.vscode` directory.
       - Inside `.vscode`, create a `settings.json` file with the following content to inject a malicious command into `phpCommand`:
         ```json
         {
             "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/rce_vulnerability_confirmed_{code_type}.txt'"
         }
         ```
         Replace `{code_type}` with a descriptive name to identify which feature triggered the vulnerability, e.g., `route`, `view`, `config`. For example, for route completion, use `rce_vulnerability_confirmed_route.txt`.
       - Initialize a basic Laravel project within `malicious-laravel-project` (you don't need a fully functional Laravel app, just the basic structure so the extension activates). `composer create-project --prefer-dist laravel/laravel:^9.0 .` (or any Laravel version).
    2. **Open Malicious Repository in VSCode:**
       - Open VSCode and open the `malicious-laravel-project` folder.
       - Ensure the "Laravel Extra Intellisense" extension is installed and activated.
    3. **Trigger Autocompletion Feature:**
       - Open any PHP file within the project (e.g., `routes/web.php`).
       - In the PHP file, type `Route::get('test', function () { ` and then try to trigger route name autocompletion by typing `route('`.
       - Observe if a file named `/tmp/rce_vulnerability_confirmed_route.txt` (or similar based on your `{code_type}`) is created. This indicates successful command injection because the `touch` command was executed due to the malicious `phpCommand` configuration and the extension's attempt to run PHP code for autocompletion.
    4. **Verify RCE:**
       - Check if the file `/tmp/rce_vulnerability_confirmed_route.txt` exists. If it does, the command injection vulnerability is confirmed, demonstrating Remote Code Execution.
       - For different features (view, config, etc.), repeat step 3 by triggering the corresponding autocompletion and adjust the `{code_type}` in the malicious `settings.json` and filename to verify the vulnerability across different extension features.
