## Vulnerability List

### 1. Command Injection via `phpCommand` configuration

- **Vulnerability Name:** Command Injection via `phpCommand` configuration
- **Description:**
    1. The "Laravel Extra Intellisense" extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code.
    2. This setting is intended to allow customization for different environments, such as Docker or Laravel Sail, by modifying the command prefix (e.g., `docker exec ... php -r`).
    3. However, the extension does not validate or sanitize this user-provided `phpCommand` setting.
    4. A malicious repository can include a `.vscode/settings.json` file that overrides this setting with a crafted command.
    5. When the extension executes PHP code (e.g., to fetch routes, views, or configs for autocompletion), it uses the manipulated `phpCommand`.
    6. If the crafted `phpCommand` contains malicious commands, they will be executed by the system, leading to command injection.

- **Impact:**
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to complete system compromise, data theft, malware installation, and other malicious activities.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The extension directly uses the `phpCommand` setting without any validation or sanitization.
- **Missing Mitigations:**
    - Input validation and sanitization of the `phpCommand` setting.
    - Restricting the allowed characters or command structure in the `phpCommand` setting.
    - Ideally, avoid executing user-provided commands directly. If customization is necessary, provide a safer mechanism, or pre-defined options.
- **Preconditions:**
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a malicious Laravel repository in VSCode that includes a `.vscode/settings.json` file.
    - The malicious `.vscode/settings.json` file must contain a manipulated `LaravelExtraIntellisense.phpCommand` setting with embedded malicious commands.
    - The victim must trigger any feature of the extension that executes PHP code (e.g., by opening a PHP or Blade file, or by typing a function that triggers autocompletion).

- **Source Code Analysis:**
    1. **File: `src/helpers.ts`**
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
        - This line retrieves the `phpCommand` setting from VSCode configuration. If the setting is not defined, it defaults to `"php -r \"{code}\""`.
    4. Line: `let command = commandTemplate.replace("{code}", code);`
        - This line substitutes the `{code}` placeholder in the `commandTemplate` with the PHP code to be executed. **Crucially, there is no sanitization of the `commandTemplate` itself, which is read from user configuration.**
    5. Line: `cp.exec(command, ...)`
        - This line executes the constructed `command` using `child_process.exec`. Because the `command` is built using an unsanitized user-provided setting, it's vulnerable to command injection.

    ```mermaid
    graph LR
        A[VSCode Configuration] --> B{Get phpCommand Setting};
        B --> C[Construct Command Template];
        C --> D{Replace {code} Placeholder};
        D --> E[Execute Command with cp.exec];
        E --> F[System Command Execution];
    ```

- **Security Test Case:**
    1. **Prepare Malicious Repository:**
        - Create a new directory named `malicious-laravel-repo`.
        - Inside `malicious-laravel-repo`, create a directory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json` with the following content:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned_command_injection'"
          }
          ```
        - Create a dummy Laravel project structure (you don't need a fully functional Laravel application, just enough to trigger the extension). For example, create an `artisan` file in `malicious-laravel-repo`.
        - Optionally, create a `routes/web.php` file with some routes to trigger route autocompletion.

    2. **Open Malicious Repository in VSCode:**
        - Open VSCode.
        - Open the `malicious-laravel-repo` directory as a workspace.
        - Ensure the "Laravel Extra Intellisense" extension is installed and activated.

    3. **Trigger Extension Feature:**
        - Open any PHP file or Blade file in the workspace (or create a new one).
        - Trigger any autocompletion feature that relies on executing PHP code. For example, start typing `Route::` in a PHP file to trigger route autocompletion, or type `config('` in a Blade file for config autocompletion.

    4. **Verify Command Injection:**
        - After triggering the autocompletion, check if the file `/tmp/pwned_command_injection` exists on your system.
        - On Linux/macOS, you can use the command `ls /tmp/pwned_command_injection` in the terminal. On Windows, check for the file in `C:\tmp` if `/tmp` is mapped, or adjust the path in `settings.json` accordingly.
        - If the file `/tmp/pwned_command_injection` exists, it confirms that the malicious command injected via `phpCommand` setting was successfully executed, demonstrating command injection.

This vulnerability allows a malicious actor to achieve Remote Code Execution on the machine of any developer who opens a repository containing a crafted `.vscode/settings.json` file and uses the "Laravel Extra Intellisense" extension. This is a critical security flaw.
