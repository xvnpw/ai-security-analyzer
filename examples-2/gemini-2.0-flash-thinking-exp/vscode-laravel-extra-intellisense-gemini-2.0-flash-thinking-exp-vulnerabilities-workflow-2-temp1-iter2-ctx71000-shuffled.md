### Arbitrary Command Execution via `phpCommand` Configuration

- **Vulnerability Name:** Arbitrary Command Execution via `phpCommand` Configuration

- **Description:**
    - The extension executes PHP code to provide Laravel intellisense features. To do this, it uses the `child_process.exec` function in `helpers.ts` to run PHP commands in the workspace.
    - The specific command used for executing PHP is configurable through the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to allow users to customize the PHP execution command for different environments, such as Docker or Laravel Sail.
    - A malicious Laravel project can include a `.vscode/settings.json` file within the `.vscode` directory in the project root. This file allows for workspace-specific settings to be defined, and it can override user settings for the opened project.
    - By crafting a malicious `.vscode/settings.json` file, an attacker can override the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary system commands.
    - When a developer opens this specially crafted Laravel project in VSCode, and the "Laravel Extra Intellisense" extension activates and attempts to gather data for autocompletion, it will use the attacker-controlled `phpCommand` setting.
    - This results in the execution of arbitrary commands on the developer's machine with the privileges of the VSCode process, effectively leading to arbitrary code execution.

- **Impact:**
    - Arbitrary code execution on the developer's machine.
    - This can allow an attacker to perform various malicious actions, such as:
        - Stealing sensitive data from the developer's machine or the opened project.
        - Installing malware, backdoors, or ransomware.
        - Modifying or deleting project files.
        - Tampering with the developer's environment for further attacks.
        - Compromising the developer's system and potentially pivoting to internal networks.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The extension code does not implement any input validation or sanitization of the `phpCommand` setting.
    - The `README.md` file includes a "Security Note" that warns users about the extension executing their Laravel application and suggests temporarily disabling the extension when working with sensitive code in service providers. However, this is a documentation note and not a technical mitigation, and it does not prevent the vulnerability.

- **Missing Mitigations:**
    - Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting. The extension should validate or sanitize the configured command to ensure it only allows safe PHP execution and prevents the injection of arbitrary commands. For example, it could verify that the command starts with `php` and only contains expected arguments, disallowing shell redirection or command chaining.
    - Display a warning to the user when the extension detects that the `LaravelExtraIntellisense.phpCommand` setting has been overridden by workspace settings, especially if it deviates from the default expected command. This can alert the developer to a potential security risk in the opened project.
    - Consider using `child_process.spawn` with individual command arguments instead of `child_process.exec` with a full shell command string. This can reduce the risk of command injection, even though the primary vulnerability is the user-configurable `phpCommand` itself.

- **Preconditions:**
    - A developer must install the "Laravel Extra Intellisense" VSCode extension.
    - An attacker must be able to create or compromise a Laravel project and add a malicious `.vscode/settings.json` file to it.
    - The developer must open the malicious Laravel project in VSCode.
    - The extension must activate and attempt to gather data, which typically happens when opening PHP or Blade files or when autocompletion is triggered.

- **Source Code Analysis:**
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Line of code: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
    - Line of code: `let command = commandTemplate.replace("{code}", code);`
    - Line of code: `cp.exec(command, ...)`
    - Analysis:
        1. The `runPhp` function retrieves the `phpCommand` setting directly from the VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        2. It uses this `phpCommand` as a template and replaces the `{code}` placeholder with the PHP code to be executed.
        3. Critically, the `command` variable, which now includes the potentially malicious `phpCommand` and the PHP code, is directly passed to `cp.exec()`.
        4. `cp.exec()` executes the command in a shell, which interprets and executes the entire string as a system command. If the `phpCommand` setting has been maliciously modified to include system commands, these commands will be executed by `cp.exec()`.
        5. There is no validation or sanitization of the `phpCommand` setting or the constructed `command` before it's executed.
    - Visualization:
        ```
        [VSCode Configuration] --> "LaravelExtraIntellisense.phpCommand" setting
                |
                V
        [src/helpers.ts:runPhp] --> Retrieves phpCommand setting
                |
                V
        [src/helpers.ts:runPhp] --> Constructs 'command' string by replacing "{code}"
                |
                V
        [child_process.exec(command)] --> Executes 'command' AS SHELL COMMAND
                |
                V
        [System Command Execution] --> If phpCommand is malicious, arbitrary commands are executed
        ```

- **Security Test Case:**
    - Step 1: Create a new directory for the malicious Laravel project, e.g., `malicious-laravel-project`.
    - Step 2: Inside `malicious-laravel-project`, create a `.vscode` directory.
    - Step 3: Inside `.vscode`, create a file named `settings.json`.
    - Step 4: Add the following JSON content to `settings.json` to override the `phpCommand` setting:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "echo 'Malicious code executed!'; touch malicious.txt"
        }
        ```
    - Step 5: Open VSCode and open the `malicious-laravel-project` directory.
    - Step 6: Install and enable the "Laravel Extra Intellisense" extension in VSCode if it is not already installed.
    - Step 7: Create or open any PHP file (e.g., `index.php` in the project root) or a Blade template file in the project. This action will trigger the extension to activate and attempt to gather intellisense data.
    - Step 8: Observe the project directory.
    - Expected Result: A file named `malicious.txt` should be created in the `malicious-laravel-project` directory. This file's creation demonstrates that the overridden `phpCommand` setting was successfully used by the extension, and arbitrary system commands (in this case, `touch malicious.txt`) were executed. The output channel of the extension may also contain "Malicious code executed!".
    - Verification: Check for the existence of the `malicious.txt` file in the project root. If the file exists, the vulnerability is confirmed.
