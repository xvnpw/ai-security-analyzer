### Vulnerability List

- Vulnerability Name: Local Code Execution via `phpCommand` Configuration
- Description:
    - A malicious actor with local access to a developer's machine can modify the Visual Studio Code settings.
    - The attacker changes the `LaravelExtraIntellisense.phpCommand` configuration setting. This setting dictates the command used to execute PHP code for the Laravel Extra Intellisense extension.
    - The attacker can inject arbitrary PHP code into this setting. For example, they could set it to execute system commands or write malicious files.
    - When the Laravel Extra Intellisense extension attempts to gather autocompletion data (e.g., for routes, views, configs), it uses the configured `phpCommand` to execute PHP code within the user's Laravel project.
    - Due to the injected malicious code in `phpCommand`, arbitrary PHP code is executed on the developer's machine within the context of their Laravel project.
- Impact:
    - Critical. Successful exploitation allows for arbitrary code execution on the developer's machine.
    - This can lead to:
        - Full compromise of the development machine.
        - Theft of sensitive source code and data.
        - Modification of project files, including introduction of backdoors into the Laravel application.
        - Further attacks on systems accessible from the development machine.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Documentation in `README.md` includes a "Security Note" that warns users about the extension executing Laravel application code and advises caution.
    - The "Security Note" suggests temporarily disabling the extension when writing sensitive code in service providers.
    - These are documentation-based warnings and do not prevent the vulnerability.
- Missing Mitigations:
    - Input validation and sanitization of the `phpCommand` configuration setting. The extension should validate or sanitize the `phpCommand` input to prevent injection of arbitrary commands.
    - Restricting the scope of commands executed. Instead of allowing users to define arbitrary PHP commands, the extension could use a safer approach, such as pre-defined functions or a more restricted execution environment.
    - User confirmation or warning when the `phpCommand` is modified, especially if it deviates from a safe default.
    - Using secure coding practices to construct and execute commands, avoiding direct execution of user-provided strings as shell commands.
- Preconditions:
    - Attacker must have local access to the developer's machine and the ability to modify VSCode settings (user or workspace `settings.json`).
    - The Laravel Extra Intellisense extension must be installed and activated in a Laravel project.
    - The developer must have the default or a potentially insecure `phpCommand` configuration.
- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Step 1: The function `runPhp` is defined to execute arbitrary PHP code passed as the `code` argument.
    - Step 2:  `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` retrieves the `phpCommand` setting from VSCode configuration. If no setting is found, it defaults to `php -r "{code}"`.
    - Step 3: `let command = commandTemplate.replace("{code}", code);` constructs the final command by directly embedding the user-provided `code` into the `phpCommand` template. **This is the vulnerable point where arbitrary code from the configuration is injected into the command.**
    - Step 4: `cp.exec(command, ...)` executes the constructed command using `child_process.exec`. This will execute the PHP code, including any malicious code injected via the `phpCommand` setting.

    ```
    src/helpers.ts:runPhp

    +---------------------+      getConfiguration('phpCommand')     +-----------------------+      replace('{code}', code)     +------------------------+      cp.exec(command)     +-----------------------+
    | User Configuration  | -------------------------------------> |  Extension retrieves  | -----------------------------------> | Command is constructed | -------------------------> |  Command is executed  |
    | (settings.json)     |                                        |  phpCommand setting   |                                      | (Vulnerable Injection) |                          |  (Code Execution)      |
    +---------------------+                                        +-----------------------+                                      +------------------------+                          +-----------------------+
    ```

- Security Test Case:
    1. Precondition:
        - Install the "Laravel Extra Intellisense" extension in Visual Studio Code.
        - Open a Laravel project in VSCode.
    2. Action:
        - Open VSCode settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - Go to Workspace Settings or User Settings.
        - Search for "LaravelExtraIntellisense: Php Command".
        - Modify the `LaravelExtraIntellisense.phpCommand` setting to the following malicious command:
          ```json
          "LaravelExtraIntellisense.phpCommand": "php -r \"file_put_contents('pwned.php', '<?php echo '<pre>'; system(\$_GET['cmd']); echo '</pre>'; ?>');\""
          ```
        - Save the settings.
    3. Trigger:
        - Open any PHP or Blade file in the Laravel project where autocompletion is expected to trigger the extension's functionality. Alternatively, wait for the extension's periodic background processes to run.
    4. Verification:
        - Check the root directory of your Laravel project. A new file named `pwned.php` should have been created. This indicates successful execution of the injected code.
    5. Exploitation (Optional):
        - Access `pwned.php` through a web browser or using `curl`. For example, if your Laravel project is served at `http://localhost:8000`, access `http://localhost:8000/pwned.php?cmd=whoami`.
        - The output of the `whoami` command (or any other system command passed via the `cmd` parameter) will be displayed on the page, confirming arbitrary code execution.

This test case demonstrates that a malicious user with local access can achieve arbitrary code execution by modifying the `phpCommand` configuration.
