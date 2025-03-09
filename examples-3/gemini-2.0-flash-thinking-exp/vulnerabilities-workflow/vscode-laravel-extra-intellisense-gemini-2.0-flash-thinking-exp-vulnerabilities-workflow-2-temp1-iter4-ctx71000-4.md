### Vulnerability List

- Vulnerability Name: **Remote Code Execution via `phpCommand` Misconfiguration**
- Description:
    - The extension relies on executing PHP code in the user's Laravel application to gather data for autocompletion.
    - This execution is performed using the `phpCommand` setting, which is configurable by the user.
    - If a user misconfigures `phpCommand` to point to a publicly accessible PHP interpreter (e.g., in a Docker development environment exposed to the internet), and if an attacker can somehow inject malicious PHP code into the Laravel application being analyzed by the extension, the attacker could achieve remote code execution on the developer's machine when the extension attempts to gather autocompletion data.
    - Steps to trigger the vulnerability:
        1. A developer misconfigures the `phpCommand` setting to use a PHP interpreter accessible from outside their local machine (e.g., a Docker container's PHP exposed via port forwarding).
        2. An attacker gains the ability to modify files within the Laravel project directory that the extension analyzes. This could happen through various means, such as exploiting a vulnerability in the Laravel application itself or compromising other services running in the development environment.
        3. The attacker injects malicious PHP code into a file that is processed by the extension when gathering autocompletion data (e.g., a config file, a route file, a view file, or a model file).
        4. The extension, due to its periodic background processes or user-initiated actions that trigger data gathering, executes the injected malicious PHP code using the misconfigured `phpCommand`.
        5. The attacker achieves remote code execution on the developer's machine with the privileges of the user running the VSCode extension.
- Impact:
    - **Critical**. Successful exploitation allows an attacker to execute arbitrary code on the developer's machine. This could lead to:
        - Full compromise of the developer's workstation.
        - Stealing sensitive data, including source code, credentials, and private keys.
        - Planting malware or ransomware.
        - Pivoting to other systems accessible from the developer's machine.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - **Security Note in README**: The `README.md` file includes a "Security Note" that warns users about the risks of the extension executing their Laravel application and advises caution, especially in scenarios involving Docker and sensitive code. This is a documentation-level mitigation, alerting users to potential risks.
    - **Error Alert Configuration**: The extension provides a setting `LaravelExtraIntellisense.disableErrorAlert` to hide error alerts. While not directly a mitigation, it might encourage users to disable error reporting, potentially masking exploitation attempts if errors are generated during malicious code execution. However, this is not intended as a security mitigation and does not prevent the vulnerability itself.
- Missing Mitigations:
    - **Input Validation and Sanitization for `phpCommand`**: The extension should validate and sanitize the `phpCommand` setting to ensure it is a safe and expected command. For example, it could:
        - Verify that the command starts with "php" or a known safe path to a PHP executable.
        - Prevent the inclusion of potentially dangerous shell operators or arguments.
        - Warn users if the configured path is outside of typical safe locations.
    - **Secure Code Execution**: The extension should implement more secure methods for executing PHP code. Instead of directly executing arbitrary code via `php -r "{code}"`, consider:
        - Using a more restricted PHP execution environment, if feasible within the VSCode extension context.
        - Implementing a sandboxed environment for PHP execution to limit the impact of potential code injection.
        - Avoiding `eval`-like constructs or dynamic code execution where possible.
    - **Permissions and Isolation**: The extension could attempt to run the PHP commands with the least necessary privileges. However, within the context of VSCode extensions and `child_process.exec`, this might be challenging to enforce effectively without significant architectural changes.
    - **Network Security Warnings**: If the extension detects that `phpCommand` points to an executable that might be exposed to the network (e.g., based on common Docker configuration patterns), it could display a more prominent warning to the user about the increased risk.
- Preconditions:
    - **Misconfigured `phpCommand`**: The user must configure `phpCommand` to point to a PHP interpreter that is reachable from outside the local development machine. This is especially relevant in Docker or containerized development environments.
    - **Code Injection Point in Laravel Project**: An attacker must find a way to inject malicious PHP code into the Laravel project files that are analyzed by the extension. This could be due to vulnerabilities in the Laravel application itself, compromised dependencies, or other security weaknesses in the development environment.
- Source Code Analysis:
    - **`helpers.ts` - `runPhp` function**:
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

                cp.exec(command,
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
        - This function is responsible for executing PHP code.
        - It retrieves the `phpCommand` from the extension's configuration, defaulting to `"php -r \"{code}\""`.
        - It uses `child_process.exec(command, ...)` to execute the command.
        - **Vulnerability**: The `code` variable, which contains the PHP code to be executed, is directly embedded into the command without sufficient sanitization beyond basic escaping of quotes and dollar signs. More importantly, the `commandTemplate` itself is taken directly from user configuration (`phpCommand`) without validation. This means if a malicious or misconfigured `phpCommand` is provided, and if an attacker can control the `code` being passed to `runPhp` (even indirectly via file injection into Laravel project), they can achieve arbitrary command execution. The `code` in this extension is generated by the extension itself and not directly from user input in the editor, but an attacker can influence this `code` through file injection into the Laravel project.

    - **Various Provider Files (`RouteProvider.ts`, `ViewProvider.ts`, etc.)**:
        - These providers use `Helpers.runLaravel()` or `Helpers.runPhp()` to execute PHP code to collect data (routes, views, configs, etc.).
        - For example, `RouteProvider.ts` uses `Helpers.runLaravel()` to fetch routes:
            ```typescript
            Helpers.runLaravel(
                "echo json_encode(array_map(function ($route) {" +
                "    return ['method' => implode('|', array_filter($route->methods(), function ($method) {" +
                "        return $method != 'HEAD';" +
                "    })), 'uri' => $route->uri(), 'name' => $route->getName(), 'action' => str_replace('App\\\\Http\\\\Controllers\\\\', '', $route->getActionName()), 'parameters' => $route->parameterNames()];" +
                "}, app('router')->getRoutes()->getRoutes()));",
                "HTTP Routes"
            )
            ```
        - **Vulnerability**: If an attacker can modify the Laravel application files (e.g., `routes/web.php`), they could inject malicious PHP code. When the extension runs `Helpers.runLaravel()`, this injected code will be executed within the Laravel application context. Coupled with a misconfigured `phpCommand`, this leads to remote code execution outside the intended scope of the Laravel application.

- Security Test Case:
    1. **Setup a Vulnerable Development Environment**:
        - Create a simple Laravel project.
        - Configure Docker for this project and expose the workspace container's port 9000 (or any port) to the host machine, simulating a publicly accessible development server (though in a controlled local environment for testing).
        - Set up VSCode to use this Laravel project workspace.
        - Misconfigure the `LaravelExtraIntellisense.phpCommand` setting in VSCode to: `"docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r \"{code}\""`, assuming Laradock setup. Adjust the command if using other Docker setups or exposed PHP interpreter.
    2. **Inject Malicious PHP Code**:
        - Modify a Laravel configuration file (e.g., `config/app.php`) or a route file (e.g., `routes/web.php`). Add the following malicious PHP code:
            ```php
            <?php
            // ... existing content ...
            if (isset($_GET['exploit'])) {
                file_put_contents('/tmp/rce_test.txt', 'RCE Successful!'); // Simple indicator of RCE
                system($_GET['cmd']); // For more advanced testing, execute a command passed via GET parameter
                exit();
            }
            ```
        - For testing purposes, placing this at the end of `config/app.php` or within a route definition in `routes/web.php` will suffice.
    3. **Trigger Extension Data Gathering**:
        - Open a PHP or Blade file in VSCode within the Laravel project.
        - Trigger autocompletion that would cause the extension to run PHP code (e.g., start typing `route('` or `config('`). This will force the extension to execute Laravel code to fetch route or config lists.
    4. **Verify Code Execution**:
        - Check if the file `/tmp/rce_test.txt` exists on the machine where the Docker container is running. If it exists, it confirms code execution.
        - For more advanced testing, in the injected PHP code, use `system($_GET['cmd']);` and then trigger the extension's data gathering process. Simultaneously, send a GET request to your publicly exposed Docker port (e.g., `http://localhost:9000/?exploit=1&cmd=whoami`). If the `whoami` command is executed on the server and you observe the output (you might need to redirect output to a file to see it clearly depending on your setup and error handling), it will confirm remote command execution through the extension due to misconfiguration and code injection.
