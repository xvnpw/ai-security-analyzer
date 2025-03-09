### Vulnerability List

- Vulnerability Name: PHP Code Injection via `phpCommand` configuration
- Description:
    1. The extension uses the `phpCommand` configuration setting to execute PHP code. This setting is user-configurable and allows specifying the command used to run PHP, including how the generated PHP code (`{code}`) is passed to the PHP interpreter.
    2. An attacker can craft a malicious Laravel project.
    3. When a developer opens this malicious project in VSCode with the extension enabled, the extension attempts to gather Laravel project information by executing PHP code using the configured `phpCommand`.
    4. If the `phpCommand` is misconfigured or maliciously crafted, especially if it allows for command injection, the attacker can leverage this to execute arbitrary system commands on the developer's machine. For example, if the `phpCommand` is set to something like `php -r "{code}; system($_GET['cmd']);"` and the extension then executes PHP code, the attacker can inject `"; system('malicious_command'); //"` into the generated code, and due to the misconfiguration, the `system($_GET['cmd']);` will be appended and executed.
    5. Even without such an explicit misconfiguration, if the extension does not properly sanitize the `{code}` part when constructing the final command, and the `phpCommand` allows for command injection (e.g., due to shell expansion vulnerabilities), it can be exploited.
- Impact: Arbitrary PHP code execution on the developer's machine, potentially leading to full system compromise depending on the privileges of the user running VSCode and the available system commands.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The extension uses `cp.exec` to execute the `phpCommand`, which, depending on the operating system and shell, might offer some level of protection against naive command injection. However, it's not a robust mitigation against all forms of command injection, especially if the `phpCommand` itself is crafted to be vulnerable.
    - The README.md contains a "Security Note" warning users about the risks of running the extension and advising them to disable it when working with sensitive code. This is a documentation-level mitigation, not a code-level one.
- Missing Mitigations:
    - **Input Sanitization/Escaping:** The extension should sanitize or escape the `{code}` part before embedding it into the `phpCommand`.  Specifically, it should prevent shell injection.  Using parameterized execution or a more secure way to pass the PHP code to the interpreter (e.g., writing to a temporary file and executing that) would be more robust.
    - **`phpCommand` Validation:** The extension could validate the `phpCommand` setting to ensure it doesn't contain potentially dangerous commands or patterns that are indicative of command injection vulnerabilities. However, this is hard to do reliably.
    - **Principle of Least Privilege:**  The extension should ideally not require arbitrary PHP code execution. If it's necessary, it should be done in the most secure way possible, minimizing the attack surface.
    - **Sandboxing/Isolation:** Running the PHP code in a sandboxed environment or container would limit the impact of a successful code injection. This is a more complex mitigation but would significantly enhance security.
- Preconditions:
    - The developer must have the "Laravel Extra Intellisense" extension installed and enabled in VSCode.
    - The developer must open a malicious Laravel project in VSCode.
    - The attacker must be able to influence the content of the Laravel project, specifically the files that the extension analyzes (configurations, views, routes, models, etc.), to trigger the vulnerability.
    - The `phpCommand` setting must be either intentionally misconfigured by the user or exploitable in its default configuration by crafted `{code}`.
- Source Code Analysis:
    1. **`src/helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Escape double quotes
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$"); // Escape dollar signs for Unix-like systems
                code = code.replace(/\\\\'/g, '\\\\\\\\\''); // More escaping
                code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // More escaping
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code);
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Executes the command
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
        - The `runPhp` function takes PHP code as a string and executes it using the `phpCommand` configuration.
        - It attempts to escape double quotes and dollar signs, and some backslash combinations, but this escaping is likely insufficient to prevent command injection in all scenarios, especially if the `phpCommand` is customized.
        - The `{code}` placeholder in `phpCommand` is directly replaced with the provided `code` string without robust sanitization.
    2. **Configuration Retrieval:** The `phpCommand` is retrieved directly from VSCode configuration:
        ```typescript
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        ```
        - This means the extension directly trusts the user-provided `phpCommand` setting.
    3. **Usage of `runLaravel` and `runPhp`:** The extension uses `runLaravel` and `runPhp` throughout its code to gather information for autocompletion (e.g., in `ConfigProvider.ts`, `TranslationProvider.ts`, `RouteProvider.ts`, etc.). The `code` passed to these functions is generated by the extension to interact with the Laravel application. If this generated code, or the way it's incorporated into the `phpCommand`, is flawed, it could lead to injection.

- Security Test Case:
    1. **Setup:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Create a new Laravel project (or use an existing one for testing purposes, but be cautious).
        - Configure the `phpCommand` setting in VSCode settings for the workspace or user. Set it to a vulnerable command that allows for command injection, for example: `php -r "{code};"` or `php -d auto_prepend_file=php://input -r "` (if `auto_prepend_file` is allowed and `php -r` is used). For a more direct test, you could use: `bash -c "{code}"`.  **Warning:** Be extremely careful when setting up a vulnerable `phpCommand` as it can lead to unintended system execution. It is recommended to test in a virtual machine or isolated environment.
        - Alternatively, keep the default `php -r "{code}"` and try to craft a `{code}` payload that exploits shell command injection based on how `php -r` and the shell interact.
    2. **Craft Malicious Laravel Project:**
        - Create or modify a Laravel project file (e.g., a config file, view file, or route file) that, when processed by the extension, will cause the extension to generate a PHP code snippet that can be exploited via the configured `phpCommand`. For instance, try to influence the generated code in `ConfigProvider.ts` by creating a config file with a name or content that might be processed unsafely.
        - A simple test could be to try to inject a command within a config name that is then used in the generated PHP code.
        - For example, if config names are used without sanitization in the generated `echo json_encode(config()->all());` command, try to create a config file named `config/test\"; system('touch /tmp/pwned'); //`.  This is a highly simplified example and might not directly work due to parsing and escaping within the `config()->all()` Laravel function itself. A more successful approach might involve exploiting vulnerabilities in how the extension parses and handles the output of the executed PHP code.
    3. **Trigger Autocompletion:**
        - Open a PHP or Blade file in the malicious Laravel project in VSCode.
        - Trigger autocompletion in a context where the extension executes PHP code (e.g., typing `config('` to trigger config autocompletion, or `route('` for route autocompletion).
    4. **Verify Code Execution:**
        - Check if the injected command was executed. In the example `bash -c "{code}"` and the `touch /tmp/pwned` example, check if the file `/tmp/pwned` was created.
        - Monitor the output of the extension (via the Output panel in VSCode, if logging is enabled) for any error messages or signs of unexpected execution.
    5. **Refine Exploit (if needed):**
        - If the initial attempt fails, analyze the generated PHP code (by logging it if necessary) and refine the malicious project files or `phpCommand` configuration to achieve code execution. The key is to find a way to get the extension to generate PHP code that, when combined with the `phpCommand`, results in arbitrary command execution.

This vulnerability highlights the risk of executing user-configurable commands with unsanitized input, especially when dealing with code execution features in development tools. The extension's reliance on executing PHP code from the workspace to provide autocompletion inherently introduces security risks if not handled with extreme care.
