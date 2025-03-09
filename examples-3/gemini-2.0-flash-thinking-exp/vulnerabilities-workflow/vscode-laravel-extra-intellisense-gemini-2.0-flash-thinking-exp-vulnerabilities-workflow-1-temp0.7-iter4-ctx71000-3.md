### Vulnerability List

* Vulnerability Name: Command Injection in `phpCommand` setting
* Description:
    1. The `Laravel Extra Intellisense` extension allows users to configure the `phpCommand` setting, which dictates how PHP code is executed to gather autocompletion data.
    2. This setting is intended to allow customization for different environments like Docker or Laravel Sail.
    3. However, the extension executes this command using `child_process.exec` without sufficient sanitization.
    4. A malicious actor can craft a `.vscode/settings.json` file within a repository that modifies the `phpCommand` setting.
    5. By injecting shell commands into the `phpCommand` setting, the attacker can achieve command injection when the extension executes PHP code.
    6. When a victim opens a repository containing this malicious `.vscode/settings.json` and the extension attempts to provide autocompletion, the injected commands will be executed on the victim's machine.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to data theft, system compromise, or further malicious activities.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None. While the extension attempts to escape double quotes within the PHP code snippet that is passed to the `php -r` command, it does not sanitize or validate the user-provided `phpCommand` setting itself.
* Missing Mitigations:
    * Sanitize the `phpCommand` setting to prevent command injection. This could involve:
        * Restricting the allowed characters or command structure in `phpCommand`.
        * Validating that the command only executes `php` and necessary arguments, preventing the injection of other commands.
        * Using parameterized execution methods if available in `child_process` to separate commands from arguments (though this might not be directly applicable to `php -r`).
    * Display a warning message to the user when the extension detects a custom `phpCommand` in the workspace settings, especially when opening a workspace from an untrusted source.
    * Consider alternative, safer methods for executing PHP code, such as using a secure sandboxed environment or a dedicated API if feasible.
* Preconditions:
    1. The victim must have the `Laravel Extra Intellisense` extension installed and activated in VSCode.
    2. The victim must open a malicious repository in VSCode.
    3. The malicious repository must contain a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.phpCommand` setting to include malicious commands.
    4. The extension must be triggered to execute a Laravel command, which occurs automatically during normal usage when providing autocompletion features.
* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` setting from VSCode configuration.
    4. Line: `let command = commandTemplate.replace("{code}", code);` - Constructs the command string by embedding the `$code` into the `phpCommand` template.
    5. Line: `cp.exec(command, ...)` - Executes the command using `child_process.exec`.
    6. Vulnerability: The `phpCommand` setting, which is user-configurable and can be controlled by malicious repository via `.vscode/settings.json`, is directly used in `cp.exec` without sufficient sanitization. This allows command injection.

    ```typescript
    // Visualization of vulnerable code path in src/helpers.ts -> runPhp
    runPhp(code: string, description: string|null = null) {
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // User controlled via settings.json
        let command = commandTemplate.replace("{code}", code); // Embeds code, but phpCommand is already potentially malicious
        cp.exec(command, ...) // Executes unsanitized command
    }
    ```
* Security Test Case:
    1. Create a new directory to simulate a malicious repository.
    2. Inside this directory, create a `.vscode` folder.
    3. Inside the `.vscode` folder, create a `settings.json` file with the following content:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r '{code}; require_once \"/tmp/command_injection_marker\";'"
        }
        ```
        Note: We use `require_once` to create a marker file as `system()` might be disabled in some PHP configurations. `require_once` will create a file if the path is treated as a command.
    4. Create an empty file at `/tmp/command_injection_marker` to ensure no errors if the command is executed before the test.
    5. Open VSCode and open the directory created in step 1 as a workspace.
    6. Open any PHP file in the workspace (or create a dummy PHP file if none exists). This action should trigger the extension and execute a Laravel command.
    7. Check if the file `/tmp/command_injection_marker` has been modified. You can check the modification timestamp or content if you append timestamp to it. If the file's modification timestamp has changed, it indicates that the injected PHP code (in this case, attempting to require a file at `/tmp/command_injection_marker`) has been executed, confirming command injection.
    8. To further verify command injection, you can modify the `settings.json` to execute a more harmful command, like creating a file with specific content or attempting network connections, observing the system's behavior for expected side effects.
