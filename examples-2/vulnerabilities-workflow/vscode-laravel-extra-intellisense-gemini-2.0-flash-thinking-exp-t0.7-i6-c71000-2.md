### Vulnerability List

* Vulnerability Name: Command Injection in `phpCommand` setting
* Description: The extension uses the `LaravelExtraIntellisense.phpCommand` setting to execute PHP code. This setting is directly used in `child_process.exec` without sufficient sanitization. A malicious user can craft a `phpCommand` that injects arbitrary commands into the system.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine by providing a malicious `phpCommand` setting in the workspace configuration.
* Vulnerability Rank: Critical
* Currently implemented mitigations: None. The code directly uses the user-provided setting in `child_process.exec`.
* Missing mitigations: Input sanitization or validation for the `phpCommand` setting. The extension should validate or sanitize the `phpCommand` to prevent command injection. Alternatively, the extension should avoid using `child_process.exec` with user-provided input directly in the command string.
* Preconditions:
    * Victim opens a workspace that contains a malicious `.vscode/settings.json` file with a manipulated `LaravelExtraIntellisense.phpCommand` setting.
    * The extension is activated in the workspace.
* Source Code Analysis:
    * File: `src/helpers.ts`
    * Function: `runPhp`
    * Step 1: The function retrieves the `phpCommand` setting from the workspace configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    ```typescript
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    ```
    * Step 2: The function replaces the `{code}` placeholder in the `commandTemplate` with the PHP code to be executed.
    ```typescript
    let command = commandTemplate.replace("{code}", code);
    ```
    * Step 3: The function executes the constructed `command` using `child_process.exec`.
    ```typescript
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) { ... }
    );
    ```
    * Visualization:
    ```
    User Configuration (settings.json) --> LaravelExtraIntellisense.phpCommand --> commandTemplate
    commandTemplate + PHP Code --> command
    cp.exec(command) --> System Command Execution
    ```
    * Explanation: The vulnerability occurs because the `phpCommand` setting, which is controlled by the user (or a malicious repository), is directly used to construct a shell command without proper sanitization. This allows an attacker to inject arbitrary shell commands by manipulating the `phpCommand` setting. For example, setting `LaravelExtraIntellisense.phpCommand` to `bash -c "malicious_command && php -r '{code}'"` would execute `malicious_command` before executing the intended PHP code.
* Security Test Case:
    1. Create a Laravel project in a folder named `test-project`.
    2. Inside the `test-project` folder, create a `.vscode` subfolder.
    3. Inside the `.vscode` folder, create a file named `settings.json`.
    4. Add the following JSON content to `settings.json` to inject a command that creates a file named `pwned` in the `/tmp/` directory:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned' && php -r \"{code}\""
    }
    ```
    5. Open the `test-project` folder in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    6. Open any PHP or Blade file within the `test-project` to trigger the extension. For example, open `routes/web.php`.
    7. Wait for a short period (or trigger any autocompletion feature that uses PHP execution).
    8. Open a terminal and check if the file `/tmp/pwned` exists by running the command `ls /tmp/pwned`.
    9. If the file `/tmp/pwned` exists, the command injection vulnerability is confirmed.
