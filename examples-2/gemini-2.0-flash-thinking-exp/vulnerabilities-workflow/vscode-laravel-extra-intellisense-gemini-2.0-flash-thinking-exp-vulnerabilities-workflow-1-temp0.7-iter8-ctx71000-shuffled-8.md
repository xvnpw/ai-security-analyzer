### Vulnerability List for Laravel Extra Intellisense VSCode Extension

* Vulnerability Name: Command Injection via `phpCommand` setting

* Description:
    1. A threat actor creates a malicious Laravel repository.
    2. Inside the malicious repository, the threat actor creates a `.vscode/settings.json` file.
    3. In the `.vscode/settings.json` file, the threat actor sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "echo '; system($_GET[\"cmd\"]); exit; ' | php"`. This command will execute arbitrary system commands when the `{code}` placeholder is replaced and executed by the extension.
    4. A victim user opens the malicious repository in VSCode and has the "Laravel Extra Intellisense" extension installed and activated.
    5. The extension attempts to provide autocompletion, which triggers the execution of a PHP command using the configured `phpCommand`.
    6. The malicious command from `.vscode/settings.json` is executed, resulting in command injection. For example, if the extension executes a command to get routes, the malicious `phpCommand` will be used, effectively running `echo '; system($_GET["cmd"]); exit; ' | php -r "{code for route retrieval}"`.
    7. The threat actor can now execute arbitrary commands on the victim's machine by sending requests to the running PHP process with the `cmd` parameter in the query string. For example, by crafting a URL that triggers any feature of the extension and appending `?cmd=whoami` to it if the malicious command was `php -r "system($_GET['cmd']);"`.

* Impact:
    - Remote Code Execution (RCE) on the victim's machine.
    - The threat actor can gain full control over the victim's workstation, steal sensitive data, install malware, and pivot to other systems in the network.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.

* Missing Mitigations:
    - Input sanitization and validation for the `phpCommand` setting. The extension should validate that the `phpCommand` setting is safe and does not contain any malicious commands or shell injection vulnerabilities.
    - Restricting the characters allowed in the `phpCommand` setting to a predefined safe set.
    - Displaying a warning to the user when a workspace setting overrides `phpCommand` and suggests reviewing it.
    -  Ideally, the extension should avoid using `php -r` and instead use a safer method to execute PHP code, or at least provide a highly secure and restricted execution environment.

* Preconditions:
    - Victim user has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - Victim user opens a malicious Laravel repository in VSCode that contains a malicious `.vscode/settings.json` file.
    - The extension attempts to use `phpCommand` setting, for example during autocompletion.

* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line:
       ```typescript
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       let command = commandTemplate.replace("{code}", code);
       ```
       - This code retrieves the `phpCommand` setting from the VSCode configuration. If no setting is provided, it defaults to `"php -r \"{code}\""`.
       - It then replaces the `{code}` placeholder in the `commandTemplate` with the `$code` argument.
    4. Line:
       ```typescript
       cp.exec(command,
           { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
           function (err, stdout, stderr) { ... }
       );
       ```
       - This code uses `child_process.exec` to execute the constructed `command` on the system.
       - **Vulnerability:** The `command` variable is constructed using the `phpCommand` setting, which can be controlled by workspace settings. If a malicious workspace setting provides a malicious command, it will be executed by `cp.exec`, leading to command injection.

* Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo '; system($_GET[\"cmd\"]); exit; ' | php"
       }
       ```
    4. Open VSCode and open the `malicious-repo` directory as a workspace.
    5. Create a new PHP file (e.g., `test.php`) in the `malicious-repo` directory.
    6. In `test.php`, type `route('`. This will trigger the route autocompletion feature of the extension.
    7. Observe that the extension attempts to execute a PHP command to fetch routes. Because of the malicious `phpCommand` setting, the actual command executed will be `echo '; system($_GET["cmd"]); exit; ' | php -r "{code for route retrieval}"`.
    8. To verify RCE, you need to somehow interact with the running PHP process. In a real scenario, an attacker would need to find a way to send HTTP requests to the PHP process. For a simplified test, we can modify the malicious command to directly execute a command and redirect the output. Modify `settings.json` to:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo '; system(\"whoami > output.txt\"); exit; ' | php"
       }
       ```
    9. Repeat step 6.
    10. Check the `malicious-repo` directory for a file named `output.txt`. If the command injection is successful, this file will be created and contain the output of the `whoami` command (the username of the user running VSCode).

This test case demonstrates that a malicious repository can inject arbitrary commands via the `phpCommand` setting, leading to Remote Code Execution.
