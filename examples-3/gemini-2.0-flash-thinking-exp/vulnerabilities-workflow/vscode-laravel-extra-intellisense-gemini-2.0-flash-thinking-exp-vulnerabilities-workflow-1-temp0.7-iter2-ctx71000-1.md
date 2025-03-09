### Vulnerability List for VSCode Laravel Extra Intellisense

* Vulnerability Name: Command Injection via `phpCommand` setting
* Description: The extension executes PHP code to gather information for autocompletion. The command used to execute PHP is configurable via the `LaravelExtraIntellisense.phpCommand` setting. This setting is directly passed to `child_process.exec` without sufficient sanitization. A malicious user can craft a malicious workspace configuration that injects arbitrary commands into the execution flow, leading to Remote Code Execution (RCE).
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the same privileges as VSCode. This can lead to data theft, malware installation, or complete system compromise.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None. The code directly uses the user-provided configuration in `cp.exec`. The README.md has a "Security Note" but it's just a warning, not a mitigation.
* Missing Mitigations:
    - Input sanitization/validation of the `phpCommand` setting.
    - Restricting the characters allowed in the `phpCommand` setting.
    - Avoiding `child_process.exec` and using safer alternatives if possible (though running PHP code might necessitate `exec`).
    - Documentation should explicitly warn about the RCE risk if a custom `phpCommand` is used, especially when opening projects from untrusted sources.
* Preconditions:
    - Victim opens a workspace containing a malicious `.vscode/settings.json` file.
    - Malicious `.vscode/settings.json` file sets a crafted `LaravelExtraIntellisense.phpCommand`.
    - The extension is activated in the workspace.
* Source Code Analysis:
    1. File: `src/helpers.ts` Function: `runPhp(code: string, description: string|null = null)`
       ```typescript
       static async runPhp(code: string, description: string|null = null) : Promise<string> {
           code = code.replace(/\"/g, "\\\""); // Minimal escaping for double quotes
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

               cp.exec(command, // Vulnerable function: child_process.exec
                   { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                   function (err, stdout, stderr) {
                       // ...
                   }
               );
           });
           return out;
       }
       ```
       The `runPhp` function retrieves the `phpCommand` setting and directly substitutes the `{code}` placeholder with the PHP code to be executed. It uses `cp.exec` to run the command. The escaping is minimal and insufficient to prevent command injection if a user crafts a malicious `phpCommand`.
    2. Configuration Retrieval: The extension gets the `phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. This configuration can be set in workspace settings, which can be included in a malicious repository.
* Security Test Case:
    1. Attacker Setup:
       - Create a new Laravel project or any directory.
       - Create a `.vscode` directory inside the project root.
       - Create a `settings.json` file inside `.vscode` with the following content:
         ```json
         {
             "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned\"); {code}'"
         }
         ```
         This malicious `phpCommand` will execute `touch /tmp/pwned` before executing the intended PHP code of the extension.
       - Host this project in a publicly accessible repository (e.g., GitHub).
    2. Victim Action:
       - Victim installs the "Laravel Extra Intellisense" extension in VSCode.
       - Victim clones the attacker's malicious repository.
       - Victim opens the cloned repository in VSCode.
       - Victim activates the extension by opening a PHP or Blade file in the workspace. Autocompletion should trigger the extension to run PHP code.
    3. Verification:
       - After the extension activates (autocompletion is attempted), check if the file `/tmp/pwned` exists on the victim's system.
       - If `/tmp/pwned` exists, the command injection is successful.
