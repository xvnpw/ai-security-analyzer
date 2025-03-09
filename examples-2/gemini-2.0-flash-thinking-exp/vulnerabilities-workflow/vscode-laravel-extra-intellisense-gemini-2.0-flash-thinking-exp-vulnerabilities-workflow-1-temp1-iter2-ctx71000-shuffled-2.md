### Vulnerability List

* Vulnerability Name: Command Injection in `phpCommand` setting
  * Description:
    1. Attacker provides a malicious repository to a victim.
    2. Victim opens the malicious repository in VSCode and activates the Laravel Extra Intellisense extension.
    3. Attacker crafts a malicious `phpCommand` in the VSCode settings (workspace settings in the malicious repository) that injects commands into the `php -r` execution. For example, attacker could set `LaravelExtraIntellisense.phpCommand` to `php -r "{code}; system('malicious command')"` or use backticks or other command injection techniques depending on the OS.
    4. When the extension tries to execute PHP code (e.g., to fetch routes, views, configs), it uses the attacker-controlled `phpCommand`.
    5. The injected command is executed by the system along with the intended PHP code.
  * Impact:
    Remote Code Execution (RCE). The attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process.
  * Vulnerability Rank: critical
  * Currently Implemented Mitigations:
    None. The extension directly uses the user-provided `phpCommand` setting without any sanitization. The "Security Note" in README is just a warning, not a mitigation.
  * Missing Mitigations:
    - Input sanitization of the `phpCommand` setting to ensure it only contains a valid path to the PHP executable and safe arguments.
    - Validating that the `phpCommand` only executes PHP interpreter and its arguments, preventing injection of arbitrary commands.
    - Restricting the characters allowed in `phpCommand` to a safe subset.
    - Considering alternative, safer APIs for executing PHP code if available within the VSCode extension context, though executing external PHP scripts is likely necessary for Laravel bootstrapping.
    - Documenting the security risks of `phpCommand` in more detail and advising users to be extremely cautious when using custom `phpCommand`, especially when opening workspaces from untrusted sources.
  * Preconditions:
    - Victim opens a malicious workspace in VSCode with the Laravel Extra Intellisense extension activated.
    - Attacker has the ability to modify workspace settings (e.g., by providing a malicious repository with a `.vscode/settings.json` file).
    - Victim must trust and open a malicious repository provided by the attacker.
  * Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Code snippet:
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

               cp.exec(command, // Command Injection Vulnerability!
                   { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                   function (err, stdout, stderr) { ... }
               );
           });
           return out;
       }
       ```
    4. Vulnerability Detail: The `runPhp` function constructs a shell command by taking the `phpCommand` from the extension's configuration and replacing the `{code}` placeholder with the PHP code to be executed. The `command` is then executed using `cp.exec()`.  Critically, there is no sanitization or validation of the `phpCommand` configuration itself. An attacker can inject arbitrary shell commands by crafting a malicious `phpCommand` in the workspace settings. The code attempts to escape double quotes and some characters for Unix-like systems in the `{code}` part, but this escaping is insufficient to prevent command injection when the base command itself is attacker-controlled.
  * Security Test Case:
    1. Create a new directory to serve as a malicious Laravel project. Inside this directory, create a `.vscode` directory and within it, a `settings.json` file.
    2. In `settings.json`, add the following configuration to override the `phpCommand`:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('touch /tmp/pwned_by_vscode_extension')\""
       }
       ```
    3. Open this malicious project directory in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    4. Open any PHP file (e.g., create an empty `test.php` file in the root of the project and open it). This action should trigger the extension to run PHP commands to gather Laravel application information.
    5. After a short delay (during which the extension attempts to fetch data), check if a file named `pwned_by_vscode_extension` has been created in the `/tmp/` directory of your system.
    6. If the file `/tmp/pwned_by_vscode_extension` exists, it confirms that the `system('touch /tmp/pwned_by_vscode_extension')` command injected through the malicious `phpCommand` setting was successfully executed, demonstrating Remote Code Execution.
