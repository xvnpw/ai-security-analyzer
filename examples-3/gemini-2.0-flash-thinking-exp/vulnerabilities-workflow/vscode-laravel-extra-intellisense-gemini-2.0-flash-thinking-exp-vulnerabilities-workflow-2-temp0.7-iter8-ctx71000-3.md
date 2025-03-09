### Vulnerability List:

- **Vulnerability Name:** Remote Code Execution via `phpCommand` configuration
  - **Description:**
    1. The extension executes PHP code from the opened Laravel project to gather autocompletion data.
    2. The `LaravelExtraIntellisense.phpCommand` setting allows users to customize the command used to execute PHP.
    3. A malicious Laravel project can include a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.phpCommand` to execute arbitrary commands on the developer's machine instead of just running PHP.
    4. When the developer opens this malicious project in VSCode, the extension reads the project settings, including the malicious `phpCommand`.
    5. Subsequently, when the extension attempts to gather autocompletion data, it uses the configured (malicious) `phpCommand`, leading to arbitrary command execution instead of intended PHP code execution.
  - **Impact:** Remote Code Execution (RCE) on the developer's machine. An attacker can gain full control over the developer's system by crafting a malicious Laravel project.
  - **Vulnerability Rank:** Critical
  - **Currently Implemented Mitigations:**
    - None. The extension allows full customization of the `phpCommand` without any validation or sanitization.
  - **Missing Mitigations:**
    - Input validation and sanitization for the `LaravelExtraIntellisense.phpCommand` setting to prevent execution of arbitrary commands.
    - Restrict the `phpCommand` to only execute `php -r "{code}"` and disallow any modifications or additional commands.
    - Display a warning to the user if the `phpCommand` setting is modified within the workspace settings, highlighting the security risks.
  - **Preconditions:**
    1. A developer must have the "Laravel Extra Intellisense" extension installed in VSCode.
    2. An attacker must be able to trick the developer into opening a malicious Laravel project in VSCode.
    3. The malicious Laravel project must contain a `.vscode/settings.json` file with a modified `LaravelExtraIntellisense.phpCommand` setting containing malicious commands.
  - **Source Code Analysis:**
    1. **`helpers.ts` - `runPhp(code: string, description: string|null = null)` function:**
       ```typescript
       static async runPhp(code: string, description: string|null = null) : Promise<string> {
           code = code.replace(/\"/g, "\\\"");
           if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
               code = code.replace(/\$/g, "\\$");
               code = code.replace(/\\\\'/g, '\\\\\\\\\'');
               code = code.replace(/\\\\"/g, '\\\\\\\\\"');
           }
           let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABILITY] User-configurable phpCommand
           let command = commandTemplate.replace("{code}", code);
           let out = new Promise<string>(function (resolve, error) {
               if (description != null) {
                   Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
               }

               cp.exec(command, // [VULNERABILITY] Command execution with user-defined command
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
       - The `runPhp` function retrieves the `phpCommand` from the extension's configuration.
       - It then replaces the `{code}` placeholder in the template with the PHP code to be executed.
       - `cp.exec(command, ...)` executes the constructed command.
       - **Vulnerability:** The `phpCommand` is directly taken from user configuration without any validation. If a malicious project provides a `phpCommand` that executes system commands instead of `php -r "{code}"`, the extension will execute those commands.

    2. **`README.md` - Sample configurations:**
       ```json
       "LaravelExtraIntellisense.phpCommand": "docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r \"{code}\"",
       "LaravelExtraIntellisense.basePathForCode": "/var/www/your-project"
       ```
       - The provided sample configurations in `README.md` show how to customize the `phpCommand` for Docker environments, reinforcing the intended customizability of this setting. However, this customizability opens the door for malicious modifications.

  - **Security Test Case:**
    1. **Setup:**
       - Install the "Laravel Extra Intellisense" extension in VSCode.
       - Create a new directory named `malicious-laravel-project`.
       - Inside `malicious-laravel-project`, create a subdirectory named `.vscode`.
       - Inside `.vscode`, create a file named `settings.json` with the following content:
         ```json
         {
             "LaravelExtraIntellisense.phpCommand": "echo '; echo ___; system(\"calc.exe\"); exit; '; php -r \"{code}\""
         }
         ```
         *(Note: `calc.exe` is used as a harmless payload for testing. In a real attack, this could be replaced with more malicious commands.)*
       - Create a dummy `artisan` file in the root of `malicious-laravel-project` (to simulate a Laravel project):
         ```bash
         touch artisan
         ```
    2. **Execution:**
       - Open the `malicious-laravel-project` directory in VSCode.
       - Open any PHP file within the project (e.g., create an empty `test.php` file and open it). This will trigger the extension to activate.
       - Observe if the calculator application (`calc.exe` on Windows) is launched.
    3. **Verification:**
       - If `calc.exe` is launched, it confirms that arbitrary commands are being executed via the modified `phpCommand` setting, proving the RCE vulnerability.

This vulnerability allows for trivial Remote Code Execution by simply opening a specially crafted Laravel project, making it a **Critical** security issue.
