## Vulnerability List

### 1. Command Injection in `phpCommand` setting

- Description:
    1. The VSCode extension "Laravel Extra Intellisense" provides autocompletion features for Laravel projects.
    2. To provide these features, the extension executes PHP code to retrieve information from the Laravel application (e.g., routes, views, configurations).
    3. The extension uses the `php -r "{code}"` command to execute PHP code.
    4. The base command `php -r "{code}"` can be customized by users through the `LaravelExtraIntellisense.phpCommand` setting in VSCode configuration.
    5. **Vulnerability:** The extension does not properly sanitize the `LaravelExtraIntellisense.phpCommand` setting.
    6. An attacker can inject arbitrary system commands by crafting a malicious `phpCommand` setting.
    7. For example, an attacker can create a malicious Laravel project and include a `.vscode/settings.json` file in the project root with a modified `phpCommand`.
    8. When a victim opens this malicious project in VSCode with the "Laravel Extra Intellisense" extension installed, the malicious settings will be applied.
    9. When the extension attempts to run any Laravel related command (which happens automatically in background for autocompletion), the injected commands within the malicious `phpCommand` will be executed by `cp.exec`.

- Impact:
    - Remote Code Execution (RCE).
    - An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's local machine and data.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - None.
    - The extension attempts to escape double quotes within the PHP code that is passed to `php -r "{code}"`, but it does not sanitize or validate the `phpCommand` setting itself.

- Missing mitigations:
    - **Input sanitization/validation:** The extension should sanitize and validate the `LaravelExtraIntellisense.phpCommand` setting.
        - Ideally, the extension should restrict the allowed characters and format of the `phpCommand` to only permit safe commands.
        - A safer approach is to disallow user customization of the execution path altogether. The extension should internally construct the command with a fixed and safe `php -r "{code}"` structure, preventing users from modifying the base command or adding extra options.
    - **Principle of least privilege:** While not directly a mitigation for command injection, running the PHP commands with the least necessary privileges can limit the impact of a successful attack. However, in the context of VSCode extensions, the commands are executed with the same privileges as the VSCode process itself.

- Preconditions:
    - Victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - Victim opens a workspace that contains a malicious `.vscode/settings.json` file or manually configures a malicious `LaravelExtraIntellisense.phpCommand` in their VSCode settings.
    - The extension is activated in the opened workspace and attempts to execute a Laravel command (which occurs automatically for autocompletion features).

- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Code snippet:
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
    - **Explanation:**
        - The `runPhp` function retrieves the `phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It constructs the command string by replacing `{code}` in the `commandTemplate` with the provided `$code`.
        - `cp.exec(command, ...)` is used to execute the constructed command string without any sanitization of the `commandTemplate`.
        - This allows for command injection if a malicious user provides a crafted `phpCommand` setting.

- Security test case:
    1. Create a new Laravel project in a local directory (e.g., `test-laravel-vuln`).
    2. Navigate to the project root directory in your terminal.
    3. Create a `.vscode` directory: `mkdir .vscode`
    4. Create a `settings.json` file inside the `.vscode` directory: `touch .vscode/settings.json`
    5. Open `.vscode/settings.json` and add the following malicious configuration:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"touch /tmp/vscode-laravel-extra-intellisense-vuln\")'"
       }
       ```
    6. Open the `test-laravel-vuln` project in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    7. Open any PHP file in the project (e.g., a controller or route file) to trigger the extension's autocompletion features, which will execute a Laravel command in the background.
    8. In your terminal, check if the file `/tmp/vscode-laravel-extra-intellisense-vuln` has been created: `ls /tmp/vscode-laravel-extra-intellisense-vuln`
    9. If the file exists, it confirms that the injected system command `touch /tmp/vscode-laravel-extra-intellisense-vuln` was successfully executed, demonstrating the command injection vulnerability.
