- vulnerability name: Command Injection via `phpCommand` setting
- description: |
  The "Laravel Extra Intellisense" extension allows users to configure the `phpCommand` setting, which defines the command used to execute PHP code for gathering autocompletion data. This setting is used in `src/helpers.ts` within the `runPhp` function. If a user maliciously crafts the `phpCommand` to include additional commands alongside the intended PHP execution, it's possible to inject and execute arbitrary system commands.

  Here's a step-by-step scenario:
  1. An attacker, posing as a user of the "Laravel Extra Intellisense" extension, opens the VSCode settings for the extension.
  2. The attacker locates the `LaravelExtraIntellisense.phpCommand` setting.
  3. The attacker modifies this setting to include a malicious command, for example:
  ```json
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; bash -c 'touch /tmp/pwned'"
  ```
  In this example, `php -r \"{code}\"` is the intended command to execute PHP code, and `; bash -c 'touch /tmp/pwned'` is the injected malicious command.
  4. The attacker then uses any feature of the extension that triggers PHP code execution, such as autocompletion for routes, views, configs, etc. This will cause the extension to call the `runPhp` function in `src/helpers.ts`.
  5. The `runPhp` function in `src/helpers.ts` takes the user-provided `phpCommand` setting and substitutes `{code}` with the PHP code that the extension needs to execute.
  6. Due to insufficient input sanitization or command construction, the entire modified `phpCommand` string, including the injected malicious command, is executed by `cp.exec`.
  7. In the example above, after the PHP code is executed by `php -r`, the injected command `bash -c 'touch /tmp/pwned'` is also executed, creating a file named `pwned` in the `/tmp/` directory on the system where VSCode is running.

- impact: |
  Successful command injection can lead to **critical** impact, including:
  - **Remote Code Execution (RCE):** Attackers can execute arbitrary system commands on the machine running VSCode.
  - **Unauthorized System Access:** Attackers can gain unauthorized access to the system, potentially escalating privileges, accessing sensitive data, and performing malicious operations.
  - **Data Exfiltration:** Attackers can steal sensitive information from the user's system or the Laravel project.
  - **System Compromise:** Injected commands could be used to completely compromise the development machine.

- vulnerability rank: critical
- currently implemented mitigations: |
  There are **no code-level mitigations** implemented in the project to prevent command injection through the `phpCommand` setting.

  The `README.md` file includes a "Security Note" that warns users about the risks of executing the Laravel application automatically and periodically:

  ```
  Security Note
  This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete.

  So if you have any unknown errors in your log make sure the extension not causing it.

  Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing.
  ```

  However, this is **only a cautionary note in documentation**, not a technical mitigation. It relies on users understanding the security implications and manually configuring the extension safely. This is not an effective mitigation against command injection vulnerabilities.

- missing mitigations: |
  The following mitigations are missing to prevent command injection vulnerability:
  - **Input Sanitization and Validation:** The extension should sanitize and validate the `phpCommand` setting to ensure it only contains expected and safe commands and arguments. It should prevent users from injecting arbitrary commands or shell metacharacters.
  - **Secure Command Execution:** Instead of using `cp.exec` which interprets the command as a shell command and is vulnerable to injection, the extension should use a safer method like `child_process.spawn` with proper argument escaping. This will prevent the shell from interpreting injected commands.
  - **Principle of Least Privilege:** The extension should ideally operate with the minimum privileges necessary. However, in this context, the vulnerability stems from user misconfiguration, so this might be less directly applicable as a mitigation within the extension itself, but rather a recommendation for secure usage.
  - **Content Security Policy (CSP) for settings:** While VSCode extensions settings don't directly use CSP, the concept of restricting the allowed characters and structure in the `phpCommand` setting is analogous to CSP principles.

- preconditions: |
  To trigger this vulnerability, the following preconditions must be met:
  1. **User-Configurable `phpCommand`:** The user must be able to modify the `LaravelExtraIntellisense.phpCommand` setting in VSCode. This is true by design as the extension provides this setting for customization.
  2. **Malicious Configuration:** The user (or an attacker who can influence the user's VSCode settings) must set the `phpCommand` to a malicious value that injects system commands.
  3. **Extension Activation and Feature Usage:** The "Laravel Extra Intellisense" extension must be activated in VSCode, and the user must use a feature that triggers the execution of PHP code via `Helpers.runPhp` or `Helpers.runLaravel`. This includes using autocompletion features for routes, views, configs, translations, etc.
  4. **Target System with Shell Access:** The system where VSCode is running must have a shell (like bash) available if the injected command relies on shell features.

- source code analysis: |
  The vulnerability lies in the `runPhp` function within `src/helpers.ts`:

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

  **Vulnerability Breakdown:**
  1. **`phpCommand` Setting:** The function retrieves the `phpCommand` setting from the extension's configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. This setting is directly controlled by the user.
  2. **Command Construction:** The line `let command = commandTemplate.replace("{code}", code);` substitutes the `{code}` placeholder in the `phpCommand` template with the `$code` argument (which is intended to be PHP code).  However, it performs a simple string replacement without any escaping or sanitization of the user-controlled `phpCommand` template itself.
  3. **`cp.exec()` Execution:** The constructed `command` string is then passed directly to `cp.exec(command, ...)` for execution. `cp.exec()` executes the provided string as a shell command. This is the critical point of vulnerability. If the `command` string contains shell metacharacters or additional commands (due to malicious `phpCommand` configuration), `cp.exec()` will execute them.
  4. **Insufficient Sanitization:** While there is some escaping of quotes and dollar signs applied to the `$code` variable *before* it's inserted into the command, there is **no sanitization or validation of the `commandTemplate`** itself (the `phpCommand` setting). This means if a user crafts a malicious `phpCommand` setting, the injected commands will be executed.

  **Visualization:**

  ```
  User Config (Malicious phpCommand):  "php -r \"{code}\"; malicious_command"
                                         |
                                         V
  runPhp("<?php echo 'test'; ?>") ---------> commandTemplate = "php -r \"{code}\"; malicious_command"
                                         |
                                         V
  command = commandTemplate.replace("{code}", "<?php echo 'test'; ?>")
          = "php -r \"<?php echo 'test'; ?>\"; malicious_command"
                                         |
                                         V
  cp.exec(command) ----------------------> Shell executes: `php -r "<?php echo 'test'; ?>"; malicious_command`
                                                        ^ Both php code and malicious command executed
  ```

- security test case: |
  **Title:** Command Injection via Malicious `phpCommand` Configuration

  **Description:** This test verifies that a malicious user can inject system commands by manipulating the `LaravelExtraIntellisense.phpCommand` setting, leading to arbitrary command execution.

  **Preconditions:**
  1. VSCode is installed with the "Laravel Extra Intellisense" extension activated.
  2. A Laravel project is opened in VSCode workspace (a dummy project is sufficient).
  3. The user has permissions to modify VSCode settings.
  4. The target system has a `bash` shell and basic command-line utilities like `touch`.

  **Steps:**
  1. **Open VSCode Settings:** In VSCode, navigate to `File` > `Preferences` > `Settings` (or `Code` > `Settings` on macOS).
  2. **Locate `phpCommand` Setting:** Search for `LaravelExtraIntellisense.phpCommand` in the settings search bar.
  3. **Modify `phpCommand` to Inject Command:** Change the `phpCommand` setting to the following malicious command:
     ```json
     "LaravelExtraIntellisense.phpCommand": "php -r \\\"{code}\\\"; touch /tmp/vscode-laravel-pwned"
     ```
     This command attempts to execute the intended PHP code and then injects a command to create a file named `vscode-laravel-pwned` in the `/tmp/` directory.
  4. **Trigger Autocompletion:** Open any PHP or Blade file within the Laravel project in VSCode.
  5. **Initiate Laravel Extension Feature:** In the opened file, start typing a Laravel function that triggers autocompletion from the extension. For example, in a PHP file, type `route('` or `config('`. This will force the extension to execute PHP code to fetch autocompletion suggestions.
  6. **Observe for Command Execution:** After triggering autocompletion, check if the injected command was executed. In this test case, verify if the file `/tmp/vscode-laravel-pwned` has been created. You can use the terminal to check: `ls /tmp/vscode-laravel-pwned`.

  **Expected Result:**
  - The file `/tmp/vscode-laravel-pwned` should be created, indicating that the injected `touch` command was successfully executed.
  - This confirms the command injection vulnerability, as arbitrary system commands were executed due to the malicious `phpCommand` configuration.

  **Cleanup:**
  1. After the test, revert the `LaravelExtraIntellisense.phpCommand` setting back to its default value (e.g., `php -r "{code}"`) to mitigate the vulnerability.
  2. Delete the created file `/tmp/vscode-laravel-pwned` using `rm /tmp/vscode-laravel-pwned`.
