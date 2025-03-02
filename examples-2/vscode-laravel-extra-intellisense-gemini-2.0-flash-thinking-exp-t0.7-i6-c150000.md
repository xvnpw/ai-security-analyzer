## Vulnerability List

### 1. Command Injection in `phpCommand` setting

- **Vulnerability Name:** Command Injection in `phpCommand` setting
- **Description:**
    1. A threat actor crafts a malicious Laravel project, intending to compromise developers using the "Laravel Extra Intellisense" VSCode extension.
    2. Within the malicious project, the attacker creates a `.vscode` directory and places a `settings.json` file inside it. This file is used by VSCode to apply workspace-specific settings.
    3. The attacker modifies the `settings.json` file to include a malicious configuration for the "Laravel Extra Intellisense" extension. Specifically, they override the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to allow users to customize the command used to execute PHP for the extension's features, but it is not properly secured.
    4. The malicious `phpCommand` is crafted to inject arbitrary system commands. For example, the attacker could set it to:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch /tmp/vscode-rce'"
       }
       ```
       This command first executes the intended PHP code snippet represented by `{code}` and then, using the command separator `;`, injects an additional system command `touch /tmp/vscode-rce`.
    5. A victim, a developer working with Laravel projects, unknowingly opens this malicious project in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    6. VSCode automatically applies the workspace settings from `.vscode/settings.json`, including the attacker's malicious `phpCommand` configuration.
    7. When the "Laravel Extra Intellisense" extension activates and attempts to perform tasks that require executing PHP code (such as gathering route information, parsing views, or providing autocompletion suggestions), it uses the configured `phpCommand`.
    8. Due to the lack of sanitization of the `phpCommand` setting, the injected system command (`touch /tmp/vscode-rce` in the example) is executed by the system shell via `child_process.exec` alongside the intended PHP command. This results in arbitrary command execution on the victim's machine with the privileges of the VSCode process.

- **Impact:**
    - Remote Code Execution (RCE).
    - Successful exploitation allows an attacker to execute arbitrary system commands on the victim's machine.
    - This can lead to a complete compromise of the victim's local system, including:
        - Data theft: Accessing and exfiltrating sensitive files, code, and credentials.
        - Malware installation: Installing persistent backdoors, ransomware, or other malicious software.
        - Lateral movement: Using the compromised machine as a stepping stone to attack other systems on the local network.
        - Denial of service: Disrupting the victim's workflow or system operations.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None.
    - While the extension attempts to escape double quotes (`"`) and backslashes (`\`, `$`, `'`) within the PHP code snippet that is substituted into the `phpCommand`, this escaping is insufficient to prevent command injection when the base command template (`phpCommand` setting) itself is controlled by the user and is not validated or sanitized.

- **Missing Mitigations:**
    - **Input Sanitization and Validation for `phpCommand`:** The most critical missing mitigation is the lack of any sanitization or validation of the `LaravelExtraIntellisense.phpCommand` setting.
        - The extension should strictly validate the format and content of the `phpCommand` setting to ensure it only contains a safe PHP execution command and does not allow for the injection of arbitrary shell commands.
        - Ideally, the extension should restrict the allowed characters and command structure to a safe subset or completely disallow user customization of the base command execution path.
    - **Restrict User Customization:** Consider removing the user-configurable `phpCommand` setting entirely. The extension could internally construct the necessary PHP command with a fixed and safe structure, eliminating the attack vector.
    - **Use `child_process.spawn` instead of `child_process.exec`:**  Migrate from `cp.exec` to `cp.spawn`. `cp.spawn` with an array of arguments avoids shell interpretation, making command injection significantly harder. If shell execution is truly necessary, extreme care must be taken with sanitization.
    - **Principle of Least Privilege:** Although not a direct mitigation for command injection, running the PHP commands with the least necessary privileges could limit the impact of a successful attack. However, VSCode extensions generally run with the same privileges as VSCode itself.
    - **User Warning and Workspace Trust Integration:** Implement a clear warning to users about the security risks of modifying the `phpCommand` setting, especially when opening workspaces from untrusted sources. Leverage VSCode's workspace trust feature to enhance these warnings and potentially restrict the application of workspace settings from untrusted sources.

- **Preconditions:**
    - The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim opens a workspace in VSCode that contains a malicious `.vscode/settings.json` file.
    - The malicious `.vscode/settings.json` file must define a malicious `LaravelExtraIntellisense.phpCommand` setting.
    - The "Laravel Extra Intellisense" extension must activate and attempt to execute PHP code, which typically happens automatically when working with Laravel projects for features like autocompletion, route/view discovery, etc.

- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `Helpers.runPhp(code: string, description: string|null = null)`
    - **Vulnerable Code Snippet:**
      ```typescript
      static async runPhp(code: string, description: string|null = null) : Promise<string> {
          code = code.replace(/\"/g, "\\\"");
          if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
              code = code.replace(/\$/g, "\\$");
              code = code.replace(/\\\\'/g, '\\\\\\\\\'');
              code = code.replace(/\\\\"/g, '\\\\\\\\\"');
          }
          let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Vulnerable line: Retrieves phpCommand from configuration
          let command = commandTemplate.replace("{code}", code); // Vulnerable line: Constructs command by replacing {code}
          let out = new Promise<string>(function (resolve, error) {
              cp.exec(command, // Vulnerable line: Executes command without sanitization
                  { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                  // ...
              );
          });
          return out;
      }
      ```

    - **Explanation:**
        - The `runPhp` function is responsible for executing PHP code within the extension.
        - It retrieves the `phpCommand` setting from the VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. If no setting is provided, it defaults to `"php -r \"{code}\""`.
        - The code then constructs the command string by replacing the placeholder `{code}` in the `commandTemplate` with the PHP code to be executed.
        - Critically, `cp.exec(command, ...)` is used to execute the constructed command. `cp.exec` executes a command in a shell, and because the `commandTemplate` (from user settings) is not sanitized, it allows for command injection.
        - The code performs some escaping on the `code` variable, but this is insufficient because the attacker controls the entire command structure via the `phpCommand` setting.

    - **Visualization of Vulnerable Code Path:**

    ```mermaid
    graph LR
        A[Start: runPhp Function] --> B{Get phpCommand Setting};
        B -- User Defined Setting --> C[commandTemplate = User Setting];
        B -- No User Setting --> D[commandTemplate = "php -r \\"{code}\\""];
        C --> E[command = commandTemplate.replace("{code}", code)];
        D --> E
        E --> F{cp.exec(command)};
        F --> G[System Command Execution];
        G --> H[End: Command Injection Vulnerability];
    ```

- **Security Test Case:**
    1. **Setup:** Create a new empty directory, for example, `laravel-vuln-test`.
    2. **Malicious Workspace Settings:** Inside `laravel-vuln-test`, create a `.vscode` directory and within it, create a `settings.json` file with the following content:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch /tmp/vscode-laravel-rce-test'"
       }
       ```
    3. **Open Malicious Workspace:** Open the `laravel-vuln-test` directory in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    4. **Trigger Extension Activity:** Open any PHP file (or create a dummy one, e.g., `test.php`). To ensure the extension activates, you might need to trigger a feature that uses PHP execution, such as autocompletion in a Blade file (e.g., type `@route(` in a `.blade.php` file if you have one, or just opening a PHP file should be enough to trigger some background activity).
    5. **Verify Command Execution:** After a short delay (to allow the extension to run in the background), check if the file `/tmp/vscode-laravel-rce-test` has been created. In a terminal, use the command `ls /tmp/vscode-laravel-rce-test`.
    6. **Successful Exploitation:** If the file `/tmp/vscode-laravel-rce-test` exists, it confirms that the injected system command `touch /tmp/vscode-laravel-rce-test` was successfully executed, demonstrating the command injection vulnerability.

    **Cleanup:** After testing, delete the `/tmp/vscode-laravel-rce-test` file.

### 2. Code Injection via Malicious Workspace Files

- **Vulnerability Name:** Code Injection via Malicious Workspace Files
- **Description:**
    1. A threat actor creates a malicious Laravel repository.
    2. The attacker modifies files within this repository, such as Blade view files, configuration files, or model files, to inject malicious PHP code directly into them.
    3. When a victim opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed, the extension automatically attempts to analyze the Laravel project to provide features like autocompletion, code navigation, and diagnostics.
    4. As part of this analysis, the extension executes PHP code from the workspace to gather information. This can involve parsing view files, loading configuration values, retrieving model definitions, and more.
    5. If the extension processes and executes the malicious PHP code injected by the attacker into the workspace files, it can lead to arbitrary code execution on the victim's machine, with the privileges of the VSCode process.
    6. For example, a malicious Blade view file could contain embedded PHP code like `<?php system('touch /tmp/vscode-code-injection'); ?>`. When the extension parses this view file to extract view information, this injected PHP code will be executed.

- **Impact:**
    - Remote Code Execution (RCE).
    - An attacker can execute arbitrary PHP code on the victim's machine by crafting malicious files within a Laravel project.
    - This can lead to the same severe consequences as command injection, including data theft, malware installation, and system compromise.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None.
    - The extension executes PHP code from the workspace in an unsafe manner, without sufficient sandboxing or security considerations to prevent the execution of malicious code embedded within project files. The "Security Note" in the README provides a warning but does not constitute a technical mitigation.

- **Missing Mitigations:**
    - **Sandboxing PHP Execution:** Implement a secure sandboxing mechanism for the PHP execution environment used by the extension. This would limit the capabilities of any PHP code executed by the extension, preventing malicious code from causing harm to the victim's system.
    - **Input Validation and Sanitization of Workspace Data:**  Apply robust input validation and sanitization to all data retrieved from the Laravel application and workspace files before processing it. This can help prevent the execution of unexpected or malicious code paths.
    - **Robust Error Handling and Security Audits:** Implement comprehensive error handling to prevent the extension from executing unexpected code paths due to parsing errors or manipulated data. Conduct regular security audits of the extension's code to identify and address potential code injection vulnerabilities.
    - **Principle of Least Privilege in Code Execution:** The extension should only execute the minimum necessary code and commands required for its functionality. Avoid executing potentially dangerous code from the workspace files if it is not strictly necessary for the extension's core features.

- **Preconditions:**
    - The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim opens a malicious Laravel repository in VSCode that contains crafted files with embedded malicious PHP code (e.g., in Blade views, config files, models).
    - The extension activates and processes these malicious files as part of its analysis of the Laravel project, leading to the execution of the injected code.

- **Source Code Analysis:**
    - **File:** Multiple files in `src/` directory, including:
        - `src/ViewProvider.ts`
        - `src/ConfigProvider.ts`
        - `src/RouteProvider.ts`
        - `src/EloquentProvider.ts`
        - `src/TranslationProvider.ts`
        - `src/AuthProvider.ts`
        - `src/BladeProvider.ts`
    - **Function:**  Various `load*` functions in these files use `Helpers.runLaravel()` to execute PHP code from the workspace. `Helpers.runLaravel()` in turn uses `Helpers.runPhp()`.
    - **Vulnerable Code Example (from `src/ViewProvider.ts:loadViews()`):**
      ```typescript
      async loadViews() {
          // ...
          return Helpers.runLaravel("echo json_encode(app('view')->getFinder()->getHints());", 'view:hints').then(function (viewPathsResult) {
              viewPaths = JSON.parse(viewPathsResult);
              // ...
          });
      }
      ```

    - **Explanation:**
        - Files like `ViewProvider.ts`, `ConfigProvider.ts`, etc., use `Helpers.runLaravel()` to execute PHP code within the Laravel application context.
        - `Helpers.runLaravel()` ultimately calls `Helpers.runPhp()` to execute the PHP command.
        - The PHP code executed by these functions is designed to extract information from the Laravel application (e.g., view paths, config values, routes).
        - However, if a malicious user injects PHP code into workspace files (e.g., within Blade views), and if the extension processes these files using the described PHP execution mechanisms, the injected code will be executed by the extension. This is because the extension does not sanitize or isolate the execution environment of the PHP code it runs.

    - **Visualization of Vulnerable Code Path (in `src/ViewProvider.ts:loadViews`):**

    ```mermaid
    graph LR
        A[Start: loadViews Function] --> B{Helpers.runLaravel("echo json_encode(app('view')->getFinder()->getHints());", 'view:hints')};
        B --> C{Helpers.runPhp(...)};
        C --> D{Execute PHP Code from Workspace};
        D -- Malicious PHP Code in Workspace --> E[Arbitrary Code Execution];
        E --> F[End: Code Injection Vulnerability];
    ```


- **Security Test Case:**
    1. **Setup:** Create a new Laravel project, for example, `laravel-code-injection-test`.
    2. **Inject Malicious PHP Code into View File:** Modify a Blade view file within the project, such as `resources/views/welcome.blade.php`. Add the following malicious PHP code at the beginning of the file:
       ```blade
       <?php system('touch /tmp/vscode-code-injection-view-test'); ?>
       ```
       Leave the rest of the Blade view file as it is or with its default content.
    3. **Open Malicious Workspace:** Open the `laravel-code-injection-test` directory in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    4. **Trigger View Processing:** Open the modified Blade view file `resources/views/welcome.blade.php` in the VSCode editor. This action should trigger the extension to process view files for features like autocompletion or view discovery. Alternatively, simply opening any PHP file within the project might be enough to trigger the extension's background analysis, which may include view processing.
    5. **Verify Code Execution:** After a short delay, check if the file `/tmp/vscode-code-injection-view-test` has been created. In a terminal, use the command `ls /tmp/vscode-code-injection-view-test`.
    6. **Successful Exploitation:** If the file `/tmp/vscode-code-injection-view-test` exists, it confirms that the injected PHP code within the Blade view file was successfully executed by the extension, demonstrating the code injection vulnerability.

    **Cleanup:** After testing, delete the `/tmp/vscode-code-injection-view-test` file.
