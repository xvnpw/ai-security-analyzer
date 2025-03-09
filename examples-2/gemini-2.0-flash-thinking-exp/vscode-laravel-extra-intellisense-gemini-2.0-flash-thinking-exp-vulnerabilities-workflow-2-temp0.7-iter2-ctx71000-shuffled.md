### Vulnerability: Command Injection via `phpCommand` setting

- **Description:**
  1. A developer installs the "Laravel Extra Intellisense" VS Code extension.
  2. An attacker crafts a malicious Laravel workspace configuration (`.vscode/settings.json`) that injects arbitrary shell commands into the `LaravelExtraIntellisense.phpCommand` setting. For example, the attacker can set `LaravelExtraIntellisense.phpCommand` to `"php -r \\"<?php system('malicious_command'); ?>{code}\\""`.
  3. The developer opens a Laravel project in VS Code and the malicious workspace configuration is loaded.
  4. The extension attempts to gather autocompletion data by executing PHP code using the configured `phpCommand`.
  5. Due to insufficient sanitization, the malicious commands injected by the attacker in the `phpCommand` setting are executed by the system shell.
  6. This results in arbitrary code execution on the developer's machine with the privileges of the VS Code process.

- **Impact:**
  - Remote Code Execution (RCE) on the developer's machine.
  - An attacker can gain full control over the developer's workstation, potentially stealing sensitive data, installing malware, or pivoting to internal networks if the developer's machine is connected to one.
  - This can severely compromise the developer's environment and any projects they are working on.

- **Vulnerability rank:** Critical

- **Currently implemented mitigations:**
  - A "Security Note" in the `README.md` file warns users about the extension executing their Laravel application and suggests disabling the extension if sensitive code is present in service providers.
  - This is not a technical mitigation and relies on the user's awareness and caution, which is insufficient to prevent exploitation.

- **Missing mitigations:**
  - Input sanitization and validation for the `LaravelExtraIntellisense.phpCommand` setting. The extension should validate and sanitize the user-provided command to prevent the injection of arbitrary shell commands.
  - Proper escaping of the `{code}` placeholder within the `phpCommand` setting to ensure that user-provided code is treated as a single argument and not interpreted as shell commands.
  - Ideally, the extension should avoid using `cp.exec` with user-provided commands altogether and instead use a safer mechanism for executing PHP code, if possible.

- **Preconditions:**
  - The attacker needs to be able to influence the workspace settings of the developer. This can be achieved if the developer opens a project controlled by the attacker, or if the attacker can somehow modify the developer's workspace settings (e.g., through a compromised repository).
  - The developer must have the "Laravel Extra Intellisense" extension installed and activated in VS Code.
  - The developer must open a Laravel project workspace in VS Code.

- **Source code analysis:**
  1. File: `src/helpers.ts`
  2. Function: `runPhp(code: string, description: string|null = null)`
  3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \\"{code}\\"";`
     - This line retrieves the `phpCommand` setting from the VS Code configuration. If not set, it defaults to `"php -r \\"{code}\\""`.
  4. Line: `let command = commandTemplate.replace("{code}", code);`
     - This line substitutes the `{code}` placeholder in the `commandTemplate` with the `$code` argument, which contains the PHP code to be executed. **Crucially, there is no sanitization or escaping performed on the `$code` before substitution.**
  5. Line: `cp.exec(command, ...)`
     - This line executes the constructed `command` using `child_process.exec`.  `cp.exec` executes a command in a shell, which is vulnerable to command injection if the command string is not properly sanitized, especially when it incorporates user-provided data like the `phpCommand` setting and the `{code}` placeholder.

  ```typescript
  // Visualization of vulnerable code in src/helpers.ts - runPhp function

  function runPhp(code: string, description: string|null = null) : Promise<string> {
      code = code.replace(/\"/g, "\\\""); // Simple escaping of double quotes in PHP code
      if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
          code = code.replace(/\$/g, "\\$"); // Escaping dollar signs for *nix shells
          code = code.replace(/\\\\'/g, '\\\\\\\\\''); // More escaping for single quotes - potentially incomplete/incorrect
          code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // More escaping for double quotes - potentially incomplete/incorrect
      }
      // Vulnerable line: User-controlled phpCommand is retrieved from settings
      let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
      // Vulnerable line: No sanitization of 'code' before string replacement
      let command = commandTemplate.replace("{code}", code);
      let out = new Promise<string>(function (resolve, error) {
          cp.exec(command, // Vulnerable line: Executing unsanitized command in shell
              { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
              function (err, stdout, stderr) { ... }
          );
      });
      return out;
  }
  ```

- **Security test case:**
  1. Create a new empty folder to simulate a Laravel project workspace.
  2. Inside the folder, create a `.vscode` directory.
  3. Inside the `.vscode` directory, create a `settings.json` file.
  4. Add the following configuration to `settings.json` to inject a malicious command into `phpCommand`:
     ```json
     {
         "LaravelExtraIntellisense.phpCommand": "php -r \\"<?php system('touch /tmp/pwned'); ?>{code}\\""
     }
     ```
     This configuration sets `phpCommand` to execute `touch /tmp/pwned` before any legitimate PHP code from the extension. This command will create a file named `pwned` in the `/tmp` directory on Linux/macOS systems. For Windows, you could use `system('echo pwned > C:\\pwned.txt');` and check for `C:\pwned.txt`.
  5. Open VS Code and open the folder created in step 1 as a workspace.
  6. Open any PHP file in the workspace (it does not need to be a valid Laravel project for this test, just any `.php` file).
  7. Observe if the file `/tmp/pwned` (or `C:\pwned.txt` for Windows) is created after VS Code activates the extension and tries to use `phpCommand`. The extension usually runs commands shortly after opening a workspace.
  8. If the `pwned` file is created, it confirms that the command injection vulnerability is present and exploitable.

This test case demonstrates that arbitrary commands can be injected and executed via the `LaravelExtraIntellisense.phpCommand` setting, confirming the command injection vulnerability.
