### Vulnerability List

- Vulnerability Name: Command Injection via `deno.path` Setting
- Description:
    1. A malicious user gains access to the VS Code settings (either user settings or workspace settings).
    2. The attacker modifies the `deno.path` setting within the VS Code settings to include malicious shell commands. For example, they might set it to: `deno ; malicious_command`.
    3. When the VS Code extension needs to execute the Deno CLI for various features such as type checking, linting, formatting, debugging, or running tasks, it retrieves the path from the `deno.path` setting.
    4. Due to the lack of proper sanitization of the `deno.path` setting, the system shell interprets the injected malicious commands along with the intended Deno command.
    5. Consequently, the malicious commands are executed on the user's system with the same privileges as the VS Code process.
- Impact:
    Arbitrary code execution on the user's machine. This can lead to severe consequences, including:
    - Data theft and exfiltration.
    - Installation of malware (viruses, ransomware, etc.).
    - System compromise and unauthorized access.
    - Privilege escalation.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    None. The code directly uses the user-provided `deno.path` setting without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization: The extension should sanitize the `deno.path` setting to ensure it only contains a valid file path and does not include any shell metacharacters or command separators (like `;`, `&`, `|`, etc.).
    - Safe command execution: Instead of directly passing the `deno.path` setting to a shell, the extension should use a safer method like `child_process.spawn` in Node.js. This involves separating the command and its arguments, preventing shell interpretation of injected commands.
- Preconditions:
    - The victim must have the "vscode-deno" extension installed in VS Code.
    - An attacker needs to be able to modify the VS Code settings, either user settings or workspace settings. This could be achieved through social engineering, supply chain attacks, or if the attacker has compromised the user's machine already.
- Source Code Analysis:
    - File: `client\src\util.ts`
    - Function: `getDenoCommandName()` and `getDenoCommandPath()`
    - Step-by-step analysis:
        1. The `getDenoCommandPath()` function is responsible for determining the path to the Deno executable.
        2. It first attempts to retrieve the path configured in the VS Code settings under `deno.path` using `getWorkspaceConfigDenoExePath()`.
        3. If a path is provided in the settings, `getDenoCommandPath()` checks if it's an absolute path. If it's relative, it tries to resolve it relative to the workspace folders.
        4. The resolved or configured path (if absolute) is then returned without any sanitization.
        5. Functions like `buildDenoTask` in `client\src\tasks.ts` and `DenoDebugConfigurationProvider` in `client\src\debug_config_provider.ts` use `getDenoCommandName()` to get the Deno command.
        6. These functions then use `vscode.ProcessExecution` to execute Deno commands, directly using the unsanitized path obtained from `getDenoCommandName()`.
    - Visualization:
      ```
      User Settings (deno.path) --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> getDenoCommandName() --> vscode.ProcessExecution --> System Shell --> Command Execution (Vulnerability)
      ```
- Security Test Case:
    1. Open Visual Studio Code with the "vscode-deno" extension installed and activated.
    2. Access VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS).
    3. In the settings search bar, type "deno.path".
    4. Edit the `Deno › Path` setting and set its value to: `deno ; touch /tmp/pwned`. This injects a command to create a file `/tmp/pwned` after the deno command.
    5. Open any TypeScript or JavaScript project folder in VS Code.
    6. Enable Deno for the workspace if it's not already enabled. You can use the command palette (Ctrl+Shift+P or Cmd+Shift+P) and run "Deno: Enable".
    7. Trigger any feature of the Deno extension that would execute the Deno CLI. For example:
        - Open a TypeScript file within the workspace. This often triggers type-checking which might execute Deno.
        - Use the command palette and run "Deno: Cache Active Document".
        - Try to format the opened document (if formatting is configured to use Deno).
        - If tests are present, try to run a Deno test using the "Run Test" code lens.
        - Create a Deno task in `tasks.json` and attempt to run it.
    8. After triggering a Deno extension feature, check if the file `/tmp/pwned` has been created in the `/tmp` directory. On Linux or macOS, you can use the command `ls /tmp/pwned` in a terminal. On Windows, check for the file in `C:\tmp\pwned` or similar, depending on your system's `/tmp` equivalent.
    9. If the file `/tmp/pwned` is successfully created, it confirms that the command injection vulnerability is present, as the `touch /tmp/pwned` command was executed due to the injected malicious command in the `deno.path` setting.
