- Vulnerability name: Arbitrary Code Execution via Malicious `deno.path` Configuration
- Description:
    - An attacker can trick a user into configuring the `deno.path` setting in the VS Code Deno extension.
    - This setting is intended to allow users to specify the path to their Deno CLI executable.
    - However, the extension directly uses this path to execute Deno CLI commands without proper validation.
    - An attacker can leverage this by convincing a user to set `deno.path` to point to a malicious executable instead of the legitimate Deno CLI.
    - Once `deno.path` is maliciously configured, any action by the VS Code Deno extension that involves running a Deno command (e.g., starting the Language Server, caching dependencies, running tests, formatting code) will result in the execution of the malicious executable.
- Impact:
    - Arbitrary code execution on the user's machine.
    - The malicious code will be executed with the same privileges as the VS Code process, which is typically user-level privileges.
    - This can lead to various malicious activities, including:
        - Data theft and exfiltration.
        - Installation of malware or ransomware.
        - System compromise and unauthorized access.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The extension's code does not include any input validation or sanitization of the `deno.path` setting.
    - The `README.md` provides a note about the `deno.path` setting and the necessity of having Deno CLI installed, but this is not a technical mitigation and relies on user awareness.
- Missing mitigations:
    - Input validation and sanitization for the `deno.path` setting. The extension should verify that the provided path points to a legitimate Deno executable and potentially reside in a trusted location.
    - Implement a warning message to be displayed when the user modifies the `deno.path` setting, emphasizing the security risks associated with pointing it to untrusted executables.
- Preconditions:
    - The user must have the VS Code Deno extension installed and activated.
    - The user must be tricked into changing the `deno.path` setting in VS Code to point to a malicious executable. This could be achieved through social engineering, phishing attacks, or by exploiting vulnerabilities in VS Code settings synchronization mechanisms.
- Source code analysis:
    - `client\src\util.ts`: The `getDenoCommandPath()` function is responsible for determining the path to the Deno executable.
        - It first checks the workspace configuration for the `deno.path` setting using `getWorkspaceConfigDenoExePath()`.
        - If `deno.path` is set, it uses this value. There is no validation or sanitization of this path at this stage.
        - If `deno.path` is a relative path, it attempts to resolve it relative to the workspace folders.
        - If `deno.path` is not set or resolution fails, it falls back to `getDefaultDenoCommand()`, which searches for "deno" in the system's PATH environment variable and default installation directories.
    - `client\src\commands.ts`: The `startLanguageServer()` function utilizes `getDenoCommandPath()` to obtain the Deno executable path.
        - The returned path is directly used to spawn the Deno Language Server process using `child_process.spawn` (indirectly via `vscode-languageclient`).
        - No checks are performed to validate the legitimacy or safety of the obtained executable path before execution.
    - `client\src\extension.ts`: Configuration changes to `deno.path` trigger a restart of the Deno Language Server via the `deno.client.restart` command, which in turn calls `startLanguageServer()`, leading to the execution of the executable specified in the potentially malicious `deno.path` setting.
    - Visualization:
        ```
        User Settings (deno.path) --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> startLanguageServer() --> LanguageClient (execute command) --> Arbitrary Code Execution
        ```
- Security test case:
    1. Create a malicious script (e.g., `malicious-deno.sh` for Linux/macOS or `malicious-deno.bat` for Windows) that performs an easily verifiable action, such as creating a file:
        - `malicious-deno.sh`:
          ```bash
          #!/bin/bash
          echo "Malicious Deno Executable Executed!" > /tmp/malicious_execution.txt
          ```
        - `malicious-deno.bat`:
          ```batch
          @echo off
          echo Malicious Deno Executable Executed! > %TEMP%\malicious_execution.txt
          ```
        - Ensure the script is executable (`chmod +x malicious-deno.sh`).
    2. Open VS Code and navigate to Settings (Ctrl+, or Cmd+,).
    3. Search for "deno.path" and locate the "Deno › Path" setting.
    4. Set the "Deno › Path" setting to the absolute path of the malicious script created in step 1 (e.g., `/path/to/malicious-deno.sh` or `C:\path\to\malicious-deno.bat`).
    5. Open a TypeScript or JavaScript file in VS Code to activate the Deno extension's Language Server, or execute the "Deno: Cache" command from the command palette (Ctrl+Shift+P or Cmd+Shift+P).
    6. Check for the indicator of malicious execution:
        - For `malicious-deno.sh`, check if the file `/tmp/malicious_execution.txt` exists and contains "Malicious Deno Executable Executed!".
        - For `malicious-deno.bat`, check if the file `%TEMP%\malicious_execution.txt` exists and contains "Malicious Deno Executable Executed!".
    7. If the file is created with the expected content, it confirms that the malicious script was executed by the VS Code Deno extension, demonstrating the arbitrary code execution vulnerability.
