- Vulnerability Name: Malicious Deno Executable Path Configuration
- Description:
    1. An attacker social engineers a user to change the `deno.path` setting in VSCode. This could be achieved through phishing, providing misleading instructions on a website, or by compromising a project's workspace settings.
    2. The user is tricked into setting `deno.path` to point to a malicious executable, controlled by the attacker. For example, `C:\Temp\malicious_deno.exe` on Windows or `/tmp/malicious_deno` on Linux/macOS.
    3. The user reloads VSCode or restarts the Deno extension.
    4. The Deno extension, upon activation or restart, reads the `deno.path` setting and attempts to execute the specified path as the Deno CLI.
    5. Because `deno.path` now points to the malicious executable, the attacker's code is executed with the privileges of the VSCode process.
- Impact: Arbitrary code execution. Successful exploitation allows an attacker to execute arbitrary code on the user's machine with the same privileges as VS Code. This could lead to sensitive data theft, system compromise, installation of malware, or further malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The extension retrieves the path from settings and checks if the file exists, but it does not validate the path's legitimacy, origin, or integrity.
- Missing Mitigations:
    - Path validation: Implement validation for the `deno.path` setting to ensure it points to a legitimate Deno CLI executable. This could include:
        - Checking if the path is within expected Deno installation directories (OS-dependent).
        - Verifying the executable's digital signature to ensure it's signed by Deno authors.
        - Whitelisting known safe paths and warning users if a path outside these safe locations is configured.
    - User warning: If the `deno.path` setting is changed to a path that is considered unusual or potentially unsafe (e.g., outside standard installation directories), display a prominent warning to the user, prompting them to confirm and acknowledge the change.
- Preconditions:
    - The user must have the "Deno for Visual Studio Code" extension installed.
    - An attacker must successfully social engineer the user into modifying the `deno.path` setting in VSCode to point to a malicious executable.
- Source Code Analysis:
    - File: `client/src/util.ts`
        - Function: `getWorkspaceConfigDenoExePath()`
            - Retrieves the value of the `deno.path` configuration setting directly from VSCode's workspace configuration.
            - No validation or sanitization is performed on the retrieved path.
        - Function: `getDenoCommandPath()`
            - Calls `getWorkspaceConfigDenoExePath()` to obtain the configured path.
            - Checks if the path `fileExists()` using `fs.stat`. This check only verifies file existence and does not assess the file's legitimacy or safety.
        - Function: `getDefaultDenoCommand()`
            - Attempts to locate the `deno` executable in system PATH directories and default installation locations if `deno.path` is not explicitly set or is a relative path. This is a fallback mechanism if `deno.path` is not configured, but the extension prioritizes the user-provided `deno.path` setting.
        - Visualization:

        ```
        [VSCode Configuration] ----> getWorkspaceConfigDenoExePath() ----> getDenoCommandPath() ----> [Deno Extension execution]
                         ^
                         |
                       deno.path setting (user-controlled, no validation)
        ```
- Security Test Case:
    1. Setup:
        - Create a malicious executable file.
            - On Linux/macOS, create a file named `malicious_deno.sh` with the following content:
              ```bash
              #!/bin/bash
              echo "Malicious Deno Executed!" > /tmp/attack_log.txt
              ```
              Make it executable: `chmod +x malicious_deno.sh`
            - On Windows, create a file named `malicious_deno.bat` with the following content:
              ```bat
              @echo off
              echo Malicious Deno Executed! > C:\Temp\attack_log.txt
              ```
        - Place the malicious executable in a predictable location, e.g., `/tmp/malicious_deno` (Linux/macOS) or `C:\Temp\malicious_deno.bat` (Windows).
    2. VSCode Configuration:
        - Open VSCode with any workspace.
        - Navigate to VSCode Settings (File > Preferences > Settings or Code > Settings > Settings on macOS).
        - Search for `deno.path`.
        - In the "Deno: Path" setting, enter the path to the malicious executable created in step 1, e.g., `/tmp/malicious_deno` or `C:\Temp\malicious_deno.bat`.
    3. Trigger Extension Execution:
        - Reload VSCode (Developer: Reload Window command) or deactivate and reactivate the "Deno for Visual Studio Code" extension. This forces the extension to re-evaluate the `deno.path` setting.
        - Open any JavaScript or TypeScript file within the workspace to ensure the Deno extension's language server features are activated and the extension attempts to execute the Deno CLI.
    4. Verification:
        - Check for the execution of the malicious code by verifying the creation and content of the log file.
            - On Linux/macOS, check if `/tmp/attack_log.txt` exists and contains the text "Malicious Deno Executed!".
            - On Windows, check if `C:\Temp\attack_log.txt` exists and contains the text "Malicious Deno Executed!".
        - If the log file exists with the expected content, it confirms arbitrary code execution through the maliciously configured `deno.path` setting, validating the vulnerability.
