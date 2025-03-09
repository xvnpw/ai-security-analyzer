### Vulnerability List

- Vulnerability Name: Malicious Deno Executable Path Configuration
- Description:
    1. An attacker tricks a user into configuring the `deno.path` setting in Visual Studio Code.
    2. The user is persuaded to set this setting to point to a malicious executable file instead of the legitimate Deno CLI executable.
    3. The attacker might use social engineering, phishing, or provide a malicious workspace configuration to achieve this.
    4. Once the `deno.path` is set to the malicious executable, the VS Code Deno extension will use this path.
    5. When the extension attempts to execute Deno CLI commands for features like type checking, linting, formatting, testing, or caching, it will inadvertently execute the malicious executable.
- Impact:
    - Arbitrary code execution on the user's system.
    - The malicious executable runs with the same privileges as the VS Code process, which is typically the user's privileges.
    - Potential consequences include:
        - Data theft: The malicious script could access and exfiltrate sensitive information from the user's file system or environment.
        - Malware installation: The script could download and install malware on the user's system.
        - System compromise: The attacker could gain complete control over the user's system, depending on the nature of the malicious executable.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Documentation in `README.md` provides a brief note: "You can explicitly set the path to the executable in Visual Studio Code Settings for `deno.path`." This serves as a minimal warning but does not prevent the vulnerability.
- Missing Mitigations:
    - Input validation for the `deno.path` setting. The extension should verify if the provided executable path is likely to be a legitimate Deno CLI. This could involve:
        - Checking the executable's name (e.g., ensuring it is named `deno` or `deno.exe`).
        - Checking the file signature or hash to match known Deno CLI versions (complex and requires maintenance).
        - Validating the location of the executable, possibly warning if it's outside of standard installation directories.
    - A warning prompt should be displayed to the user when they modify the `deno.path` setting, especially if the new path is unusual or potentially dangerous. This prompt should emphasize the security risks of pointing to untrusted executables.
    - Enhance documentation in `README.md` and potentially in the extension settings UI to clearly and prominently warn users about the security implications of modifying the `deno.path` setting and advise them to only point it to trusted Deno CLI executables.
- Preconditions:
    - The VS Code Deno extension must be installed and activated.
    - The user must have the ability to modify VS Code settings.
    - The attacker must successfully trick the user into changing the `deno.path` setting to a malicious executable.
- Source Code Analysis:
    1. `client/src/util.ts`: The `getDenoCommandPath()` function is responsible for resolving the Deno executable path.
    2. `getDenoCommandPath()` first retrieves the path configured in VS Code settings using `getWorkspaceConfigDenoExePath()`.
    3. `getWorkspaceConfigDenoExePath()` directly fetches the string value of the `deno.path` setting without any validation.
    4. If a path is configured, `getDenoCommandPath()` checks if it is absolute. If relative, it attempts to resolve it against workspace folders. There is no check to validate if this path is safe or points to a legitimate Deno executable.
    5. If no path is set in settings or the configured path is invalid, `getDefaultDenoCommand()` is called to search for `deno` in the system's PATH and default installation directories.
    6. `client/src/commands.ts`: The `startLanguageServer()` function calls `getDenoCommandPath()` to obtain the executable path.
    7. The obtained path is then used to spawn a child process for the Deno Language Server:
       ```typescript
       const serverOptions: ServerOptions = {
           run: {
               command, // Path obtained from getDenoCommandPath()
               args: ["lsp"],
               options: { env },
           },
           debug: {
               command, // Path obtained from getDenoCommandPath()
               args: ["lsp"],
               options: { env },
           },
       };
       const client = new LanguageClient( ... , serverOptions, ... );
       ```
    8. **Visualization:**

    ```mermaid
    graph LR
        subgraph client/src/commands.ts
            startLanguageServer --> getDenoCommandPath
            startLanguageServer --> LanguageClient
        end
        subgraph client/src/util.ts
            getDenoCommandPath --> getWorkspaceConfigDenoExePath
            getDenoCommandPath --> getDefaultDenoCommand
            getWorkspaceConfigDenoExePath --> vscodeSettings(vscode.workspace.getConfiguration('deno').get('path'))
        end
        vscodeSettings --> userConfiguration{User Configuration "deno.path"}
        userConfiguration --> maliciousPath{Malicious Executable Path}
        maliciousPath --> LanguageClientExecution{Execution of Malicious Executable}
    ```
    9. The code directly uses the path from settings without any sanitization or validation, leading to the execution of whatever executable path the user configures.

- Security Test Case:
    1. **Preparation:**
        - Create a malicious script file.
            - For example, on Linux/macOS, create `malicious_deno.sh` with:
              ```sh
              #!/bin/bash
              echo "Malicious Deno Executed!"
              echo "This is just a test, but in a real attack, harmful commands could be executed."
              exit 1
              ```
              Make it executable: `chmod +x malicious_deno.sh`
            - On Windows, create `malicious_deno.bat` with:
              ```bat
              @echo off
              echo Malicious Deno Executed!
              echo This is just a test, but in a real attack, harmful commands could be executed.
              exit /b 1
              ```
        - Place this malicious script in a known location (e.g., your home directory or a temporary folder).
    2. **VS Code Configuration:**
        - Open Visual Studio Code.
        - Open the Settings (File > Preferences > Settings > Settings or Code > Settings > Settings on macOS).
        - Search for "deno path".
        - Locate the "Deno › Path" setting.
        - Set the "Deno › Path" setting to the absolute path of the malicious script created in step 1.
            - Example: `/path/to/malicious_deno.sh` or `C:\path\to\malicious_deno.bat`.
    3. **Trigger Extension Functionality:**
        - Open any JavaScript or TypeScript file in VS Code.
        - Ensure the Deno extension is enabled for the workspace (you might need to run "Deno: Enable" command or have a `deno.json` file).
        - Trigger any Deno extension feature that utilizes the Deno CLI. For example:
            - Format the current document (Format Document command).
            - Run Deno cache command (Deno: Cache command).
            - Run Deno lint command (if enabled).
    4. **Verification:**
        - Observe the output. You should see the message "Malicious Deno Executed!" in:
            - The VS Code Output panel (usually under "Deno Language Server" output channel).
            - Potentially in a terminal window if the malicious script opens one or writes to standard output/error streams that are captured by VS Code.
        - The presence of this message confirms that the malicious script was executed because the `deno.path` setting was successfully manipulated.

This test case demonstrates that by changing the `deno.path` setting, a malicious executable can be run by the VS Code Deno extension, confirming the vulnerability.
