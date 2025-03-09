- Vulnerability name: Malicious Deno Path Configuration
- Description:
    - An attacker could socially engineer a user into changing the `deno.path` setting in Visual Studio Code.
    - The user is tricked into setting `deno.path` to point to a malicious executable instead of the legitimate Deno CLI.
    - When the VS Code Deno extension attempts to invoke Deno for various operations (like formatting, linting, testing, caching, or language server functionalities), it will execute the malicious executable specified in `deno.path`.
- Impact:
    - Arbitrary code execution on the user's machine.
    - This can lead to a wide range of malicious activities, including:
        - Data theft: The malicious script could access and exfiltrate sensitive information from the user's system.
        - Malware installation: The attacker could use the code execution to download and install malware on the user's machine.
        - System compromise: The attacker could gain persistent access to the user's system, potentially leading to further attacks or control.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - The `README.md` file contains a warning message in the "Important" section, advising users to "explicitly set the path to the executable in Visual Studio Code Settings for `deno.path`."
    - This warning serves as documentation to mitigate the risk by informing users about the setting, but it does not actively prevent a user from configuring a malicious path.
- Missing mitigations:
    - Input validation for the `deno.path` setting: The extension should validate the path provided by the user to ensure it is likely to be a legitimate Deno executable. This could include:
        - Checking if the executable exists at the given path.
        - Verifying the file signature of the executable against a known Deno signature (more complex and might require updates for new Deno versions).
        - Checking if the path is within a typical installation directory for Deno (e.g., `/usr/bin/deno`, `C:\Program Files\deno\deno.exe`, `~/.deno/bin/deno`).
    - Warning message on settings change: Display a prominent warning message when a user modifies the `deno.path` setting, especially if the path is unusual or outside of expected locations. This warning should explicitly mention the security risks of pointing to untrusted executables.
    - Path restriction: Provide an option to restrict the `deno.path` setting, allowing only paths within a predefined safe list of directories or requiring explicit user confirmation for paths outside these directories.
- Preconditions:
    - The user has the "Deno for Visual Studio Code" extension installed.
    - An attacker successfully employs social engineering techniques to convince the user to modify the `deno.path` setting in VS Code to point to a malicious executable. This could be achieved through phishing, misleading instructions, or by exploiting user trust.
- Source code analysis:
    - `client\src\util.ts`:
        - Function `getDenoCommandPath()` is responsible for resolving the path to the Deno executable.
        - It first checks the `deno.path` setting from VS Code configuration (`getWorkspaceConfigDenoExePath()`).
        - If `deno.path` is set, the extension directly uses this path, without any validation, to execute Deno commands.
        - If `deno.path` is not set or is a relative path, it attempts to resolve the "deno" command from the environment path.
        - There is no input validation or sanitization performed on the `deno.path` setting before it is used in process execution.
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath(); // Retrieves deno.path setting
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand();
          } else if (!path.isAbsolute(command)) {
            // ... relative path resolution ...
          } else {
            return command; // Directly returns user-provided path without validation
          }
        }
        ```
    - `client\src\extension.ts`, `client\src\debug_config_provider.ts`, `client\src\tasks.ts`, `client\src\commands.ts`:
        - These files import and use `getDenoCommandName()` (which calls `getDenoCommandPath()`) to obtain the Deno executable path.
        - They then use this path to spawn child processes for various Deno commands (e.g., `deno lsp`, `deno run`, `deno test`, `deno cache`).
        - Because `getDenoCommandPath()` directly returns the user-configured path without validation, these features will execute whatever executable path is provided in `deno.path`.

- Security test case:
    1. Setup:
        - Create a directory named `malicious_deno` in a temporary location.
        - Inside `malicious_deno`, create a file named `malicious-deno.sh` (for Linux/macOS) or `malicious-deno.bat` (for Windows) with the following content:
            - `malicious-deno.sh`:
              ```bash
              #!/bin/bash
              echo "Malicious Deno Executable Executed!" > /tmp/malicious_execution.txt
              # Optionally, execute a legitimate deno command to avoid immediate errors from the extension
              /usr/bin/env deno "$@"
              ```
            - `malicious-deno.bat`:
              ```batch
              @echo off
              echo Malicious Deno Executable Executed! > %TEMP%\malicious_execution.txt
              # Optionally, execute a legitimate deno command to avoid immediate errors from the extension
              deno %*
              ```
            - Make the script executable: `chmod +x malicious-deno.sh` (Linux/macOS).
        - Ensure you have a legitimate Deno CLI installed and know its actual path (e.g., `/usr/bin/deno` on Linux/macOS, or where it's installed on Windows).  Modify the optional "legitimate deno command" part in the malicious script to point to your actual Deno path if you include it. If you don't include it, expect errors from the extension, but the vulnerability is still demonstrable by the file creation.

    2. VS Code Configuration:
        - Open Visual Studio Code.
        - Open settings (File > Preferences > Settings or Code > Settings on macOS).
        - Search for "deno.path".
        - Set the `Deno › Path` setting to the absolute path of your malicious script (e.g., `/tmp/malicious_deno/malicious-deno.sh` or `C:\Users\YourUser\AppData\Local\Temp\malicious_deno\malicious-deno.bat`).
        - Ensure Deno is enabled for the workspace (`deno.enable` is true, or a `deno.json` file exists in the workspace root).

    3. Trigger Vulnerability:
        - Open any Deno project or a JavaScript/TypeScript file in a Deno-enabled workspace.
        - Execute any Deno extension command that invokes the Deno CLI. Examples:
            - Format the current document (Format Document command).
            - Run tests (if tests are defined and test code lens is enabled).
            - Cache dependencies (Deno: Cache command).
            - Trigger any language server feature that implicitly invokes Deno.

    4. Verification:
        - Check for the execution of the malicious script:
            - Verify that the file `/tmp/malicious_execution.txt` (Linux/macOS) or `%TEMP%\malicious_execution.txt` (Windows) has been created and contains the text "Malicious Deno Executable Executed!".
        - If you included the optional legitimate Deno command in the malicious script, the Deno extension features might appear to function partially, but the malicious action (file creation) confirms arbitrary code execution. If you didn't include it, the extension might show errors because the malicious script might not fully emulate the Deno CLI, but the file creation still confirms the vulnerability.

This test case demonstrates that by setting `deno.path` to a malicious executable, an attacker can achieve arbitrary code execution when using the VS Code Deno extension.
