## Combined Vulnerability List

### Arbitrary Code Execution via Malicious `deno.path` Configuration

- **Vulnerability Name:** Arbitrary Code Execution via Malicious `deno.path` Configuration
- **Description:**
    1. A malicious actor can trick a user into configuring the `deno.path` setting in their VS Code workspace to point to a malicious executable instead of the legitimate Deno CLI. This could be achieved through social engineering, phishing, or by compromising a user's settings synchronization.
    2. The attacker provides the user with a path that points to a malicious executable file, instead of the legitimate Deno CLI executable. This malicious executable can be located anywhere on the user's file system or even a network share accessible to the user.
    3. The user, believing they are improving or customizing their Deno extension setup, or simply following attacker's instructions, configures the `deno.path` setting with the malicious path.
    4. Subsequently, when the VS Code Deno extension needs to execute Deno CLI commands for various features like language server functionalities (type checking, linting, formatting, testing, caching, etc.), or debugging and tasks execution, it retrieves the configured `deno.path`.
    5. Instead of invoking the genuine Deno CLI, the extension unknowingly executes the malicious executable specified in `deno.path`.
    6. The malicious executable now runs with the privileges of the user who is running VS Code, allowing the attacker to execute arbitrary code on the user's machine, potentially performing data theft, malware installation, or system compromise.
- **Impact:**
    - Critical. Successful exploitation of this vulnerability allows for arbitrary code execution on the user's machine. An attacker could potentially gain full control of the user's system, steal sensitive data, install malware, or perform other malicious actions. Full compromise of the user's local system with the privileges of the user running VS Code.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - Documentation Warning: The extension's README.md includes a warning in the "Important" section, advising users to ensure `deno.path` points to the legitimate Deno CLI and providing a link to Deno CLI installation instructions.
        - File: `vscode_deno\README.md`
        - Content Snippet:
          ```markdown
          > ⚠️ **Important:** You need to have a version of Deno CLI installed (v1.13.0 or
          > later). The extension requires the executable and by default will use the
          > environment path. You can explicitly set the path to the executable in Visual
          > Studio Code Settings for `deno.path`.
          >
          > [Check here](https://docs.deno.com/runtime/) for instructions on how to
          > install the Deno CLI.
          ```
    - None. The code currently reads the `deno.path` setting from the VS Code configuration and directly uses it to execute the command without any validation or sanitization. There are no checks to verify if the provided path is a legitimate Deno executable or to restrict the path to specific locations in the code itself.
- **Missing Mitigations:**
    - Input validation for the `deno.path` setting: The extension should validate the provided path to ensure it is likely to be a legitimate Deno executable. This could include checks such as:
        - Verifying that the file exists at the specified path.
        - Checking the file extension to ensure it is an executable format for the operating system (e.g., `.exe` on Windows, executable permissions on Linux/macOS).
        - Potentially checking the file's digital signature or hash against known Deno CLI signatures (though this might be complex to maintain).
        - Validating the path against a list of allowed or disallowed directories to prevent execution from obviously suspicious locations (e.g., temporary directories).
    - User warnings: When the `deno.path` setting is changed by the user, especially if it deviates from the default behavior of using the environment path, the extension should display a prominent warning message. This warning should highlight the security risks associated with using custom executable paths and advise users to only set this path if they are absolutely sure it points to a trusted Deno CLI executable. Absence of a security warning when a user modifies the `deno.path` setting, especially if the new path is outside of standard program installation directories. A warning could alert users to the security implications of pointing this setting to untrusted executables.
    - Recommendation against using `deno.path`: The extension's documentation and UI could be updated to strongly recommend relying on the Deno CLI being available in the system's PATH environment variable. Setting `deno.path` should be presented as an advanced option for specific use cases and discouraged for general users to minimize the risk of misconfiguration.
    - Executable Integrity Check: Missing integrity check for the executable specified in `deno.path`. The extension could implement checks to verify the authenticity or signature of the Deno CLI executable, although this might be complex to implement robustly across platforms.
- **Preconditions:**
    - User Installs VS Code Deno Extension: The user must have the `denoland.vscode-deno` extension installed in Visual Studio Code.
    - A workspace must be opened in VS Code.
    - User Modifies `deno.path` Setting: The attacker needs to trick the user into manually changing the `deno.path` setting within VS Code's settings to point to a malicious executable. The user must have the ability to modify workspace settings or be tricked into importing malicious settings.
    - The user must have write access to a location on their file system where the attacker can place the malicious executable, or the attacker must provide a path to a malicious executable hosted on a network share accessible to the user.
- **Source Code Analysis:**
    - Vulnerable Code Location: `client\src\util.ts` in the `getDenoCommandPath` function and `getWorkspaceConfigDenoExePath` function.
    - Step-by-step analysis:
        - 1. Function `getDenoCommandPath` is called to determine the path to the Deno executable.
        - 2. It retrieves the configured path from VS Code settings using `getWorkspaceConfigDenoExePath()`. This function reads the `deno.path` setting using `vscode.workspace.getConfiguration(EXTENSION_NS).get<string>("path")`.
        - 3. If `deno.path` is configured (and is not blank), `getDenoCommandPath` prioritizes this user-defined path.
        - 4. If `deno.path` is not set or is blank, the function falls back to searching for 'deno' in the system's PATH and default installation directories (`getDefaultDenoCommand`).
        - 5. **Vulnerability:** The code directly uses the path from `deno.path` setting without any validation or security checks. If a malicious path is provided, it will be used to execute commands. There is **no validation** of the `command` variable obtained from `getWorkspaceConfigDenoExePath()`. The function directly returns this path (after potential relative path resolution) without any checks to ensure it points to a valid or safe executable. `getWorkspaceConfigDenoExePath()` function simply retrieves the `deno.path` configuration setting and **does not perform any validation** on the content of the `exePath` string itself.
        - 6. The resolved command path is then used in `client\src\commands.ts` to spawn the Deno language server process and in `client\src\debug_config_provider.ts` for debugging and tasks execution, and in other parts of the extension like `tasks.ts`. In the `startLanguageServer()` function in `client\src\commands.ts`, the `command` variable, which is the potentially malicious path obtained from `getDenoCommandPath()`, is directly used within the `serverOptions` to define how the Language Server process is launched. The `LanguageClient` then uses these `serverOptions` to execute the specified command. Because there is no validation before this point, a malicious executable path configured in `deno.path` will be executed.
    - Visualization:
      ```
      UserSettings (deno.path) --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> ProcessExecution (client/src/commands.ts, client/src/debug_config_provider.ts, tasks.ts) --> System Command Execution
      ```
      ```mermaid
            graph LR
                subgraph VS Code Configuration
                    A[deno.path Setting]
                end
                subgraph client\src\util.ts
                    B[getWorkspaceConfigDenoExePath()] --> A
                    C[getDenoCommandPath()] --> B
                    D[getDenoCommandName()] --> C
                    E[ProcessExecution in tasks.ts/debug_config_provider.ts etc.] --> D
                end
                A --> B
                C --> E
            ```
- **Security Test Case:**
    - Step 1: Setup - Install VS Code and the Deno extension. Create a malicious script file, for example `malicious_deno.sh` (for Linux/macOS) or `malicious_deno.bat` (for Windows), which contains code to demonstrate arbitrary command execution (e.g., display a message and create a file in a temporary directory).
        - Example `malicious_deno.sh`:
          ```bash
          #!/bin/bash
          echo "[MALICIOUS DENO EXECUTABLE]: Executed with user ID: $(id -u)"
          echo "Malicious Deno Executable is running!"
          date > /tmp/malicious_execution.txt
          exit 1
          ```
        - Make the script executable (`chmod +x malicious_deno.sh`).
        - Example `malicious-deno.bat`:
            ```batch
            @echo off
            echo [MALICIOUS DENO EXECUTABLE]: Executed by user: %USERNAME%
            echo Malicious Deno Executable is running!
            date > %TEMP%\malicious_execution.txt
            exit 1
            ```
    - Step 2: Configuration - Open VS Code settings and locate the `deno.path` setting. Set the value of `deno.path` to the absolute path of the malicious script (e.g., `/path/to/malicious_deno.sh` or `C:\path\to\malicious_deno.bat`). Ensure to use absolute path.
    - Step 3: Trigger Vulnerability - Open any Deno or TypeScript project in VS Code. Open the command palette (Ctrl+Shift+P or Cmd+Shift+P) and execute the command "Deno: Cache". Alternatively, you can try "Deno: Initialize Workspace Configuration", "Deno: Run Tests" or format a document with Deno. This action triggers the extension to invoke the Deno CLI.
    - Step 4: Verification - Check the output. You should see the message "Malicious Deno Executable is running!" in the terminal or output window depending on how the extension handles output. Open the Output panel in VS Code (View -> Output). In the dropdown menu at the top-right of the Output panel, select "Deno Language Server". Check the output for the message from malicious script. Verify that the file `/tmp/malicious_execution.txt` (or `%TEMP%\malicious_execution.txt` on Windows) has been created, confirming that the malicious script was executed instead of the real Deno CLI.
