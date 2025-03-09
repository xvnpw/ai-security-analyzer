- Vulnerability Name: Arbitrary Code Execution via Malicious Deno Path Configuration
  - Description:
    1. The VSCode Deno extension allows users to configure the path to the Deno executable using the `deno.path` setting.
    2. The extension uses this configured path to execute Deno commands, such as type checking, linting, formatting, and testing.
    3. An attacker can trick a user into setting `deno.path` to point to a malicious executable. This can be achieved through social engineering, where the attacker convinces the user to modify their VSCode settings.
    4. Once the user configures the malicious path, any Deno command executed by the extension will actually execute the malicious executable.
    5. This leads to arbitrary code execution on the user's machine with the privileges of the VSCode process.
  - Impact: Arbitrary code execution on the user's machine. An attacker can gain full control of the user's system, steal sensitive data, install malware, or perform other malicious actions.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - The `README.md` file contains a warning message about the `deno.path` setting, advising users to ensure they have a legitimate Deno CLI installed. This is a documentation-based mitigation.
  - Missing Mitigations:
    - Input validation: The extension does not validate the `deno.path` setting to ensure it points to a legitimate Deno executable.
    - Path sanitization: The extension does not sanitize the `deno.path` setting to prevent path traversal or other injection attacks.
    - User confirmation: The extension does not prompt the user for confirmation before executing a Deno command if the `deno.path` setting is configured.
    - Running Deno in a sandbox: The extension does not run the Deno CLI in a sandboxed environment to limit the impact of a malicious executable.
  - Preconditions:
    1. The user has installed the VSCode Deno extension.
    2. The user is tricked into configuring the `deno.path` setting in VSCode to point to a malicious executable.
    3. The Deno extension is enabled and attempts to execute a Deno command (e.g., upon opening a Deno project or manually triggering a Deno command).
  - Source Code Analysis:
    1. In `client\src\util.ts`, the `getDenoCommandPath()` function retrieves the `deno.path` setting from VSCode configuration:
       ```typescript
       function getWorkspaceConfigDenoExePath() {
         const exePath = workspace.getConfiguration(EXTENSION_NS)
           .get<string>("path");
         // ...
         return exePath;
       }
       ```
    2. This path is then used directly to spawn the Deno CLI process in `client\src\commands.ts`:
       ```typescript
       const serverOptions: ServerOptions = {
         run: {
           command, // This is the path from getDenoCommandPath()
           args: ["lsp"],
           options: { env },
         },
         debug: {
           command, // This is the path from getDenoCommandPath()
           args: ["lsp"],
           options: { env },
         },
       };
       const client = new LanguageClient(..., serverOptions, ...);
       await client.start();
       ```
    3. There is no validation or sanitization of the `command` variable before it is used in `child_process.spawn` (implicitly by `LanguageClient`). If `command` points to a malicious executable, it will be executed.
  - Security Test Case:
    1. Create a malicious executable file (e.g., `malicious-deno.sh` or `malicious-deno.bat`). This script should perform some harmless action for testing purposes, like creating a file named `pwned.txt` in the user's home directory and print "PWNED" to console.
       - `malicious-deno.sh`:
         ```bash
         #!/bin/bash
         echo "PWNED"
         touch $HOME/pwned.txt
         ```
       - `malicious-deno.bat`:
         ```batch
         @echo off
         echo PWNED
         echo > %USERPROFILE%\pwned.txt
         ```
    2. In VSCode, open settings (`Ctrl+,`).
    3. Search for "deno.path" setting.
    4. Set the "Deno › Path" setting to the absolute path of the malicious executable file created in step 1.
    5. Open a TypeScript or JavaScript file in VSCode.
    6. Ensure that the Deno extension is enabled for the workspace (if not enabled, run "Deno: Enable" command).
    7. Observe the output console of VSCode. You should see "PWNED" printed by the malicious script.
    8. Check your home directory. A file named `pwned.txt` should be created, indicating that the malicious script was executed by the VSCode Deno extension.
