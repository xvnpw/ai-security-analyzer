- **Vulnerability Name:** Malicious Deno Path Override Leading to Arbitrary Code Execution

  - **Description:**
    An attacker who can inject or commit a malicious workspace configuration file (for example, a `.vscode/settings.json`) may set the `"deno.path"` setting to point not to the authentic Deno CLI binary but to a malicious executable. When the extension starts the Deno language server, it calls a helper function to read this setting without further sanitization or integrity verification. The returned value is then passed directly as the executable command in a process‐spawn call (via the LanguageClient), resulting in the execution of the (potentially untrusted) binary. An attacker can therefore trigger arbitrary commands or code execution on the victim’s machine.

  - **Impact:**
    - Execution of attacker-controlled code in the context of the user running VS Code.
    - Potential full system compromise if the malicious binary is designed to escalate privileges.
    - Unauthorized access to sensitive data or system modifications.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The extension reads configuration via VS Code’s settings API (using `workspace.getConfiguration`) but does not perform any additional validation of the provided path value.
    - The code does check whether the value is non-empty and, if relative, attempts to resolve it against workspace folder paths. It also makes a basic file existence check (through an asynchronous `fileExists` function) when resolving a relative path.

  - **Missing Mitigations:**
    - **Input Validation/Sanitization:** There is no verification to ensure that the provided `"deno.path"` points to a known, trusted, and expected Deno binary.
    - **Whitelist Enforcement:** The extension does not compare the provided path against a whitelist of permitted directories or file signatures.
    - **Integrity Verification:** There is no check for the binary’s version or integrity before using it to spawn a process.
    - **User Warning:** No explicit warning is raised when an unusual or non-standard executable path is provided.

  - **Preconditions:**
    - The attacker must be able to insert or modify the workspace configuration (for example, by committing a malicious `.vscode/settings.json` into a repository, or by exploiting auto-loaded settings).
    - The victim must open the affected workspace in Visual Studio Code with the Deno extension enabled.
    - The system’s file permissions must allow execution of the file specified in `"deno.path"`.

  - **Source Code Analysis:**
    1. **Configuration Reading:**
       In `client/src/util.ts`, the function `getWorkspaceConfigDenoExePath()` retrieves the value of `"deno.path"` from the extension’s configuration without sanitizing its content:
       ```ts
       function getWorkspaceConfigDenoExePath() {
         const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
         if (typeof exePath === "string" && exePath.trim().length === 0) {
           return undefined;
         } else {
           return exePath;
         }
       }
       ```
    2. **Determining the Command:**
       The function `getDenoCommandPath()` calls `getWorkspaceConfigDenoExePath()`. If the returned path is absolute, no further checks are performed:
       ```ts
       export async function getDenoCommandPath() {
         const command = getWorkspaceConfigDenoExePath();
         // …if command is absolute, simply return it:
         } else {
           return command;
         }
       }
       ```
    3. **Process Spawning:**
       In `client/src/commands.ts`, the `startLanguageServer` function awaits the command value by calling `getDenoCommandPath()` and then constructs the server options:
       ```ts
       const command = await getDenoCommandPath();
       const serverOptions: ServerOptions = {
         run: { command, args: ["lsp"], options: { env } },
         debug: { command, args: ["lsp"], options: { env } }
       };
       ```
       This value is then passed directly into the LanguageClient, which under the hood spawns a child process without further validation.
    4. **Risk:**
       If an attacker supplies a malicious executable path via `"deno.path"`, the extension will launch that binary when starting the Deno language server. Because there is no whitelist, signature/integrity check, or user confirmation before executing this file, it opens the door for arbitrary code execution.

  - **Security Test Case:**
    1. **Setup:**
       - Create a test workspace and add a `.vscode/settings.json` file.
       - In this file, set:
         ```json
         {
           "deno.path": "/tmp/malicious_deno"
         }
         ```
       - On a test Unix system, create an executable file at `/tmp/malicious_deno` with the following content (this is a benign payload for testing):
         ```bash
         #!/bin/bash
         echo "Malicious payload executed" > /tmp/hacked.txt
         ```
         Then give it executable permission (e.g., `chmod +x /tmp/malicious_deno`).
    2. **Execution:**
       - Open the test workspace in Visual Studio Code.
       - Ensure that the Deno extension is active (for example, by running the “Deno: Enable” command or opening a Deno project file so that the language server starts).
       - Observe that the extension calls `getDenoCommandPath()`, which returns your provided `/tmp/malicious_deno`.
    3. **Verification:**
       - After the extension starts (or attempts to start the language server), check for the presence of the file `/tmp/hacked.txt` in your filesystem.
       - If the file exists and contains the expected text, it demonstrates that the malicious executable was run.
    4. **Cleanup:**
       - Remove the `/tmp/malicious_deno` file and `/tmp/hacked.txt` after testing.
