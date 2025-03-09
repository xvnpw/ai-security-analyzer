# Combined Vulnerability List

The following lists have been consolidated into a single, comprehensive vulnerability description. This vulnerability leverages the lack of input validation and sanitization when resolving the Deno executable path from workspace settings, thereby enabling a remote code execution (RCE) attack.

---

## Vulnerability: Arbitrary Command Execution via Malicious Workspace Configuration ("deno.path")

### Description

The extension obtains the Deno executable path from the workspace configuration (typically from a repository’s `.vscode/settings.json` file) without performing any proper validation or sanitization. An attacker can exploit this behavior by crafting a malicious repository that includes a workspace settings file with the `"deno.path"` entry set to a relative or absolute path pointing to an attacker-controlled binary. When a victim opens this repository in Visual Studio Code—and implicitly trusts the workspace—the extension will resolve and use the provided executable path when starting the Deno language server or executing related commands. The following steps illustrate how an attacker can trigger this vulnerability:

1. **Crafting the Malicious Repository:**
   - The attacker creates or modifies a repository to include a workspace configuration file (e.g., `.vscode/settings.json`) with the following content:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
   - Alternatively, the attacker could use a relative path that navigates outside the expected directory (e.g., `"../../evil"`) if supported by the file resolution mechanism.

2. **Embedding the Malicious Executable:**
   - Along with the malicious settings file, the repository includes an executable (or script) named `malicious_executable` (or equivalent). This executable is designed to perform a clearly visible action (e.g., writing a file, displaying a notification, or logging a distinctive output) to demonstrate its execution.

3. **Workspace Trust and Activation:**
   - The victim opens the repository in Visual Studio Code. If the victim chooses to trust the workspace settings, the extension loads the workspace’s configuration.
   - During its initialization (such as when launching the language server), the extension calls helper functions like `getWorkspaceConfigDenoExePath()` and `getDenoCommandPath()`, which simply read and resolve the `"deno.path"` value without validation.

4. **Execution of the Attacker-Controlled Binary:**
   - Because the extension does not properly validate or sanitize the supplied `"deno.path"`, it resolves relative paths against the workspace folder and executes the binary found at the resulting location.
   - As a result, the attacker-controlled executable is launched, leading to arbitrary command execution with the privileges of the user running Visual Studio Code.

### Impact

If exploited, this vulnerability enables an attacker to execute arbitrary commands on the victim’s system. The malicious executable, running in the context of the VS Code extension, could perform actions such as:

- Writing or modifying files on disk.
- Installing or executing further malware.
- Exfiltrating sensitive data.
- Potentially compromising the entire system depending on the privileges available.

This represents a full remote code execution (RCE) scenario, thereby posing a critical security risk.

### Vulnerability Rank

**Critical**

### Currently Implemented Mitigations

- **Basic Existence and Absoluteness Check:**
  - The extension checks whether the `"deno.path"` value is nonempty.
  - It verifies if the provided executable path is absolute; if not, it resolves it relative to the workspace folder.

- **Reliance on Workspace Trust:**
  - The extension assumes the workspace configuration is trusted and does not enforce additional validation beyond the basic check.

*Note:* No additional verification (such as whitelisting, signature validation, or explicit user confirmation) is performed on the resolved path.

### Missing Mitigations

- **Input Validation / Whitelisting:**
  - There is no mechanism to validate the `"deno.path"` value against a whitelist or enforce that it points to a known, trusted Deno executable.

- **User Confirmation:**
  - The extension does not prompt the user for confirmation when a workspace supplies a custom `"deno.path"` that deviates from the global or trusted configuration.

- **Security Context Enforcement:**
  - The extension does not restrict or reject critical settings sourced solely from the workspace, even if the repository is untrusted.

- **Resistance to Relative Path Abuse:**
  - There is no safeguard against using relative paths that could resolve to unintended locations within the repository or file system.

### Preconditions

- **Malicious Repository Presence:**
  The victim must open a repository (or workspace) controlled by the attacker that includes a malicious `.vscode/settings.json` (or equivalent configuration) file with a manipulated `"deno.path"` value.

- **User Trust of Workspace Settings:**
  The victim must trust the workspace settings, thereby allowing the extension to load and act upon the configuration provided by the repository.

- **Attacker-Controlled Executable Availability:**
  The repository must bundle, or otherwise ensure the availability of, the malicious executable at the resolved path.

### Source Code Analysis

1. **Retrieving the Executable Path:**
   - In `client/src/util.ts`, the function `getWorkspaceConfigDenoExePath()` retrieves the Deno path setting:
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
   - **Observation:** The function directly returns the configuration value without any sanitization or validation.

2. **Path Resolution Process:**
   - The function `getDenoCommandPath()` uses the retrieved value to determine the command to execute:
     ```ts
     export async function getDenoCommandPath() {
       const command = getWorkspaceConfigDenoExePath();
       if (!command || !workspace.workspaceFolders) {
         return command ?? await getDefaultDenoCommand();
       } else if (!path.isAbsolute(command)) {
         for (const workspace of workspace.workspaceFolders) {
           const commandPath = path.resolve(workspace.uri.fsPath, command);
           if (await fileExists(commandPath)) {
             return commandPath;
           }
         }
         return undefined;
       } else {
         return command;
       }
     }
     ```
   - **Observation:** If the provided `"deno.path"` is not absolute, it is resolved relative to the workspace folder, and no further checks are performed to verify that the resolved file is a legitimate Deno executable.

3. **Process Execution:**
   - In `client/src/commands.ts`, within the `startLanguageServer()` function, the resolved command is used to launch the language server:
     ```ts
     const command = await getDenoCommandPath();
     if (command == null) {
       // Error handling omitted for brevity
       return;
     }
     const serverOptions: ServerOptions = {
       run: {
         command,
         args: ["lsp"],
         options: { env },
       },
       debug: { /* Debug configuration omitted */ }
     };
     ```
   - **Observation:** The command value—sourced directly from user-controlled workspace configuration—is passed to the process execution layer without ensuring that it is safe, opening the door to arbitrary command execution.

### Security Test Case

1. **Setup:**
   - Create a test repository containing a `.vscode/settings.json` file with the following content:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
   - In the repository root, include an executable file named `malicious_executable`. For testing purposes, the file might be a simple script (e.g., `malicious_executable.sh`) that contains:
     ```sh
     #!/bin/sh
     echo "Malicious code executed" > /tmp/exploit.txt
     ```
   - Ensure that the `malicious_executable` file has the appropriate executable permissions.

2. **Execution:**
   - Open the test repository in Visual Studio Code with the Deno extension installed.
   - Trust the workspace when prompted, so the extension loads the repository’s configuration settings.
   - Trigger the extension’s functionality that starts the language server (e.g., by running the “Deno: Enable” command).

3. **Verification:**
   - Observe that the extension calls `getDenoCommandPath()` and resolves the `"deno.path"` value to the path of `./malicious_executable`.
   - Confirm that the malicious executable is launched—e.g., check for the creation of the `/tmp/exploit.txt` file or monitor the expected log output.

4. **Conclusion:**
   - Successfully observing the execution of `malicious_executable` validates that a workspace-supplied `"deno.path"` setting can force the extension to execute an arbitrary, attacker-controlled executable, thereby demonstrating a full remote code execution vulnerability.

---

This consolidated description captures all the detailed aspects of the vulnerability as originally described in the separate lists.
