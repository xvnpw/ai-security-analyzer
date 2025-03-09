# Vulnerability List

## 1. Insecure Resolution of Deno Executable Path via Workspace Settings

**Description:**
The extension obtains the Deno executable path from the workspace configuration without proper validation. In particular, the function in `client/src/util.ts` named `getWorkspaceConfigDenoExePath()` simply returns the value of the `"deno.path"` setting from the workspace (typically defined in a repository’s `.vscode/settings.json`). Later, in the function `getDenoCommandPath()`, if the provided path is not absolute, it is resolved relative to the workspace folder. An attacker who provides a malicious repository can include a `.vscode/settings.json` that sets `"deno.path"` to a relative path pointing to an executable that the attacker also supplies (for example, a binary named `./malicious_exe`). When the extension starts the language server by invoking the command at that path, the malicious executable is launched—leading to potential remote code execution (RCE).

**Impact:**
When the user opens a workspace containing these settings, the extension will execute the attacker's supplied binary under the guise of launching the Deno language server. This can lead to full remote code execution (RCE) on the victim’s system, potentially compromising confidential data and system integrity.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension merely checks if the provided executable path is nonempty.
- There is a basic check (in `getDenoCommandPath()`) for whether the path is absolute, but no further sanitization or trust validation is performed on the workspace-provided value.

**Missing Mitigations:**
- No verification is performed to ensure that the value of `"deno.path"` points to a trusted, system-installed Deno executable.
- The extension does not require explicit user confirmation before using a workspace‑specified executable path.
- There is no mechanism to restrict the use of relative paths that resolve to files contained in the repository.

**Preconditions:**
- The victim must open a workspace (or repository) in VSCode that contains a malicious `.vscode/settings.json` file setting `"deno.path"` to a relative path (for example, `"./malicious_exe"`).
- The repository must include (or otherwise make available) the malicious executable at the resolved location.

**Source Code Analysis:**
1. **Reading the Setting:**
   - In `client/src/util.ts`, the function `getWorkspaceConfigDenoExePath()` reads the configured executable path using:
     ```ts
     const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
     ```
   - No sanitization is performed—the value is returned directly as provided by the workspace settings.

2. **Path Resolution:**
   - In `getDenoCommandPath()`, if the provided path is not absolute, the extension iterates over all workspace folders and calls:
     ```ts
     const commandPath = path.resolve(workspace.uri.fsPath, command);
     ```
   - This resolves a relative path (such as one set by a malicious repository) to a location within the repository.

3. **Command Execution:**
   - After resolving the path, an asynchronous check using `fs.stat` confirms the existence of the file. Once found, this path is passed along to the Language Client as the executable for the Deno language server.
   - No further checks are made to verify that the executable is the legitimate Deno binary.

4. **Result:**
   - An attacker who controls the repository’s settings can supply a relative path and include a malicious executable at that location. When the extension starts, it will resolve and execute the attacker's binary, enabling remote code execution (RCE).

**Security Test Case:**
1. **Setup:**
   - Create or fork a repository that includes a `.vscode/settings.json` file containing:
     ```json
     {
       "deno.path": "./malicious_exe"
     }
     ```
   - Include a file named `malicious_exe` (this could be a script or binary that, for testing, performs an easily observable action like writing a file to disk or displaying a UI message).

2. **Execution:**
   - Open the repository in Visual Studio Code with the vscode_deno extension installed.
   - Observe that when the extension initializes (e.g., when it attempts to start the Deno language server), it calls `getDenoCommandPath()`, which resolves `"./malicious_exe"` relative to the workspace.

3. **Verification:**
   - Use OS process tools or check for the expected side effect (e.g., creation of a file or alert) to confirm that the malicious executable is launched.
   - Optionally, modify the workspace settings to a safe value and verify that the malicious executable is not run.

4. **Expected Result:**
   - The test confirms that a workspace-provided `"deno.path"` value can force the extension to resolve and execute an arbitrary binary, verifying the existence of the remote code execution (RCE) vulnerability.
