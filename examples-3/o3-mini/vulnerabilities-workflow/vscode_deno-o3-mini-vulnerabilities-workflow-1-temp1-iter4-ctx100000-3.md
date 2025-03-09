# Vulnerability List

---

## Vulnerability Name: Untrusted Workspace “deno.path” Override Leading to Arbitrary Code Execution

**Description**:
The extension determines which Deno executable to run by reading the workspace configuration value for the setting `"deno.path"`. When a workspace is opened, the extension (via functions in `client/src/util.ts` and `client/src/commands.ts`) proceeds as follows:

1. It calls `getWorkspaceConfigDenoExePath()` to retrieve the `"deno.path"` value from the workspace settings.
2. It then calls `getDenoCommandPath()` to resolve the value (relative or absolute) and check that a file exists at that path.
3. Finally, `startLanguageServer()` uses the resolved executable path to spawn a new process with the argument `["lsp"]`.

An attacker can supply a malicious repository containing a manipulated `.vscode/settings.json` file with a payload such as:
```json
{
  "deno.path": "./malicious_executable"
}
```
In addition to this configuration, the attacker plants an executable file named `malicious_executable` in the repository. If the victim opens this repository in Visual Studio Code, the extension will resolve and verify that the file exists (without checking its authenticity), and then it will spawn the executable—thereby executing attacker‑controlled code.

**Impact**:
If exploited, the malicious executable will run within the context of the extension and, by extension, the user's environment. This can lead to arbitrary code execution on the victim’s machine, resulting in system compromise through data exfiltration, malware installation, or other malicious activities.

**Vulnerability Rank**:
Critical

**Currently Implemented Mitigations**:
- The extension checks for the existence of the file specified in `"deno.path"` using an asynchronous file system stat call (via the helper function `fileExists` in `client/src/util.ts`).

**Missing Mitigations**:
- No integrity or digital signature verification is performed on the executable specified by `"deno.path"`.
- No warning or explicit confirmation is offered to the user when workspace settings (potentially from an untrusted repository) override the user's global or trusted settings.
- The extension does not distinguish between user-configured settings and those supplied via repository content.

**Preconditions**:
- The victim opens a workspace that contains a manipulated `.vscode/settings.json` file with `"deno.path"` set to an attacker-controlled value (e.g., a path pointing to a malicious executable included in the repository).
- The malicious executable exists (or can be placed) at the indicated path and is marked as executable.
- The extension loads and automatically applies the workspace configuration without prompting the user to review or validate the settings.

**Source Code Analysis**:

- **Step 1:**
  In `client/src/util.ts`, the function `getWorkspaceConfigDenoExePath()` reads the `"deno.path"` value without verifying its origin:
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
  *Visualization:*
  `[workspace.getConfiguration] -> Retrieve "deno.path" -> Check empty string -> Return value`

- **Step 2:**
  The function `getDenoCommandPath()` in the same file processes the command path. For relative paths, it resolves them against each workspace folder and checks if a file exists:
  ```ts
  async function getDenoCommandPath() {
    const command = getWorkspaceConfigDenoExePath();
    const workspaceFolders = workspace.workspaceFolders;
    if (!command || !workspaceFolders) {
      return command ?? await getDefaultDenoCommand();
    } else if (!path.isAbsolute(command)) {
      for (const workspace of workspaceFolders) {
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
  *Visualization:*
  `[getWorkspaceConfigDenoExePath()] -> [Check if relative] -> [Iterate workspace folders] -> [Resolve and validate file exists] -> Return commandPath`

- **Step 3:**
  In `client/src/commands.ts`, `startLanguageServer()` calls `getDenoCommandPath()` and uses the returned value to spawn a new process:
  ```ts
  const command = await getDenoCommandPath();
  if (command == null) {
    // ... show error message ...
    return;
  }
  const serverOptions: ServerOptions = {
    run: { command, args: ["lsp"], options: { env } },
    debug: { command, args: ["lsp"], options: { env } },
  };
  ```
  This means that if a malicious `"deno.path"` is provided, the extension will spawn that executable with the argument `"lsp"`, leading directly to execution of attacker-controlled code.

**Security Test Case**:

1. **Setup**:
   - Create a repository that contains a `.vscode/settings.json` file with the following content:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
   - In the root of the repository, include an executable file named `malicious_executable`. Ensure it has the proper executable permissions. For testing, the executable can perform a lightweight action (e.g., create a file named `pwned.txt` or log a distinctive message).

2. **Execution**:
   - Open the repository in Visual Studio Code with the Deno extension installed.
   - Allow the workspace configuration (including the potentially manipulated `"deno.path"`) to load automatically.

3. **Observation**:
   - Monitor the extension’s output channel and the file system for the effect of the payload (e.g., check for the creation of `pwned.txt` or any log entries indicating execution of the malicious executable).
   - Verify that the language server startup process invokes the malicious executable instead of a legitimate Deno binary.

4. **Conclusion**:
   - If the payload (e.g., file creation or specific log messages) is observed, it confirms that the extension is improperly executing an untrusted executable, validating the vulnerability.

---
```

This updated list includes only the valid, unmitigated high-severity vulnerability related to Remote Code Execution, which is triggered by an attacker-supplied malicious repository.
