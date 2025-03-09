# Vulnerability List

---

## 1. Arbitrary Command Execution via Malicious Workspace Configuration ("deno.path")

**Description:**
The extension reads the configuration value for the Deno executable path (“deno.path”) from the workspace settings (for example, from a file such as `.vscode/settings.json`). No validation or sanitization is performed on this setting. An attacker supplying a malicious repository can include a `.vscode/settings.json` file that sets the value of “deno.path” to a path referencing an attacker‑controlled executable (for example, a script named “malicious.sh” stored in the repository). When the victim opens this repository in Visual Studio Code, the extension calls functions like `getDenoCommandPath()` (in `util.ts`) and later uses that value when starting the language server (or executing tasks such as “upgrade”, “run”, or debugging commands). Because the executable path is taken directly from the workspace configuration without restrictions, the malicious code will be launched automatically during normal extension operations, thereby allowing arbitrary command execution.

**Impact:**
Exploiting this vulnerability would allow an attacker to execute arbitrary commands on the victim’s system in the context of the VSCode extension. This can result in full remote code execution (RCE) and may lead to a complete compromise of the system depending on the privileges under which VSCode is running.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension directly reads the “deno.path” value with no sanitization or whitelist checks.
- All calls to spawn a process (for starting the language server, tasks, etc.) rely on the value returned by `getDenoCommandPath()`, and no further validation is performed.

**Missing Mitigations:**
- **Input Validation/Whitelisting:** There is no check that the supplied “deno.path” points to a known, trusted executable (for example, by verifying that it is an absolute path in an approved directory).
- **User Confirmation:** No prompt is issued to the user when a workspace‑supplied “deno.path” differs from the user’s expected trusted configuration.
- **Policy/Defaults Enforcement:** The extension does not override or ignore suspicious “deno.path” settings when they originate from repository settings rather than user settings.

**Preconditions:**
- A malicious repository must include a workspace configuration file (e.g. `.vscode/settings.json`) that sets the key “deno.path” to a relative or absolute path pointing to an attacker‑controlled executable (for instance, a locally stored malicious script).
- The victim opens the repository in VSCode without having overridden or locked down the workspace settings in their global configuration.
- The extension functions that launch external processes (e.g. starting the language server, running upgrade or test tasks) will then use the supplied “deno.path” value.

**Source Code Analysis:**
- In **`util.ts`**, the helper function to retrieve the executable path is defined as follows:
  ```js
  function getWorkspaceConfigDenoExePath() {
    const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
    if (typeof exePath === "string" && exePath.trim().length === 0) {
      return undefined;
    } else {
      return exePath;
    }
  }
  ```
  This function directly returns the “deno.path” from the workspace configuration.
- The **`getDenoCommandPath()`** function then uses this value:
  ```js
  export async function getDenoCommandPath() {
    const command = getWorkspaceConfigDenoExePath();
    // If the command is not absolute, iterate over the workspace folders
    // to resolve the path.
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
  No sanitization or checks are performed on the value of `command`.
- In **`commands.ts`** (within the `startLanguageServer` function), the process to start the Deno Language Server is created using the result of `getDenoCommandPath()`:
  ```js
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
    debug: { ... }
  };
  ```
  Since the command value is taken directly from user‑controlled workspace configuration, a malicious “deno.path” will result in the attacker‑controlled executable being launched.

**Security Test Case:**
1. **Setup a Malicious Repository:**
   - Create a repository that includes a `.vscode/settings.json` file with the following content:
     ```json
     {
       "deno.path": "./malicious.sh"
     }
     ```
   - Also include a file named `malicious.sh` in the repository root. This file should be marked as executable and could contain:
     ```sh
     #!/bin/sh
     echo "Malicious code executed" > /tmp/exploit.txt
     # Additional malicious commands can be added here.
     ```
2. **Open the Repository:**
   - Open the repository in Visual Studio Code. Ensure that the workspace settings from the repository are loaded.
3. **Trigger the Vulnerable Functionality:**
   - Execute any command that causes the extension to resolve and spawn the Deno executable (for example, run the “Deno: Enable” command or trigger a language server restart).
4. **Observe and Verify:**
   - Verify that the malicious script `./malicious.sh` was executed. For instance, check that the file `/tmp/exploit.txt` was created or that the expected malicious output was produced.
5. **Conclusion:**
   - Confirm that a workspace‑supplied “deno.path” value allowed the execution of an arbitrary (attacker‑controlled) executable, demonstrating full remote code execution.
