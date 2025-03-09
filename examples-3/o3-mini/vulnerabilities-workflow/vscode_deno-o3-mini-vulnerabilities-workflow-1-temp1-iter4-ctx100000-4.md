# Vulnerability List

## Vulnerability: Arbitrary Command Execution via Malicious “deno.path” Configuration

**Description:**
The extension reads the “deno.path” value from the user’s workspace settings (for example, from a .vscode/settings.json or a deno.json[c] file). A malicious repository can include a configuration that sets “deno.path” to a relative path pointing to an attacker‑controlled executable (for example, `"deno.path": "./malicious_executable"`). When the victim opens the repository in VS Code and (directly or indirectly) enables Deno support, the extension calls its utility function to resolve this path. Since the code only checks that a file exists (using a basic fs.stat check) and then passes that string as the command to spawn a new process for the Deno language server, the malicious executable is launched instead of the intended Deno CLI.

_Step by step:_
1. The attacker creates a repository that includes a malicious executable file (e.g., a script or binary named “malicious_executable”) and a configuration file (such as .vscode/settings.json) in which “deno.path” is set to a relative path (e.g. `"./malicious_executable"`).
2. The victim clones or opens this repository in VS Code.
3. The extension reads the workspace configuration via the call to `workspace.getConfiguration(EXTENSION_NS).get("path")` inside `getDenoCommandPath()` (in client/src/util.ts).
4. Because the setting is relative, the function resolves it against the workspace folder and confirms its existence (with `fs.stat`), without checking whether this file is from a trusted source.
5. The resolved path is then passed to the function `startLanguageServer()` (in client/src/commands.ts) where it is used as the command that launches the language server process (using an API such as child_process.spawn via the LanguageClient’s serverOptions).
6. As a result, the malicious executable gets executed with the victim’s privileges, enabling arbitrary command execution.

**Impact:**
An attacker can execute arbitrary commands on the victim’s system with the same privilege level as the user running VS Code. This may result in full system compromise, data exfiltration, installation of malware, or any other arbitrary code execution outcome.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- The code performs a simple file‑existence check (using `fs.stat`) on the path supplied via “deno.path”.
- No further validation is performed on the source or trustworthiness of the provided path, and there is no check to prevent relative paths from being used as the command.

**Missing Mitigations:**
- Validation and sanitization of configuration input (in particular, the “deno.path” setting) to confirm that it points to a known, trusted installation of the Deno executable.
- An explicit restriction to require an absolute path instead of accepting arbitrary relative paths from the workspace.
- Additional user confirmation or warnings when a workspace’s configuration file attempts to override a critical parameter like “deno.path”.

**Preconditions:**
- The victim opens a repository (or workspace) that contains a configuration file (e.g., .vscode/settings.json or deno.json[c]) with “deno.path” set to an attacker‑controlled relative path.
- A malicious executable file exists at the indicated (relative) location within the repository.
- The Deno extension is activated (i.e., “deno.enable” is true, either globally or per‑workspace).

**Source Code Analysis:**
1. **Retrieving the Setting:**
   - In `client/src/util.ts`, the function `getDenoCommandPath()` calls:
     ```js
     const command = getWorkspaceConfigDenoExePath();
     ```
     This reads the “deno.path” setting from the workspace configuration.

2. **Path Resolution:**
   - If the retrieved path is not absolute, the function iterates over each workspace folder and resolves it using `path.resolve(workspaceFolder.uri.fsPath, command)`.

3. **Existence Check:**
   - The code uses `fs.stat` to verify that the file exists; however, it does not check whether it is the legitimate Deno binary.

4. **Process Execution:**
   - In `client/src/commands.ts`, the resolved command is used in the creation of the `serverOptions` for the LanguageClient:
     ```js
     const serverOptions: ServerOptions = {
       run: { command, args: ["lsp"], options: { env } },
       debug: { command, args: ["lsp"], options: { env } },
     };
     ```
     This results in the attacker‑controlled executable being spawned whenever the language server (or related commands) is initiated.

**Security Test Case:**
1. **Prepare a Malicious Repository:**
   - Create a repository that includes a file at the root (e.g., “malicious_executable”).
   - Make “malicious_executable” an executable script or binary that, when run, performs an easily detectable action (for testing, it might write a specific file to disk or log to a preset location).
   - In the repository’s `.vscode/settings.json`, include the following configuration:
     ```json
     {
       "deno.enable": true,
       "deno.path": "./malicious_executable"
     }
     ```

2. **Execute the Test:**
   - Open the repository in Visual Studio Code with the Deno extension installed.
   - Trigger the activation of the Deno language server (for example, by using the “Deno: Enable” command or by opening a Deno‑related file).
   - Monitor the system to verify that “malicious_executable” is executed (e.g., check for the expected file creation, log entries, or other behavior indicating that the executable was run).

3. **Expected Outcome:**
   - The malicious executable is launched instead of the legitimate Deno CLI, thereby confirming that the manipulated “deno.path” configuration leads to arbitrary command execution.
