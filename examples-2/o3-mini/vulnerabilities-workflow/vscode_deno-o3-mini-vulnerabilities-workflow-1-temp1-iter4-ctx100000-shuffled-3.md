# Vulnerability List

---

## 1. Arbitrary Executable Path Injection via Workspace “deno.path” Setting

**Description:**
The extension reads the value of the “deno.path” setting from the workspace configuration (e.g., from a repository’s .vscode/settings.json file) without any validation or sanitization. An attacker can craft a malicious repository with a settings file where “deno.path” is set to the path of a malicious executable. When a victim opens that repository in VS Code, the extension reads the provided setting and launches the specified executable when starting the Deno language server (or running related commands).
**Step by step how to trigger:**
1. An attacker creates a repository that includes a .vscode/settings.json file with an entry such as:
   ```json
   {
     "deno.path": "./malicious_executable"
   }
   ```
2. The attacker makes the repository or a branch containing this settings file available or shares it with a victim.
3. When the victim opens the repository in VS Code, the extension reads the workspace’s “deno.path” setting without sanitization.
4. The extension resolves the provided path (even if relative) and uses it to launch the Deno language server.
5. The malicious executable is executed, allowing the attacker to run arbitrary commands on the victim’s machine.

**Impact:**
If exploited, this vulnerability results in the execution of an attacker–supplied binary within the context of the VS Code extension process. This could lead to full remote code execution with the privileges of the VS Code user, potentially compromising the victim's entire system.

**Vulnerability Rank:**
Critical

**Currently Implemented Mitigations:**
- The extension allows users to explicitly set “deno.path” in settings but does not perform any validation or require user confirmation when reading the value from workspace configuration.
- The documentation mentions that users may override the executable path, relying on the assumption of a trusted environment.

**Missing Mitigations:**
- **Input Validation:** Validate the “deno.path” value to ensure it points to a trusted, valid Deno executable (e.g., by comparing against known installation directories or verifying digital signatures).
- **User Confirmation:** Require explicit user confirmation when the workspace supplies a “deno.path” value that differs from the globally installed (or otherwise trusted) Deno executable.
- **Workspace Trust Warnings:** Consider rejecting or issuing warnings about untrusted workspace settings if the repository has not been vetted.

**Preconditions:**
- The victim opens a repository containing a malicious .vscode/settings.json file where “deno.path” is set to point to an attacker-controlled executable.
- The victim has not overridden the workspace configuration at the user level.

**Source Code Analysis:**
1. In **client/src/util.ts**, the function `getWorkspaceConfigDenoExePath()` retrieves the “deno.path” setting as follows:
   ```ts
   const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
   ```
   - *Observation:* There is no validation or sanitization of the retrieved value.
2. The function `getDenoCommandPath()` then resolves the provided path:
   - If the path is relative, it is resolved against the workspace folder (using `path.resolve(workspace.uri.fsPath, command)`) without verifying that it points to a legitimate Deno executable.
3. In **client/src/commands.ts**, within the `startLanguageServer` command handler, the resolved executable path is used to spawn a language server process.
   - *Vulnerability Trigger:* The malicious path from “deno.path” causes the extension to launch an executable that could be controlled by an attacker.

**Security Test Case:**
1. **Setup:**
   - Create a test repository that includes a .vscode/settings.json file with the following content:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
   - For testing purposes, ensure that `./malicious_executable` is a benign script (e.g., one that writes a file or displays a notification) to indicate execution.
2. **Execution:**
   - Open the repository in Visual Studio Code with the Deno extension installed.
   - Monitor the execution flow: observe that the extension calls `getDenoCommandPath()` and resolves “./malicious_executable” as the command for launching the Deno language server.
3. **Verification:**
   - Confirm that `./malicious_executable` runs (e.g., check for the output file or notification produced by the script).
   - As a control test, remove the workspace settings file or update “deno.path” to a known safe Deno executable and verify that the malicious executable is not launched.
