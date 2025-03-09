# Vulnerabilities in vscode_deno Extension

## 1. Arbitrary Command Execution via deno.path Setting

**Description:**
The vscode_deno extension allows users to specify a custom path to the Deno executable via the `deno.path` setting. An attacker who can modify this setting could point it to a malicious executable, which would be executed when the extension performs operations like starting the language server, running tests, or caching modules.

The vulnerability exists because the extension doesn't validate that the path points to a legitimate Deno executable before executing it. It simply resolves the path and checks if it exists.

Steps to trigger:
1. An attacker crafts a malicious executable that appears to be Deno but contains harmful code
2. They manipulate the `deno.path` setting to point to this executable (either through social engineering, accessing an unattended workstation, or exploiting another vulnerability)
3. When the extension runs any Deno command (e.g., starting the language server), it will execute the malicious executable instead

**Impact:**
High - This could lead to arbitrary code execution with the privileges of the VS Code user. The malicious executable could access/modify any files the user has access to, steal sensitive information, or install additional malware.

**Currently Implemented Mitigations:**
The extension does check if the specified file exists, but it doesn't verify that it's actually the Deno executable or perform any signature or integrity checks.

**Missing Mitigations:**
1. Validate that the executable is a legitimate Deno CLI by checking its version output or signature
2. Implement a confirmation prompt when a custom Deno path is specified, especially if it's outside standard installation directories
3. Add an option to restrict executable paths to certain directories

**Preconditions:**
- The attacker must be able to modify the `deno.path` setting in the user's VS Code settings
- The attacker must be able to place a malicious executable somewhere on the user's system

**Source Code Analysis:**
In `client/src/util.ts`, the function `getDenoCommandPath()` retrieves the Deno executable path:

```typescript
export async function getDenoCommandPath() {
  const command = getWorkspaceConfigDenoExePath();
  const workspaceFolders = workspace.workspaceFolders;
  if (!command || !workspaceFolders) {
    return command ?? await getDefaultDenoCommand();
  } else if (!path.isAbsolute(command)) {
    // if sent a relative path, iterate over workspace folders to try and resolve.
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

This function gets the path from `getWorkspaceConfigDenoExePath()`:

```typescript
function getWorkspaceConfigDenoExePath() {
  const exePath = workspace.getConfiguration(EXTENSION_NS)
    .get<string>("path");
  // it is possible for the path to be blank. In that case, return undefined
  if (typeof exePath === "string" && exePath.trim().length === 0) {
    return undefined;
  } else {
    return exePath;
  }
}
```

The path is then used in various commands, such as in `startLanguageServer()` in `client/src/commands.ts`:

```typescript
const serverOptions: ServerOptions = {
  run: {
    command,
    args: ["lsp"],
    options: { env },
  },
  debug: {
    command,
    args: ["lsp"],
    options: { env },
  },
};
```

When the language server starts, the executable is invoked with no validation that it's actually the Deno CLI.

**Security Test Case:**
1. Create a simple executable that logs command-line arguments and environment variables to a file
2. Name it "malicious-deno.exe" (or appropriate for your OS)
3. Open VS Code and a Deno project
4. Modify the `deno.path` setting to point to your malicious executable
5. Run any Deno command from VS Code (e.g., "Deno: Enable")
6. Verify that your executable was called instead of the real Deno CLI by checking the log file
7. Note that in a real attack, this executable could perform any action the user has permission to do
