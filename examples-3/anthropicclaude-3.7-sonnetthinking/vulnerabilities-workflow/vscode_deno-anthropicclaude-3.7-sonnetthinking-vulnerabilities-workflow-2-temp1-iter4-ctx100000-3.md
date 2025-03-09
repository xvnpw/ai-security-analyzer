# Vulnerabilities in Deno for Visual Studio Code

## Custom Deno Path Execution

- **Description**: The extension allows specifying a custom path to the Deno executable through the `deno.path` configuration setting, which can be set in workspace settings. When a malicious project includes a crafted `.vscode/settings.json` with a `deno.path` pointing to a malicious executable, that executable will be run instead of Deno whenever the extension executes Deno commands.

- **Impact**: An attacker can achieve arbitrary code execution with the privileges of the VS Code user, potentially leading to complete system compromise, data theft, credential stealing, or malware installation.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: None. The extension does not validate or warn when a custom Deno path is being used.

- **Missing Mitigations**:
  - Validate that the custom Deno path points to a legitimate Deno executable
  - Display a prominent warning when a custom Deno path is configured
  - Require explicit user confirmation before using a non-standard Deno path
  - Implement path allowlisting to only permit paths to known Deno installations

- **Preconditions**:
  - The victim must open a malicious workspace with a custom `deno.path` configured
  - The victim must perform an action that triggers Deno execution, such as running tests or tasks

- **Source Code Analysis**:
The vulnerability is in how the extension resolves the Deno executable path. In `util.ts`, the `getDenoCommandPath` function gets the Deno path directly from the configuration without validation:

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

The `getWorkspaceConfigDenoExePath` function returns the `deno.path` setting without any validation:

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

Throughout the codebase, `getDenoCommandName()` (which calls `getDenoCommandPath()`) is used to get the command to execute:

```typescript
export async function getDenoCommandName() {
  return await getDenoCommandPath() ?? "deno";
}
```

- **Security Test Case**:
  1. Create a malicious executable:
     - On Windows, create `malicious.exe` that executes malicious code
     - On macOS/Linux, create an executable script named `malicious`

  2. Create a malicious workspace with a `.vscode/settings.json` file containing:
  ```json
  {
    "deno.enable": true,
    "deno.path": "/path/to/malicious"
  }
  ```

  3. Share this project with the victim

  4. When the victim opens the workspace in VS Code with the Deno extension installed, the extension will automatically activate

  5. As soon as the victim performs any action that triggers Deno execution (like running a test, formatting a file, or enabling the extension), the malicious executable will run instead of Deno
