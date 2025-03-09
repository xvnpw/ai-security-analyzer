# Vulnerabilities

## Remote Code Execution via `deno.path` Setting

### Description
An attacker can achieve remote code execution by manipulating the `deno.path` setting in a malicious repository. Here's how the attack works:

1. The attacker creates a malicious repository containing a `.vscode/settings.json` file that sets the `deno.path` configuration to point to a malicious executable.
2. When a victim opens this repository in VSCode, the Deno extension reads this setting to determine which executable to use when running Deno-related commands.
3. When the victim triggers any action that executes the Deno CLI (such as running tests, debugging, or executing tasks), the extension will run the attacker's malicious executable instead of the legitimate Deno binary.

### Impact
This vulnerability allows for remote code execution with the privileges of the VSCode process. The malicious executable will inherit the victim's permissions, giving the attacker access to the victim's files and potentially allowing further exploitation of the system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The extension does not validate that the specified path points to a legitimate Deno executable.

### Missing Mitigations
1. Validate that the specified executable is a legitimate Deno binary by checking the output of commands like `deno --version` before execution.
2. Display a security warning when using a custom Deno executable path, especially when opening a repository for the first time.
3. Implement a confirmation dialog that requires explicit user approval before using a custom Deno executable.

### Preconditions
1. The victim must open a malicious repository in VSCode.
2. The repository must contain a `.vscode/settings.json` file with a custom `deno.path` setting.
3. The victim must trigger a feature that executes the Deno CLI.

### Source Code Analysis
The vulnerability exists in how the extension retrieves and uses the Deno executable path without any validation:

In `client/src/util.ts`, the `getDenoCommandPath()` function retrieves the Deno executable path from workspace configuration:

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

The function `getWorkspaceConfigDenoExePath()` simply retrieves the path from the configuration without any validation:

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

When the extension executes tasks or other operations that involve the Deno CLI, it uses this path to spawn processes. For example, in `client/src/tasks.ts`:

```typescript
async provideTasks(): Promise<vscode.Task[]> {
  // ...
  const process = await getDenoCommandName();
  for (const workspaceFolder of vscode.workspace.workspaceFolders ?? []) {
    for (const { command, group, problemMatchers } of defs) {
      const task = buildDenoTask(
        workspaceFolder,
        process,
        { type: TASK_TYPE, command },
        command,
        [command],
        problemMatchers,
      );
      // ...
    }
  }
  // ...
}
```

The vulnerability is exploited when this path is used to execute commands through VSCode's task execution API:

```typescript
export function buildDenoTask(
  target: vscode.WorkspaceFolder,
  process: string,
  definition: DenoTaskDefinition,
  name: string,
  args: string[],
  problemMatchers: string[],
): vscode.Task {
  const exec = new vscode.ProcessExecution(
    process,
    args,
    definition,
  );

  return new vscode.Task(
    definition,
    target,
    name,
    TASK_SOURCE,
    exec,
    problemMatchers,
  );
}
```

### Security Test Case
1. Create a malicious executable (e.g., a script that executes a reverse shell or other arbitrary commands).
2. Create a repository with a `.vscode/settings.json` file containing:
```json
{
  "deno.enable": true,
  "deno.path": "/path/to/malicious/executable"
}
```
3. Add a simple `deno.json` file with task definitions:
```json
{
  "tasks": {
    "start": "echo 'Starting application'"
  }
}
```
4. When the victim opens this repository in VSCode and runs the "start" task (or any other Deno command), the malicious executable will run instead of the legitimate Deno CLI.
5. The malicious executable will receive the arguments that were intended for the Deno CLI, which it can either ignore or use to maintain the appearance of normal operation while executing malicious code.
