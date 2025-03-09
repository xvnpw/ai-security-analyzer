# Vulnerabilities in Deno VS Code Extension

## 1. Command Injection via Deno Tasks

### Description
The Deno VS Code extension allows running tasks defined in the `deno.json` configuration file. When a victim opens a malicious repository and runs a Deno task, arbitrary system commands embedded in the task definition can be executed on the victim's machine. This happens because the extension fetches task definitions from the Deno Language Server and executes them using `tasks.executeTask()` without adequate validation.

### Impact
Critical - An attacker can execute arbitrary system commands on the victim's machine with the same privileges as the VS Code process, potentially leading to complete system compromise.

### Currently Implemented Mitigations
The extension relies on the user to review task content before execution, but there are no technical controls preventing malicious commands from being executed.

### Missing Mitigations
- No sandboxing or restriction of commands that can be executed through Deno tasks
- No warning or confirmation dialog showing the actual command to be executed
- No validation of task command content against a whitelist of safe operations

### Preconditions
- Victim must open a malicious repository with a crafted `deno.json` file
- Victim must trigger a task execution (by clicking "Run Task" in the Tasks sidebar or through the command palette)
- Deno extension must be enabled for the workspace

### Source Code Analysis
Here's how the vulnerability can be triggered:

1. In `tasks_sidebar.ts`, the `#runTask` method directly executes tasks:
```typescript
#runTask(task: DenoTask) {
  tasks.executeTask(task.task);
}
```

2. Tasks are built from the repository's deno.json in the `DenoTaskProvider`:
```typescript
const task = buildDenoConfigTask(
  workspaceFolder,
  process,
  configTask.name,
  configTask.command ?? configTask.detail,
  Uri.parse(configTask.sourceUri),
);
```

3. The `buildDenoConfigTask` function in `tasks.ts` creates a `ProcessExecution` object that will execute the command:
```typescript
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
```

4. When the task is executed, it runs `deno task [name]`, where the actual command executed is determined by the task definition in the deno.json file.

### Security Test Case
1. Create a malicious repository with a `deno.json` file containing:
```json
{
  "tasks": {
    "malicious": "echo 'Malicious command executed' && calc.exe"
  }
}
```

2. Open the repository in VS Code with the Deno extension installed
3. Open the Deno Tasks sidebar
4. Click on the "malicious" task
5. Observe that calculator application is launched, demonstrating arbitrary command execution

## 2. Remote Code Execution via Debug Configuration

### Description
When a victim debugs a JavaScript/TypeScript file with the Deno extension, the extension automatically creates a debug configuration with the `--allow-all` flag if no configuration exists. This flag grants the executed code full permissions to access the file system, network, and execute system commands without any restrictions or user confirmation.

### Impact
Critical - Malicious code can access sensitive files, exfiltrate data, or execute arbitrary commands on the victim's system with the same privileges as the VS Code process.

### Currently Implemented Mitigations
None - The extension automatically configures debugging with full permissions.

### Missing Mitigations
- No permission prompt or warning before applying `--allow-all` permissions
- No default minimal permission set (least privilege approach)
- No option to run in a restricted sandbox first

### Preconditions
- Victim must open a malicious JavaScript/TypeScript file
- Victim must start debugging the file (F5 or "Start Debugging" command)
- Deno extension must be enabled

### Source Code Analysis
In `debug_config_provider.ts`, the `resolveDebugConfiguration` method automatically creates a configuration with `--allow-all` when none exists:

```typescript
async resolveDebugConfiguration(
  workspace: vscode.WorkspaceFolder | undefined,
  config: vscode.DebugConfiguration,
): Promise<vscode.DebugConfiguration | null | undefined> {
  // if launch.json is missing or empty
  if (!config.type && !config.request && !config.name) {
    const editor = vscode.window.activeTextEditor;
    const langId = editor?.document.languageId;
    if (
      editor &&
      (langId === "typescript" || langId === "javascript" ||
        langId === "typescriptreact" || langId === "javascriptreact")
    ) {
      // ...
      const debugConfig: vscode.DebugConfiguration = {
        request: "launch",
        name: "Launch Program",
        type: "node",
        program: "${file}",
        env: this.#getEnv(),
        runtimeExecutable: await getDenoCommandName(),
        runtimeArgs: [
          "run",
          ...this.#getAdditionalRuntimeArgs(),
          this.#getInspectArg(),
          "--allow-all", // Grants full permissions to code being debugged
        ],
        attachSimplePort: 9229,
      };

      // Immediately starts debugging with this configuration
      vscode.debug.startDebugging(workspace, debugConfig);
      return undefined;
    }
    return null;
  }
  // ...
}
```

The key issue is the automatic inclusion of the `--allow-all` flag which grants the code full access to system resources without requiring any user confirmation. When combined with automatically starting the debugging session, this creates a path for immediate code execution with elevated privileges.

### Security Test Case
1. Create a malicious TypeScript file (evil.ts) with the following content:
```typescript
// This will execute calc.exe on Windows or open calculator on macOS
// In a real attack, this could exfiltrate data, install malware, etc.
if (Deno.build.os === "windows") {
  const p = Deno.run({cmd: ["calc.exe"]});
  await p.status();
} else if (Deno.build.os === "darwin") {
  const p = Deno.run({cmd: ["open", "-a", "Calculator"]});
  await p.status();
} else {
  const p = Deno.run({cmd: ["xdg-open", "https://example.com"]});
  await p.status();
}

console.log("Malicious code executed with full permissions!");
```

2. Open this file in VS Code with the Deno extension enabled
3. Press F5 or click the debug button to start debugging
4. Observe that the calculator application opens, demonstrating successful arbitrary code execution
5. The code has full access to the file system, network, and can run arbitrary system commands
