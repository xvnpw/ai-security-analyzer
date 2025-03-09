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

**Impact**: An attacker can execute arbitrary code with the privileges of the VS Code process whenever the extension starts or restarts. Since the extension uses this executable for all Deno operations, the attacker's code would run whenever Deno commands are executed.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**: The extension checks if the file exists using `fileExists`, but this doesn't prevent executing a malicious executable if it exists.

**Missing Mitigations**: The extension should validate that the executable is a legitimate Deno executable, possibly by checking its version or signature. It should also restrict the `deno.path` setting to known safe locations or require absolute paths that aren't within the workspace.

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
