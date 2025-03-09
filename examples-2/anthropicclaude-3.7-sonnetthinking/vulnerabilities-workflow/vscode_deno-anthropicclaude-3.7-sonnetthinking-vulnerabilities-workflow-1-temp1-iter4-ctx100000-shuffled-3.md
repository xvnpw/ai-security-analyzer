# Critical Vulnerabilities in VSCode Deno Extension

## Remote Code Execution via Custom Deno Path

### Description
The Deno VSCode extension allows specifying a custom path to the Deno executable via the `deno.path` configuration setting. An attacker can create a malicious repository with a custom `.vscode/settings.json` file that points to a malicious executable. When a victim opens this repository in VSCode, the extension will attempt to use this malicious executable instead of the legitimate Deno CLI.

Step by step exploitation process:
1. Attacker creates a repository containing a malicious executable (e.g., `evil.sh` or `evil.exe`)
2. Attacker adds a `.vscode/settings.json` file to the repository with the following content:
   ```json
   {
     "deno.enable": true,
     "deno.path": "./evil"
   }
   ```
3. When a victim opens this repository in VSCode with the Deno extension installed, the extension will resolve this relative path against the workspace folder
4. The extension will then execute this malicious binary when it attempts to start the Deno language server

### Impact
This vulnerability allows arbitrary code execution on the victim's machine with the same privileges as VSCode. The attacker's code executes without requiring any user interaction beyond opening the repository. The malicious code would have full access to the victim's system, allowing the attacker to steal sensitive information, install malware, or perform any other actions the user can perform.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The code directly uses the path from the configuration without validation:

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

### Missing Mitigations
1. The extension should validate that the specified Deno executable is legitimate before executing it
2. It could validate the binary by checking for a digital signature or verifying its hash
3. The extension should only resolve relative paths against trusted locations, not arbitrary workspace folders
4. Alternatively, it could warn the user when a custom Deno path is specified and require explicit confirmation

### Preconditions
1. The victim must have the Deno VSCode extension installed
2. The victim must open a repository containing the malicious configuration and executable
3. The Deno extension must be activated (which happens automatically when a repository with Deno configuration is opened)

### Source Code Analysis
The vulnerability exists in the path resolution process:

1. In `util.ts`, the `getDenoCommandPath()` function is defined:
```typescript
async function getDenoCommandPath() {
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

2. This function retrieves the Deno executable path from workspace configuration using `getWorkspaceConfigDenoExePath()`
3. If a relative path is provided, it resolves it against each workspace folder
4. In `commands.ts`, the `startLanguageServer()` function uses this path to spawn a process:
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
const client = new LanguageClient(
  LANGUAGE_CLIENT_ID,
  LANGUAGE_CLIENT_NAME,
  serverOptions,
  // ...
);
```

5. This function is called when the extension activates or when certain commands are run

The core issue is that the extension blindly trusts and executes whatever binary is specified in the `deno.path` setting, including binaries located within the potentially untrusted repository being opened.

### Security Test Case
To demonstrate this vulnerability:

1. Create a malicious executable for the target platform (e.g., a bash script for Linux/macOS or a .exe/.bat file for Windows)
   - For Linux/macOS:
     ```bash
     #!/bin/bash
     # evil.sh
     touch /tmp/pwned
     # Also mimic expected behavior to avoid suspicion
     if [ "$1" = "lsp" ]; then
       sleep 10
     fi
     ```
   - Make it executable: `chmod +x evil.sh`

2. Create a `.vscode/settings.json` file in the repository:
   ```json
   {
     "deno.enable": true,
     "deno.path": "./evil.sh"
   }
   ```

3. When a victim with the Deno extension installed opens this repository in VSCode, the extension will execute the malicious script

4. Verify that `/tmp/pwned` file was created, indicating successful exploitation

This vulnerability is especially dangerous as it requires no user interaction beyond opening a repository, making it an effective supply chain attack vector.

## Command Injection via Import Map Path

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
