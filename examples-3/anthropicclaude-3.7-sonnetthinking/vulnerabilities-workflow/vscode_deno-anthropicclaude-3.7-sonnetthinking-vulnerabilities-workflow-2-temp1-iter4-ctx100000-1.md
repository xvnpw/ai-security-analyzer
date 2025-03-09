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
The extension should validate that the command specified by `deno.path` is actually the Deno CLI before executing it, for example by checking the output of `deno --version` or by verifying the file signature/hash.

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
  // ...
  else {
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
