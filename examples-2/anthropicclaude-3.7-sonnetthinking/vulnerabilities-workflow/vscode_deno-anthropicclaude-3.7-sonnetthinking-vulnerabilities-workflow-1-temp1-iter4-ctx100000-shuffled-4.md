# List of Vulnerabilities in VSCode Deno Extension

## Path Traversal Leading to Command Injection via Environment File Configuration

### Vulnerability Name
Path Traversal Leading to Command Injection via Environment File Configuration

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
