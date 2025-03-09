### Vulnerability List:

- Vulnerability Name: Path Traversal in `deno.path` setting

- Description:
    1. An attacker can modify the VS Code workspace settings, for example by contributing to a shared project or through a malicious workspace.
    2. The attacker sets the `deno.path` setting in `.vscode/settings.json` to a malicious path containing path traversal sequences, such as `"../../../path/to/malicious_script.js"`.
    3. When the VS Code Deno extension activates or restarts the language server, it reads the `deno.path` setting.
    4. The extension uses the `getDenoCommandPath` function to resolve the path to the Deno executable. This function resolves relative paths using `path.resolve` without sanitization.
    5. As a result, the resolved path points to the attacker-controlled script outside the intended workspace directory.
    6. When the extension attempts to spawn the Deno language server or execute Deno commands, it inadvertently executes the attacker-specified malicious script instead of the legitimate Deno CLI.

- Impact:
    - Arbitrary code execution on the user's machine with the permissions of the VS Code process.
    - If Deno is launched with broad permissions (e.g., `--allow-all` often used in development or testing and as default in some code lens contexts), the attacker's script can perform malicious actions such as reading sensitive files, exfiltrating data, or modifying system configurations.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The extension code does not sanitize or validate the `deno.path` setting.

- Missing Mitigations:
    - Input sanitization: Sanitize the `deno.path` setting to remove or neutralize path traversal sequences before resolving the path.
    - Path validation: Validate that the resolved path for `deno.path` points to an executable within a trusted directory or within the workspace itself.
    - User warning: Display a warning to the user if `deno.path` is set to a location outside the workspace or a standard Deno installation directory, advising caution.

- Preconditions:
    - The attacker must be able to influence the VS Code workspace settings, such as by contributing a malicious `.vscode/settings.json` to a shared project, or by tricking a user into opening a workspace containing malicious settings.
    - The Deno VS Code extension must be enabled in the workspace.

- Source Code Analysis:
    ```typescript
    // File: client/src/util.ts
    async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath();
      const workspaceFolders = workspace.workspaceFolders;
      if (!command || !workspaceFolders) {
        return command ?? await getDefaultDenoCommand();
      } else if (!path.isAbsolute(command)) {
        // if sent a relative path, iterate over workspace folders to try and resolve.
        for (const workspace of workspaceFolders) {
          const commandPath = path.resolve(workspace.uri.fsPath, command); // Potential Path Traversal
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
    - The `getDenoCommandPath` function in `client\src\util.ts` retrieves the `deno.path` setting.
    - When `deno.path` is a relative path, `path.resolve(workspace.uri.fsPath, command)` is used to resolve it.
    - `path.resolve` does not prevent path traversal; it resolves path segments like `..` normally.
    - An attacker-controlled relative path in `deno.path` like `"../../../malicious_script.js"` will be resolved by `path.resolve` to a path outside the workspace.
    - Subsequently, this path is used to execute the "deno" command, leading to the execution of the malicious script.

- Security Test Case:
    1. Create a malicious JavaScript file named `malicious.js` with the following content:
        ```javascript
        #!/usr/bin/env node
        const fs = require('fs');
        const os = require('os');
        const sensitiveFile = os.platform() === 'win32' ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' : '/etc/passwd';
        try {
            const content = fs.readFileSync(sensitiveFile, 'utf8');
            console.log(`[MALICIOUS SCRIPT] Successfully read sensitive file: ${sensitiveFile}`);
            // In a real attack, data would be exfiltrated.
        } catch (e) {
            console.error(`[MALICIOUS SCRIPT] Failed to read sensitive file: ${sensitiveFile} - ${e.message}`);
        }
        console.log("[MALICIOUS SCRIPT] Executed!");
        ```
    2. Place `malicious.js` in a directory outside your intended VS Code workspace, for example, in your home directory.
    3. Create a new VS Code workspace or open an existing one.
    4. Create a `.vscode` directory in the workspace root if it doesn't exist.
    5. Inside `.vscode`, create or modify `settings.json` and add the following configuration, adjusting the path to `malicious.js` based on its location relative to your workspace root (using enough `../` to traverse out and then down to `malicious.js`):
        ```json
        {
            "deno.enable": true,
            "deno.path": "../../../malicious.js"
        }
        ```
    6. Open any JavaScript or TypeScript file in the workspace to activate the Deno extension.
    7. Observe the output in the "Output" panel (select "Deno Language Server" in the dropdown). You should see the "[MALICIOUS SCRIPT] Executed!" message and potentially messages indicating successful or failed attempts to read a sensitive file, demonstrating that your malicious script has been executed instead of the Deno CLI.
    8. To further verify, you can modify `malicious.js` to perform other actions or to write to a file within your workspace to confirm arbitrary code execution.

---

- Vulnerability Name: Path Traversal in `deno.config` and `deno.importMap` settings

- Description:
    1. An attacker can modify the VS Code workspace settings, potentially by contributing to a shared project.
    2. The attacker sets the `deno.config` and/or `deno.importMap` settings in `.vscode/settings.json` to malicious paths containing path traversal sequences, such as `"../../../path/to/malicious_config.json"` and `"../../../path/to/malicious_import_map.json"`.
    3. When the VS Code Deno extension performs actions that use these settings (like starting the language server, running tests, or debugging), it reads the `deno.config` and `deno.importMap` settings.
    4. The extension passes these settings as command-line arguments `--config` and `--import-map` to the Deno CLI, without sanitizing the paths.
    5. When Deno CLI processes these commands, it attempts to load the configuration file and import map from the attacker-specified paths, which can be outside the intended workspace directory due to path traversal sequences.
    6. This can lead to the Deno CLI accessing and potentially processing files from arbitrary locations on the user's file system, depending on the Deno CLI's behavior with these options.

- Impact:
    - Potential arbitrary file system read. While not direct code execution through the extension itself, an attacker may be able to craft malicious configuration or import map files that, when processed by Deno CLI, could lead to unintended actions or information disclosure if Deno CLI processing of these files is not properly sandboxed or restricted. The severity depends on how Deno CLI handles maliciously crafted config and import map files from arbitrary locations and the permissions granted to Deno processes.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The extension code passes the `deno.config` and `deno.importMap` settings directly to the Deno CLI without validation or sanitization.

- Missing Mitigations:
    - Input sanitization: Sanitize the `deno.config` and `deno.importMap` settings to remove path traversal sequences.
    - Path validation: Validate that the resolved paths for `deno.config` and `deno.importMap` are within the workspace or trusted directories.
    - User warning: Warn users if `deno.config` or `deno.importMap` are set to locations outside the workspace, advising caution.

- Preconditions:
    - The attacker must be able to influence the VS Code workspace settings.
    - The Deno VS Code extension must be enabled in the workspace.
    - Features that utilize `deno.config` and `deno.importMap` settings (like debugging, testing, language server operations) must be triggered.

- Source Code Analysis:
    ```typescript
    // File: client/src/debug_config_provider.ts
    #getAdditionalRuntimeArgs() {
      const args: string[] = [];
      const settings = this.#extensionContext.clientOptions
        .initializationOptions();
      ...
      if (settings.importMap) {
        args.push("--import-map");
        args.push(settings.importMap.trim()); // Potential Path Traversal
      }
      if (settings.config) {
        args.push("--config");
        args.push(settings.config.trim()); // Potential Path Traversal
      }
      return args;
    }
    ```
    ```typescript
    // File: client/src/commands.ts (test command example)
    export function test( ... ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        ...
        if (!testArgs.includes("--import-map")) {
          const importMap: string | undefined | null = config.get("importMap");
          if (importMap?.trim()) {
            testArgs.push("--import-map", importMap.trim()); // Potential Path Traversal
          }
        }
        if (config.get<string>("config")) {
            testArgs.push("--config");
            testArgs.push(config.get<string>("config")!.trim()); // Potential Path Traversal
        }
        ...
      }
    }
    ```
    - In `debug_config_provider.ts` and `commands.ts`, the extension retrieves `deno.config` and `deno.importMap` settings.
    - It directly appends these settings to the command-line arguments for Deno CLI as `--import-map` and `--config`.
    - If `deno.config` or `deno.importMap` contains path traversal sequences (e.g., `"../../../malicious_config.json"`), these are passed directly to Deno CLI.
    - Deno CLI might then attempt to load files from these attacker-controlled paths.

- Security Test Case:
    1. Create a malicious configuration file `malicious_config.json` outside your workspace with potentially harmful or revealing configurations (the specific content depends on what aspects of Deno configuration are exploitable). For a simple test, a valid but benign config is sufficient to demonstrate path traversal. Example:
        ```json
        {
          "lint": {
            "rules": {
              "tags": ["recommended"]
            }
          }
        }
        ```
    2. Create a malicious import map file `malicious_import_map.json` outside your workspace. Example:
        ```json
        {
          "imports": {
            "lodash": "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"
          }
        }
        ```
    3. Create a VS Code workspace.
    4. In `.vscode/settings.json`, set `deno.config` and `deno.importMap` to point to these malicious files using path traversal (adjust paths accordingly):
        ```json
        {
            "deno.enable": true,
            "deno.config": "../../../malicious_config.json",
            "deno.importMap": "../../../malicious_import_map.json"
        }
        ```
    5. Open a Deno project within the workspace.
    6. Trigger actions that utilize these settings, such as starting a debug session, running tests, or simply activating the Deno language server.
    7. Monitor file system access (using system tools if necessary) or Deno CLI behavior to observe if it attempts to load `malicious_config.json` and `malicious_import_map.json` from the attacker-specified locations outside the workspace. The impact might be subtle and might require deeper analysis of Deno CLI's behavior when provided with external config/import map files. For instance, look for logs or errors indicating attempts to read or process these files.
