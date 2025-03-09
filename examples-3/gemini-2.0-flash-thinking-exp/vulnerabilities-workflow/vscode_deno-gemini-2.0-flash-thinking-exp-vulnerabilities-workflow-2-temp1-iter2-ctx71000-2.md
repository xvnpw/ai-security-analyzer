### Vulnerability List

- Vulnerability Name: Malicious `deno.path` Configuration
- Description:
    1. An attacker crafts a malicious VS Code workspace.
    2. Within this workspace, the attacker creates a `.vscode/settings.json` file.
    3. In this settings file, the attacker sets the `deno.path` configuration to point to a malicious executable file located within the workspace or an attacker-controlled external location. This malicious executable is designed to mimic the Deno CLI but contains harmful code.
    4. The victim opens this malicious workspace in VS Code with the Deno extension enabled.
    5. When the Deno extension starts, it reads the `deno.path` setting from the workspace configuration.
    6. The extension, without proper validation, uses the attacker-specified path to execute what it believes is the Deno CLI, but is actually the malicious executable.
    7. The malicious executable runs with the privileges of the user running VS Code, allowing the attacker to execute arbitrary code on the victim's machine.
- Impact: Arbitrary code execution on the user's machine. An attacker can gain full control over the user's development environment, potentially leading to data theft, malware installation, or further system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The extension currently retrieves and uses the `deno.path` setting without any validation to ensure it points to a legitimate and safe Deno executable.
- Missing Mitigations:
    - Input validation for the `deno.path` setting: The extension should validate that the provided path points to a legitimate Deno executable. This could involve checking file signatures, verifying the executable's origin, or using a safelist of known good paths.
    - User warning: When the `deno.path` setting is changed, especially to a location within the workspace or an external potentially untrusted path, the extension should display a prominent warning to the user. This warning should highlight the security risks associated with using custom executable paths and advise users to only use trusted Deno executables.
- Preconditions:
    - The victim has the Deno extension for VS Code installed and enabled.
    - The victim opens a malicious VS Code workspace provided by the attacker.
- Source Code Analysis:
    1. `client\src\commands.ts`:
        - The `startLanguageServer` function is responsible for initiating the Deno Language Server.
        - It calls `getDenoCommandPath()` to determine the path to the Deno executable.
        ```typescript
        const command = await getDenoCommandPath();
        if (command == null) {
          // ... error handling ...
          return;
        }
        ```
    2. `client\src\util.ts`:
        - The `getDenoCommandPath()` function retrieves the `deno.path` configuration from VS Code settings.
        ```typescript
        function getWorkspaceConfigDenoExePath() {
          const exePath = workspace.getConfiguration(EXTENSION_NS)
            .get<string>("path");
          // ...
          return exePath;
        }
        ```
        - It prioritizes the `deno.path` setting over the default `deno` command lookup.
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath();
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand();
          } // ...
        }
        ```
        - The code does not perform any validation on the `command` path to verify it is a legitimate Deno executable or from a trusted source. It merely checks if the file exists.
    - Visualization:
        ```mermaid
        graph LR
            A[User opens malicious workspace] --> B(Extension activation);
            B --> C{Read deno.path from settings};
            C --> D[getDenoCommandPath() in util.ts];
            D --> E{getConfiguration(EXTENSION_NS).get("path")};
            E --> F[No validation of path];
            F --> G[Execute command as Language Server];
            G --> H[Malicious code execution];
        ```
- Security Test Case:
    1. **Setup Malicious Executable:**
        - Create a file named `malicious-deno.sh` (or `malicious-deno.bat` on Windows) with the following content:
            ```bash
            #!/bin/bash
            echo "Malicious Deno Executable Running!" > /tmp/malicious_execution.txt
            # On Windows, use: echo "Malicious Deno Executable Running!" > %TEMP%\malicious_execution.txt
            ```
        - Make the script executable: `chmod +x malicious-deno.sh`
        - Place this script in a known location, for example, within your testing workspace.
    2. **Create Malicious Workspace:**
        - Create a new VS Code workspace directory.
        - Inside the workspace, create a `.vscode` folder.
        - Within `.vscode`, create a `settings.json` file with the following content, adjusting the path to the malicious script:
            ```json
            {
                "deno.enable": true,
                "deno.path": "/path/to/your/workspace/malicious-deno.sh"
                // On Windows, use: "deno.path": "C:\\path\\to\\your\\workspace\\malicious-deno.bat"
            }
            ```
            - **Important:** Replace `/path/to/your/workspace/malicious-deno.sh` with the actual absolute path to the `malicious-deno.sh` file you created. Ensure to use forward slashes even on Windows in JSON.
    3. **Open Workspace in VS Code:**
        - Open the workspace you created in VS Code with the Deno extension enabled.
    4. **Observe Malicious Execution:**
        - Check for the file `/tmp/malicious_execution.txt` (or `%TEMP%\malicious_execution.txt` on Windows). If it exists and contains "Malicious Deno Executable Running!", the vulnerability is confirmed. This indicates that the malicious script specified in `deno.path` was executed by the extension.

- Vulnerability Name: Malicious `deno.importMap` Configuration
- Description:
    1. An attacker creates a malicious VS Code workspace.
    2. In the workspace's `.vscode/settings.json` or a `deno.json` file, the attacker sets the `deno.importMap` configuration to point to a malicious import map file. This import map file is crafted to redirect legitimate module specifiers to attacker-controlled, potentially malicious modules hosted remotely or within the workspace.
    3. The victim opens the malicious workspace in VS Code with the Deno extension enabled.
    4. When the Deno extension or Deno CLI within the workspace resolves modules (e.g., during type checking, linting, testing, or debugging), it uses the configured malicious import map.
    5. Due to the redirection in the import map, when the victim's code attempts to import a seemingly safe module (e.g., from `std/http/server.ts`), the Deno extension or CLI instead loads and potentially executes the malicious module specified in the import map.
    6. This can lead to dependency confusion attacks and potentially remote code execution if the malicious module contains harmful code.
- Impact: Dependency confusion leading to potential remote code execution. An attacker can hijack dependencies within the project, potentially compromising the project's integrity and security.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The extension reads and applies the `deno.importMap` setting without validating the content or source of the import map file.
- Missing Mitigations:
    - Input validation for `deno.importMap`: The extension should validate the `deno.importMap` setting. If the import map is a remote URL, the extension should warn the user about potential risks and ideally provide a way to review the content of the import map before applying it. For local files, while less risky, validation could still involve checking for unusual redirects or patterns.
    - Warning for remote import maps: Display a security warning to the user when a workspace configuration specifies a remote URL for `deno.importMap`. This warning should emphasize the risk of using untrusted remote import maps.
- Preconditions:
    - The victim has the Deno extension for VS Code installed and enabled.
    - The victim opens a malicious VS Code workspace provided by the attacker.
    - The malicious workspace configures `deno.importMap` to a malicious import map file.
- Source Code Analysis:
    1. `client\src\commands.ts` and `client\src\debug_config_provider.ts`:
        - These files demonstrate how the `deno.importMap` setting is retrieved and used when executing Deno commands like `test` and for debugging configurations.
        - In `debug_config_provider.ts`:
            ```typescript
            #getAdditionalRuntimeArgs() {
                const args: string[] = [];
                const settings = this.#extensionContext.clientOptions
                .initializationOptions();
                // ...
                if (settings.importMap) {
                    args.push("--import-map");
                    args.push(settings.importMap.trim());
                }
                // ...
                return args;
            }
            ```
        - In `commands.ts` (within the `test` function):
            ```typescript
            if (!testArgs.includes("--import-map")) {
                const importMap: string | undefined | null = config.get("importMap");
                if (importMap?.trim()) {
                    testArgs.push("--import-map", importMap.trim());
                }
            }
            ```
        - The code retrieves the `deno.importMap` setting via `config.get("importMap")` and `settings.importMap` and directly passes it as a command-line argument `--import-map` to the Deno CLI, without any validation or security checks on the import map's content or source.
    - Visualization:
        ```mermaid
        graph LR
            A[User opens malicious workspace] --> B(Extension activation);
            B --> C{Read deno.importMap from settings};
            C --> D[debug_config_provider.ts & commands.ts];
            D --> E{getConfiguration(EXTENSION_NS).get("importMap")};
            E --> F[No validation of importMap content/source];
            F --> G[Pass --import-map to Deno CLI];
            G --> H[Deno CLI uses malicious import map];
            H --> I[Dependency confusion/RCE];
        ```
- Security Test Case:
    1. **Create Malicious Import Map:**
        - Create a file named `malicious_import_map.json` in your testing workspace with the following content. This example redirects `std/http/server.ts` to a local malicious module.
            ```json
            {
              "imports": {
                "std/http/server.ts": "./malicious_server.ts"
              }
            }
            ```
    2. **Create Malicious Module:**
        - Create a file named `malicious_server.ts` in your testing workspace with the following content. This script will write to a file indicating malicious code execution.
            ```typescript
            // malicious_server.ts
            import * as fs from 'node:fs';
            fs.writeFileSync('/tmp/malicious_import_map_execution.txt', 'Malicious Import Map Executed!');
            // On Windows, use: fs.writeFileSync('%TEMP%\\malicious_import_map_execution.txt', 'Malicious Import Map Executed!');

            export function serve(handler: any, options?: any): any {
                console.log("Serving from malicious server!");
                // Original serve functionality could be mocked or omitted for test simplicity
            }
            ```
    3. **Create Test File:**
        - Create a file, for example, `test.ts`, in your workspace that imports and attempts to use the redirected module.
            ```typescript
            // test.ts
            import { serve } from "std/http/server.ts";

            serve(() => new Response("Hello, World!"));
            console.log("Server started (or should have)...");
            ```
    4. **Configure Workspace Settings:**
        - In your workspace's `.vscode` folder, create or modify `settings.json` to set the `deno.importMap` path:
            ```json
            {
                "deno.enable": true,
                "deno.importMap": "./malicious_import_map.json"
            }
            ```
    5. **Open Workspace and Run Test File:**
        - Open the workspace in VS Code with the Deno extension enabled.
        - Open `test.ts`. The Deno extension will likely perform type checking or linting, which triggers module resolution.
        - Alternatively, try to run or debug `test.ts` using the Deno extension's features.
    6. **Observe Malicious Execution:**
        - Check for the file `/tmp/malicious_import_map_execution.txt` (or `%TEMP%\malicious_import_map_execution.txt` on Windows). If it exists and contains "Malicious Import Map Executed!", the vulnerability is confirmed. This shows that the malicious code from `malicious_server.ts` was executed due to the import map redirection.

- Vulnerability Name: Malicious `deno.config` Configuration
- Description:
    1. An attacker sets up a malicious VS Code workspace.
    2. Within the workspace's `.vscode/settings.json` or a dedicated `deno.json`/`deno.jsonc` file, the attacker configures the `deno.config` setting to point to a malicious Deno configuration file. This malicious configuration file can contain a variety of settings that could be exploited, focusing on compiler options or potentially other Deno-specific configurations.
    3. When the victim opens this workspace in VS Code with the Deno extension active, the extension reads the `deno.config` setting.
    4. The Deno Language Server and extension utilize this attacker-specified configuration file without sufficient validation.
    5. While direct Remote Code Execution (RCE) might be less probable via configuration files, the malicious config can still manipulate the behavior of the Deno LSP and extension in unintended, possibly harmful ways. This could include:
        - Information Leak: Setting compiler options that might expose internal file paths, project structure, or other sensitive data in diagnostics or logs.
        - Unexpected Behavior: Altering compiler or linter settings to bypass security checks, suppress warnings, or introduce subtle vulnerabilities in the project's build or type-checking process.
        - Redirection or resource manipulation (less likely but theoretically possible depending on the extent of config processing).
- Impact: Configuration manipulation, potential for information leakage, and unexpected or insecure behavior of the Deno extension and LSP. While direct RCE is less likely, the manipulated configuration could weaken project security or expose sensitive information.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None. The extension loads and applies the configuration file specified by `deno.config` without any validation of its contents for malicious settings or security implications beyond basic JSON parsing.
- Missing Mitigations:
    - Input validation for `deno.config` contents: The extension should validate the contents of the Deno configuration file, especially compiler options and other security-sensitive settings. Implement a safelist or denylist for configuration options to prevent the application of potentially harmful settings.
    - Warning for custom configurations: Display a warning to the user when a workspace configuration specifies a custom `deno.config` file, especially if it overrides default or recommended settings. Advise users to review custom configurations from untrusted sources carefully.
- Preconditions:
    - The victim has the Deno extension for VS Code installed.
    - The victim opens a malicious VS Code workspace from an attacker.
    - The workspace is configured to use a malicious Deno configuration file via the `deno.config` setting.
- Source Code Analysis:
    1. `client\src\commands.ts` and `client\src\debug_config_provider.ts`:
        - Similar to `deno.importMap`, these files show how `deno.config` is retrieved and utilized when executing Deno commands or setting up debug configurations.
        - In `debug_config_provider.ts`:
            ```typescript
            #getAdditionalRuntimeArgs() {
                const args: string[] = [];
                const settings = this.#extensionContext.clientOptions
                .initializationOptions();
                // ...
                if (settings.config) {
                    args.push("--config");
                    args.push(settings.config.trim());
                }
                return args;
            }
            ```
        - In `commands.ts` (within the `test` function):
            ```typescript
            if (!testArgs.includes("--config")) {
                const configPath: string | undefined | null = config.get("config");
                if (configPath?.trim()) {
                    testArgs.push("--config", configPath.trim());
                }
            }
            ```
        - The code retrieves the `deno.config` path and directly passes it to the Deno CLI using the `--config` flag, without any inspection or validation of the configuration file's content.
    - Visualization:
        ```mermaid
        graph LR
            A[User opens malicious workspace] --> B(Extension activation);
            B --> C{Read deno.config from settings};
            C --> D[debug_config_provider.ts & commands.ts];
            D --> E{getConfiguration(EXTENSION_NS).get("config")};
            E --> F[No validation of config file content];
            F --> G[Pass --config to Deno CLI];
            G --> H[Deno CLI uses malicious config];
            H --> I[Configuration manipulation/Info Leak];
        ```
- Security Test Case:
    1. **Create Malicious Deno Config File:**
        - Create a file named `malicious_deno_config.json` in your testing workspace. For this test, we will attempt to use a compiler option that might lead to information leakage (though practical leakage might depend on Deno LSP internals and error reporting). A simple example is to try and set a custom `outDir`, though direct exploitation might be limited. More complex scenarios might involve manipulating module resolution or type checking behavior.
            ```json
            {
              "compilerOptions": {
                "outDir": "./malicious_output"
              }
            }
            ```
    2. **Configure Workspace Settings:**
        - In your workspace's `.vscode` folder, create or modify `settings.json` to set the `deno.config` path:
            ```json
            {
                "deno.enable": true,
                "deno.config": "./malicious_deno_config.json"
            }
            ```
    3. **Open Workspace:**
        - Open the workspace in VS Code with the Deno extension enabled.
    4. **Trigger Deno Extension Features:**
        - Open a TypeScript or JavaScript file in the workspace. This should trigger the Deno LSP to start and process the configuration.
        - Attempt to use features like type checking, linting, or formatting which might engage the Deno CLI with the provided configuration.
    5. **Observe Behavior and Check for Unexpected Output:**
        - Check if the configuration is applied. For instance, in this example, check if a directory `./malicious_output` is created, though `outDir` might not be directly relevant to LSP behavior and more for `deno compile`. The key is to observe if the extension is indeed processing and applying the configuration from `malicious_deno_config.json`. More sophisticated tests might involve analyzing LSP logs (if available and detailed enough) or observing changes in diagnostic outputs based on manipulated compilerOptions if exploitable options are found. For security validation, focus on configuration options that could potentially weaken security, expose information, or alter expected behavior in a way exploitable by an attacker.
