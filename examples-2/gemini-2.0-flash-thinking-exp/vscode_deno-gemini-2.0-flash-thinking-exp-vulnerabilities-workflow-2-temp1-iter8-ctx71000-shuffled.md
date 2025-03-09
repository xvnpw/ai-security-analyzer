## Combined Vulnerability List

### Malicious Module Import via Import Map Redirection
*   **Vulnerability Name:** Malicious Module Import via Import Map Redirection
    *   **Description:**
        1.  An attacker crafts a malicious `import_map.json` file. This file redirects module specifiers to attacker-controlled locations (e.g., a malicious server or a file path containing malicious code).
        2.  The attacker tricks a user into opening a VS Code workspace that contains this malicious `import_map.json` file.
        3.  If the Deno extension is enabled for this workspace (either explicitly by the user, or by auto-detection via `deno.json`), the extension will pass the path to the malicious `import_map.json` to the Deno language server through the `deno.importMap` setting.
        4.  When the user opens or creates a JavaScript/TypeScript file within the workspace and the Deno extension attempts to resolve module imports, it uses the provided import map.
        5.  Due to the malicious import map, module specifiers are redirected to attacker-controlled locations.
        6.  The Deno language server (and potentially Deno runtime if code is executed) fetches and executes code from these malicious locations.
        7.  This allows the attacker to execute arbitrary code within the user's environment when the Deno extension is active in the workspace.
    *   **Impact:** Arbitrary code execution. Successful exploitation can lead to various malicious outcomes, including data theft, installation of malware, or complete system compromise, depending on the privileges of the user running VS Code and the nature of the malicious code.
    *   **Vulnerability Rank:** High
    *   **Currently Implemented Mitigations:**
        *   Deno extension is not enabled by default (`deno.enable: false`). Users must explicitly enable it for a workspace or globally, reducing the attack surface to users who intentionally activate the extension.
        *   The extension supports workspace folder configurations, allowing users to enable Deno granularly, mitigating risk in multi-root workspaces by limiting Deno's scope.
    *   **Missing Mitigations:**
        *   Lack of explicit warning to the user when an `import_map.json` file is detected in a workspace, particularly upon initial Deno enablement in that workspace. A warning could educate users about the potential risks of using import maps from untrusted sources.
        *   Absence of input validation or sanitization within the VS Code extension for paths specified in `import_map.json`.
        *   Insufficient documentation within the extension explicitly highlighting the security risks associated with utilizing import maps from untrusted sources.
    *   **Preconditions:**
        *   The user has the VS Code Deno extension installed.
        *   The user opens a workspace provided by an attacker, which includes a malicious `import_map.json` file.
        *   The Deno extension is enabled for the workspace.
    *   **Source Code Analysis:**
        *   `client/src/extension.ts`: The `activate` function retrieves the `deno.importMap` setting from VS Code's configuration and passes it to the Deno Language Server.
            ```typescript
            initializationOptions: () => {
              const denoConfiguration = vscode.workspace.getConfiguration().get(
                EXTENSION_NS,
              ) as Record<string, unknown>;
              commands.transformDenoConfiguration(extensionContext, denoConfiguration);
              return {
                ...denoConfiguration, // includes importMap setting
                javascript: vscode.workspace.getConfiguration().get("javascript"),
                typescript: vscode.workspace.getConfiguration().get("typescript"),
                enableBuiltinCommands: true,
              } as object;
            },
            ```
        *   The VS Code extension transmits the `deno.importMap` setting to the Deno Language Server without validation. The vulnerability is in Deno's handling of import maps.
    *   **Security Test Case:**
        1.  Create `malicious-workspace/import_map.json` with malicious import redirection.
        2.  Create `malicious-workspace/malicious/code.js` with malicious JavaScript code.
        3.  Create `malicious-workspace/main.ts` importing `malicious-module`.
        4.  Open `malicious-workspace` in VS Code and enable Deno.
        5.  Open `main.ts`.
        6.  Observe malicious code execution in VS Code output console.

### Arbitrary Code Execution via Malicious Workspace Settings (`deno.path`)
* Vulnerability Name: Arbitrary Code Execution via Malicious Workspace Settings (`deno.path`)
    * Description:
        1. An attacker creates a malicious workspace folder with `.vscode/settings.json`.
        2. In `settings.json`, the attacker sets `deno.path` to a malicious executable.
        3. The attacker tricks a victim into opening this workspace in VS Code with the Deno extension enabled.
        4. When the Deno extension initializes or uses the Deno CLI, it reads `deno.path`.
        5. The extension executes the malicious executable specified in `deno.path`.
    * Impact: Arbitrary code execution on the victim's machine, potentially leading to full system compromise.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations:
        - None. The extension uses the `deno.path` setting without validation.
    * Missing Mitigations:
        - Input validation and sanitization for `deno.path`.
        - Warning to the user when workspace settings override `deno.path`.
        - Restricting `deno.path` to trusted locations.
        - Mechanism to verify if the executable at `deno.path` is a Deno CLI executable.
    * Preconditions:
        - "Deno for Visual Studio Code" extension installed and enabled.
        - Victim opens a workspace folder controlled by the attacker.
    * Source Code Analysis:
        1. **`client\src\util.ts:getDenoCommandPath()`**: Retrieves `deno.path` from workspace config without validation.
            ```typescript
            export async function getDenoCommandPath() {
              const command = getWorkspaceConfigDenoExePath();
              // ...
              return command; // Returns path directly without validation
            }

            function getWorkspaceConfigDenoExePath() {
              const exePath = workspace.getConfiguration(EXTENSION_NS)
                .get<string>("path"); // Reads "deno.path" setting
              return exePath;
            }
            ```
        2. **`client\src\tasks.ts:buildDenoTask()` and `client\src\debug_config_provider.ts:DenoDebugConfigurationProvider`**: Use the path from `getDenoCommandPath()` to execute Deno commands.
    * Security Test Case:
        1. **Setup Malicious Executable:** Create `malicious-deno/deno.sh` (or `deno.bat`) with malicious script (e.g., creates `/tmp/pwned.txt`). Make it executable.
        2. **Create Malicious Workspace:** Create `malicious-workspace/.vscode/settings.json` with `"deno.path": "/path/to/malicious-deno/deno.sh"`. Create `test.ts`.
        3. **Open Workspace in VS Code:** Open `malicious-workspace`. Enable Deno extension.
        4. **Trigger Deno Extension Execution:** Open `test.ts` or run "Deno: Cache".
        5. **Verify Malicious Code Execution:** Check for output in VS Code output panel and existence of `/tmp/pwned.txt`.

### Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings
* Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings
    * Description:
        1. Attacker tricks user into opening a VS Code workspace with a Deno project.
        2. Attacker persuades user to add malicious command-line arguments to `deno.testing.args` or `deno.codeLens.testArgs` settings in workspace settings.
        3. User executes Deno tests via CodeLens or Test Explorer.
        4. Deno extension spawns Deno CLI process for tests.
        5. Extension directly incorporates user-provided arguments into the Deno CLI command line without sanitization.
        6. Injected shell commands are executed, leading to arbitrary code execution.
    * Impact: Critical. Arbitrary code execution on the user's machine, potentially leading to full system compromise.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations:
        - No mitigations for command injection via these settings.
    * Missing Mitigations:
        - Input sanitization for `deno.testing.args` and `deno.codeLens.testArgs`.
        - User warning when modifying these settings.
        - Reconsider default `"--allow-all"` argument.
    * Preconditions:
        - "Deno for Visual Studio Code" extension installed and enabled.
        - Deno CLI installed.
        - Attacker tricks user into opening malicious workspace or modifying settings.
        - User executes Deno tests using CodeLens or Test Explorer.
    * Source Code Analysis:
        1. File: `client/src/commands.ts`, Function: `test`
        2. Retrieves `deno.codeLens.testArgs` setting.
        3. Directly includes `testArgs` in the `args` array for `deno test` command.
        4. `vscode.tasks.executeTask` executes command via system shell, leading to command injection.
    * Security Test Case:
        1. Prerequisites: VS Code, Deno extension, Deno CLI, new workspace, `test.ts`.
        2. Vulnerability Injection: Modify workspace settings (`.vscode/settings.json`) to add malicious command to `deno.codeLens.testArgs` (e.g., `; touch /tmp/deno_pwned ;`).
        3. Triggering the Vulnerability: Open `test.ts`, click "Run Test" CodeLens.
        4. Verification of Exploitation: Check for `/tmp/deno_pwned` file, confirming command injection. Repeat for `deno.testing.args` and Test Explorer.

### Malicious Import Suggestions via Compromised Hosts
* Vulnerability Name: Malicious Import Suggestions via Compromised Hosts
    * Description:
        1. Attacker compromises a domain in `deno.suggest.imports.hosts`.
        2. Developer has compromised domain in `deno.suggest.imports.hosts`.
        3. Developer works on Deno project, triggers auto-completion for imports.
        4. Deno extension requests import suggestions from compromised domain.
        5. Attacker's compromised domain serves malicious JavaScript/TypeScript code as suggestions.
        6. Extension displays malicious suggestions.
        7. Developer selects a malicious suggestion.
        8. Malicious code's URL is inserted as import statement.
        9. Deno fetches and potentially executes malicious code.
    * Impact: Arbitrary Code Execution. Project Compromise. Supply Chain Attack.
    * Vulnerability Rank: High
    * Currently Implemented Mitigations:
        - User Prompt for Registry Suggestions with warning "Only do this if you trust...".
    * Missing Mitigations:
        - Input Validation and Sanitization for `deno.suggest.imports.hosts`.
        - Content Security Policy (CSP) for Suggestions.
        - Enhanced User Education and Awareness.
        - Domain Reputation and Trust Indicators.
        - Sandboxing or Isolation for Suggestion Retrieval.
    * Preconditions:
        1. VS Code Deno extension installed and enabled.
        2. Deno enabled for workspace.
        3. Domain added to `deno.suggest.imports.hosts`.
        4. Attacker compromises domain.
        5. Developer triggers import auto-completion.
    * Source Code Analysis:
        1. Configuration Setting: `deno.suggest.imports.hosts` user configurable.
        2. `client\src\notification_handlers.ts`: `createRegistryStateHandler` prompts user and updates `deno.suggest.imports.hosts`.
            ```typescript
            export function createRegistryStateHandler(): NotificationHandler<RegistryStateParams> {
              return async function handler({ origin, suggestions }) {
                // ...
                const selection = await vscode.window.showInformationMessage(
                  `The server "${origin}" supports completion suggestions for imports. Do you wish to enable this? (Only do this if you trust "${origin}") [Learn More](https://github.com/denoland/vscode_deno/blob/main/docs/ImportCompletions.md)`,
                  "No", "Enable",
                );
                // ... updates deno.suggest.imports.hosts based on user choice
              };
            }
            ```
        3. `client\src\extension.ts`: `initializationOptions` passes `deno.suggest.imports` to language server.
    * Security Test Case:
        1. Setup Mock Malicious Server (`http://localhost:8080`) serving malicious import suggestions.
        2. Configure VS Code Deno Extension: Add `localhost:8080` to `deno.suggest.imports.hosts`.
        3. Create Test Project.
        4. Trigger Auto-Completion in `test.ts` (`import {`).
        5. Verify Malicious Suggestion ("malicious-module" from `localhost:8080`).
        6. Select and Insert Malicious Import.
        7. Run/Type-Check Code.
        8. Observe Malicious Code Execution.
