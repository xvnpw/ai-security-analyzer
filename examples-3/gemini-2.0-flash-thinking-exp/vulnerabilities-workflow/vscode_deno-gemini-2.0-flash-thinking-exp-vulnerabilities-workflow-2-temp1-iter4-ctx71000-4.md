- Vulnerability name: Malicious Deno Path Override leading to Arbitrary Code Execution
- Description:
  - An attacker can create a malicious project repository containing a crafted `.vscode/settings.json` file.
  - This `.vscode/settings.json` file overrides the `deno.path` setting, pointing it to a malicious executable file. This malicious executable can be located within the project repository itself or at a remote URL that is downloaded upon opening the workspace.
  - If a user, especially one who has globally enabled the Deno extension or is prone to enabling it per workspace, opens this malicious repository in Visual Studio Code, the Deno extension will attempt to locate and execute the Deno CLI.
  - Due to the overridden `deno.path` setting, instead of executing the legitimate Deno CLI, the extension will inadvertently execute the malicious executable specified in the `.vscode/settings.json`.
  - This execution happens in the context of the user's machine with the permissions of the VS Code process.
- Impact:
  - Arbitrary code execution on the user's machine.
  - Potential compromise of the user's system and data, depending on the actions performed by the malicious executable.
  - An attacker could gain unauthorized access, install malware, steal credentials, or perform other malicious activities.
- Vulnerability rank: Critical
- Currently implemented mitigations:
  - None. The extension currently trusts the path provided in the `deno.path` setting without validation.
- Missing mitigations:
  - Input validation and sanitization for the `deno.path` setting to ensure it points to a valid and safe executable location.
  - Display a warning message to the user when the `deno.path` setting is overridden by workspace settings, especially if it points to a location within the workspace or a temporary directory.
  - Consider using a more secure method to locate the Deno executable, possibly by relying on a known installation location or by prompting the user for explicit confirmation if the `deno.path` is modified.
- Preconditions:
  - The user must have the Deno extension for Visual Studio Code installed.
  - The user must open a workspace that contains a malicious `.vscode/settings.json` file.
  - The Deno extension must be enabled for the workspace, either through global settings, workspace settings, or by the presence of a `deno.json` or `deno.jsonc` file in the workspace root, causing the extension to activate and utilize the Deno language server.
- Source code analysis:
  - `client/src/util.ts`:
    - The function `getDenoCommandPath()` is responsible for determining the path to the Deno executable.
    - It first retrieves the `deno.path` setting from the workspace configuration using `workspace.getConfiguration(EXTENSION_NS).get<string>("path")`.
    - If `deno.path` is set, the function checks if it's an absolute path. If not, it attempts to resolve it relative to each workspace folder.
    - If `deno.path` is not set or the configured path is not found, it falls back to `getDefaultDenoCommand()` which searches for "deno" in the system's PATH and default installation directories.
    - **Vulnerability Point:** The code directly uses the value of `deno.path` from the configuration without any validation or sanitization. This allows a malicious workspace to inject an arbitrary executable path.
  - `client/src/commands.ts`:
    - The `startLanguageServer` function calls `getDenoCommandPath()` to get the Deno command.
    - It then uses this path to spawn a new Language Client (`LanguageClient`) with server options that include the resolved command path.
    -  ```typescript
       const serverOptions: ServerOptions = {
         run: {
           command, // Path from getDenoCommandPath()
           args: ["lsp"],
           options: { env },
         },
         debug: {
           command, // Path from getDenoCommandPath()
           args: ["lsp"],
           options: { env },
         },
       };
       const client = new LanguageClient( ... , serverOptions, ... );
       await client.start();
       ```
    - **Vulnerability Point:** The `command` obtained from `getDenoCommandPath()` is directly used in `ProcessExecution` without any checks, leading to the execution of the specified (potentially malicious) executable.

  - Visualization:

  ```mermaid
  graph LR
      subgraph VS Code Workspace
          A[User Opens Workspace] --> B(Malicious .vscode/settings.json)
      end

      subgraph VS Code Deno Extension
          C[Extension Activation] --> D{Read deno.path from settings}
          D --> E(getDenoCommandPath in util.ts)
          E --> F{No Validation on deno.path}
          F --> G(Return malicious path)
          G --> H(startLanguageServer in commands.ts)
          H --> I(LanguageClient spawns process)
          I --> J[Malicious Executable Runs]
      end

      B --> D
      E -- Malicious Path --> J
  ```
- Security test case:
  - Step 1: Create a new directory named `malicious-deno-workspace`.
  - Step 2: Inside `malicious-deno-workspace`, create a subdirectory named `.vscode`.
  - Step 3: Inside `.vscode`, create a file named `settings.json` with the following content. Replace `/path/to/malicious/script.sh` (for Linux/macOS) or `C:\\path\\to\\malicious\\script.bat` (for Windows) with the actual path to your malicious script. For testing, you can create a simple script that, for example, writes to a file or displays a message.

    ```json
    {
        "deno.path": "/path/to/malicious/script.sh"  // or "C:\\path\\to\\malicious\\script.bat" for Windows
    }
    ```

    Example malicious `script.sh` (Linux/macOS):
    ```bash
    #!/bin/bash
    echo "Malicious script executed by vscode-deno extension!" > /tmp/vscode-deno-exploit.txt
    ```

    Example malicious `script.bat` (Windows):
    ```batch
    @echo off
    echo Malicious script executed by vscode-deno extension! > C:\vscode-deno-exploit.txt
    ```
    **Ensure the script has execute permissions (e.g., `chmod +x script.sh`).** Place this script in `/path/to/malicious/` or `C:\\path\\to\\malicious\\` as referenced in `settings.json`.
  - Step 4: Open the `malicious-deno-workspace` directory in Visual Studio Code.
  - Step 5:  Ensure the Deno extension is enabled for this workspace (if not globally enabled, you might need to enable it for this workspace via the "Deno: Enable" command, or have a `deno.json` file in the workspace root).
  - Step 6: Observe the execution. The malicious script specified in `deno.path` will be executed by the Deno extension when it initializes the language server. In this test case, a file `/tmp/vscode-deno-exploit.txt` (or `C:\vscode-deno-exploit.txt` on Windows) should be created with the message.
  - Step 7: Verify the exploit by checking for the created file or observing the malicious actions defined in your script.

This test case demonstrates that by overriding the `deno.path` setting in the workspace configuration, an attacker can achieve arbitrary code execution when a user opens a malicious workspace with the VS Code Deno extension enabled.
