### Vulnerabilities Report

This report details a critical vulnerability found in the VS Code Deno extension, allowing for arbitrary code execution.

- **Vulnerability Name**: Arbitrary Code Execution via Malicious Deno Path Configuration

  - **Description**:
    1. A user can configure the `deno.path` setting in VS Code to specify the path to the Deno executable.
    2. The VS Code Deno extension uses this setting to locate and execute the Deno CLI for various functionalities like language server, tasks, and testing.
    3. The extension lacks validation and sanitization of the `deno.path` setting.
    4. A malicious actor can leverage social engineering tactics to trick a user into setting `deno.path` to a malicious executable or script. This could be achieved through phishing, misleading instructions, or malicious workspace configurations.
    5. When the extension attempts to execute a Deno command, it will use the maliciously configured path, leading to the execution of the attacker's code instead of the legitimate Deno CLI.
    6. This results in arbitrary code execution on the user's system with the privileges of the VS Code process.

  - **Impact**:
    - Complete compromise of the user's system is possible.
    - Arbitrary code can be executed with the same privileges as the VS Code process.
    - Potential consequences include data theft, installation of malware, system corruption, and other malicious activities.

  - **Vulnerability Rank**: Critical

  - **Currently implemented mitigations**:
    - None. The extension directly retrieves and utilizes the `deno.path` setting without any form of validation or security measures.

  - **Missing mitigations**:
    - **Input validation and sanitization**: The extension must validate the `deno.path` setting to ensure it points to a legitimate Deno executable. This validation should include checks for file type, path location, and potentially digital signatures.
    - **User warning**: A clear and prominent warning should be displayed to the user when they are modifying the `deno.path` setting, especially if the path deviates from standard Deno installation locations. This warning should emphasize the security risks associated with pointing this setting to untrusted executables.
    - **Path sanitization**: The provided path should be sanitized to prevent any form of command injection or unexpected execution behavior.

  - **Preconditions**:
    - The user must have the VS Code Deno extension installed and enabled.
    - The user must be successfully social engineered into modifying the `deno.path` setting to point to a malicious executable.
    - An action within VS Code that triggers the Deno extension to execute the Deno CLI must be performed (e.g., opening a Deno project, running a Deno command, using formatting or linting features).

  - **Source code analysis**:
    - **File**: `client/src/util.ts`
    - **Function**: `getDenoCommandPath()`
      - The function `getWorkspaceConfigDenoExePath()` retrieves the value of the `deno.path` configuration setting from VS Code workspace settings.
      - `getDenoCommandPath()` calls `getWorkspaceConfigDenoExePath()` to obtain the configured path.
      - If a path is configured and it is absolute, the function directly returns it without any validation or security checks. If the path is relative, it attempts to resolve it within workspace folders, but absolute paths are used directly.
      - Code snippet from `client/src/util.ts`:
        ```typescript
        function getWorkspaceConfigDenoExePath() {
          const exePath = workspace.getConfiguration(EXTENSION_NS)
            .get<string>("path");
          if (typeof exePath === "string" && exePath.trim().length === 0) {
            return undefined;
          } else {
            return exePath; // Directly returns user-provided path
          }
        }
        ```
    - **File**: `client/src/commands.ts` and `client/src/tasks.ts`
      - Functions like `startLanguageServer()` and `buildDenoTask()` utilize the path returned by `getDenoCommandPath()` to execute Deno CLI commands.
      - This path, which can be controlled by the user via the `deno.path` setting, is directly passed to `child_process.spawn` or similar execution mechanisms without sanitization.
      - Code snippet from `client/src/commands.ts`:
        ```typescript
        const serverOptions: ServerOptions = {
          run: {
            command, // Unsanitized path from settings
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // Unsanitized path from settings
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( ... );
        await client.start();
        ```
    - **Visualization**:
      ```mermaid
      graph LR
          subgraph VS Code Deno Extension
              Settings("deno.path Setting (User Controlled)")
              getWorkspaceConfigDenoExePath --> Settings
              getDenoCommandPath --> getWorkspaceConfigDenoExePath
              getDenoCommandName --> getDenoCommandPath
              buildDenoTask --> getDenoCommandName
              ProcessExecution --> buildDenoTask
              Task --> ProcessExecution
              ExecuteTask("VS Code Task Execution API") --> Task
          end
          MaliciousExecutable("Malicious Executable (User Specified in deno.path)")
          ProcessExecution --> MaliciousExecutable
          UserAction("User Triggers Deno Command (e.g., Format, Lint, Test)") --> ExecuteTask
          SocialEngineering("Social Engineering Attack") --> Settings

          style Settings fill:#f9f,stroke:#333,stroke-width:2px
          style MaliciousExecutable fill:#fbb,stroke:#333,stroke-width:2px
          style SocialEngineering fill:#ccf,stroke:#333,stroke-width:2px
      ```

  - **Security test case**:
    1. **Create Malicious Script**: Create an executable script (e.g., `malicious.sh` on Linux/macOS or `malicious.bat` on Windows) with malicious commands. For example:
       - `malicious.sh`:
         ```bash
         #!/bin/bash
         echo "Malicious script executed!"
         touch /tmp/pwned_by_deno_extension
         ```
       - Make the script executable: `chmod +x malicious.sh`
    2. **Configure `deno.path`**: In VS Code settings (Ctrl+,), search for "deno.path" and set it to the absolute path of your malicious script (e.g., `/path/to/malicious.sh`).
    3. **Trigger Deno Extension**: Reload VS Code or restart the Deno language server ("Deno: Restart Language Server"). Alternatively, trigger any Deno command such as "Deno: Cache" or use a test code lens.
    4. **Observe Execution**: Check for the execution of the malicious script. For `malicious.sh` example, verify the creation of the `/tmp/pwned_by_deno_extension` file and observe "Malicious script executed!" in the output.
    5. **Verification**: Successful execution of the malicious script confirms the Arbitrary Code Execution vulnerability.
