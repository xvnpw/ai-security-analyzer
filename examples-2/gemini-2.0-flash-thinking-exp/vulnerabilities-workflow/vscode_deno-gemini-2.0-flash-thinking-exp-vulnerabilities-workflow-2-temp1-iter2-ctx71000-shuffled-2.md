- Vulnerability Name: Arbitrary Code Execution via Malicious Deno Path Configuration
- Description:
  1. An attacker social engineers a victim into changing the `deno.path` setting in VS Code. This can be achieved through various phishing techniques, misleading instructions on websites, or by directly convincing the victim through communication channels.
  2. The victim, believing they are improving or configuring their Deno development environment, sets the `deno.path` setting to point to a malicious executable provided by the attacker. This malicious executable can be located anywhere on the victim's file system, or even on a network share accessible to the victim's machine.
  3. Once the `deno.path` is maliciously configured, the VS Code Deno extension, upon activation or when triggered by certain actions (like running a Deno command, formatting, linting, testing, or any other feature that invokes the Deno CLI), will execute the program specified in `deno.path` setting.
  4. The malicious executable, now running in the context of the victim's user privileges, can perform arbitrary actions on the victim's system. This could include data theft, installation of malware, system corruption, or any other malicious activity the attacker designs the executable to perform.
- Impact:
  - Complete compromise of the user's system.
  - Arbitrary code execution with the privileges of the user running VS Code.
  - Potential data exfiltration, malware installation, and other malicious actions.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - No mitigations are currently implemented within the extension to prevent execution of arbitrary executables specified in the `deno.path` setting. The extension directly uses the path provided by the user configuration without any validation or sanitization.
- Missing Mitigations:
  - Input validation: The extension should validate the `deno.path` setting to ensure it points to a legitimate Deno executable. This could involve checking the file extension, verifying a digital signature, or using a whitelist of allowed paths.
  - User warning: Display a prominent warning to the user when they are about to change the `deno.path` setting, especially if the path is outside of standard Deno installation locations. This warning should highlight the security risks of pointing this setting to untrusted executables.
  - Path sanitization: Ensure that the path provided by the user is sanitized to prevent any form of command injection or unexpected execution behavior.
  - Principle of least privilege: While not directly mitigating this vulnerability, ensuring the extension itself runs with the least privileges necessary can limit the damage an attacker can cause even if the vulnerability is exploited.
- Preconditions:
  - The victim has the VS Code Deno extension installed and enabled.
  - The attacker must successfully social engineer the victim into changing the `deno.path` setting and providing a path to a malicious executable.
  - The victim must perform an action within VS Code that triggers the extension to execute the Deno CLI (e.g., opening a Deno project, running a Deno command, using formatting or linting features).
- Source Code Analysis:
  - File: `client/src/util.ts`
  - Function: `getDenoCommandPath()`
  ```typescript
  export async function getDenoCommandPath() {
    const command = getWorkspaceConfigDenoExePath(); // [1] Get path from settings
    const workspaceFolders = workspace.workspaceFolders;
    if (!command || !workspaceFolders) {
      return command ?? await getDefaultDenoCommand();
    } else if (!path.isAbsolute(command)) { // [2] Resolve relative path if not absolute
      // if sent a relative path, iterate over workspace folders to try and resolve.
      for (const workspace of workspaceFolders) {
        const commandPath = path.resolve(workspace.uri.fsPath, command);
        if (await fileExists(commandPath)) {
          return commandPath;
        }
      }
      return undefined;
    } else {
      return command; // [3] Return absolute path as is
    }
  }

  function getWorkspaceConfigDenoExePath() {
    const exePath = workspace.getConfiguration(EXTENSION_NS)
      .get<string>("path"); // [1] Get 'deno.path' setting
    // it is possible for the path to be blank. In that case, return undefined
    if (typeof exePath === "string" && exePath.trim().length === 0) {
      return undefined;
    } else {
      return exePath; // [2] Return path from settings
    }
  }
  ```
  - **[1] `getWorkspaceConfigDenoExePath`**: This function retrieves the value of the `deno.path` configuration setting.
  - **[2] `getDenoCommandPath`**: This function calls `getWorkspaceConfigDenoExePath` to get the configured path. If a path is configured and it's absolute, it proceeds to return it without any validation. If it's relative, it attempts to resolve it, but if it's absolute, it's used directly.
  - **[3] Return absolute path as is**: The code directly returns the absolute path from settings without any checks to ensure it's a valid or safe Deno executable.

  - File: `client/src/tasks.ts`
  - Function: `buildDenoTask()`
  ```typescript
  export function buildDenoTask(
    target: vscode.WorkspaceFolder,
    process: string, // [1] 'process' is the command path from getDenoCommandPath
    definition: DenoTaskDefinition,
    name: string,
    args: string[],
    problemMatchers: string[],
  ): vscode.Task {
    const exec = new vscode.ProcessExecution(
      process, // [2] 'process' is directly used in ProcessExecution
      args,
      definition,
    );

    return new vscode.Task(
      definition,
      target,
      name,
      TASK_SOURCE,
      exec,
      problemMatchers,
    );
  }
  ```
  - **[1] `process` parameter**: The `buildDenoTask` function takes `process` as a parameter, which comes directly from `getDenoCommandPath()`.
  - **[2] `ProcessExecution`**: The `process` variable, which could be a malicious path from `deno.path`, is directly used to create a `vscode.ProcessExecution`. This will cause VS Code to execute the provided path.

  - Visualization:

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

- Security Test Case:
  1. **Setup Malicious Executable**: Create a simple executable file (e.g., a `.bat` file on Windows, a shell script on Linux/macOS) that simulates malicious behavior. For example, the script could write a message to a file system, display a pop-up, or attempt network communication.
     - Example `malicious.bat` (Windows):
       ```bat
       @echo off
       echo Vulnerability Exploited > exploited.txt
       echo Malicious code executed!
       ```
     - Example `malicious.sh` (Linux/macOS):
       ```sh
       #!/bin/bash
       echo "Vulnerability Exploited" > exploited.txt
       echo "Malicious code executed!"
       ```
     - Ensure the script is executable (`chmod +x malicious.sh` on Linux/macOS).
  2. **Place Malicious Executable**: Place this malicious executable in a known location on your test system (e.g., `/tmp/malicious.sh` or `C:\temp\malicious.bat`).
  3. **Configure `deno.path`**: In VS Code, open the settings (Ctrl+,). Search for `deno.path` and set it to the path of your malicious executable (e.g., `/tmp/malicious.sh` or `C:\temp\malicious.bat`).
  4. **Trigger Deno Extension**: Open any TypeScript or JavaScript file in VS Code. Ensure the Deno extension is active for this workspace (you might need to enable Deno for the workspace if it's not already). Trigger any Deno command that would execute the Deno CLI. For example, you can try to format the document (if Deno is configured as the formatter) or use the "Deno: Cache" command from the command palette.
  5. **Observe Malicious Execution**: Check if the malicious executable has been executed. In the example scripts above, check for the creation of the `exploited.txt` file in your user's home directory or the location where the script was executed. Observe the output of the malicious script (e.g., the "Malicious code executed!" message, if displayed).
  6. **Verification**: If the `exploited.txt` file is created and the "Malicious code executed!" message (or similar malicious behavior you programmed) is observed, then the Arbitrary Code Execution vulnerability via malicious `deno.path` configuration is confirmed.

This test case demonstrates how an attacker can achieve arbitrary code execution by tricking a user into configuring the `deno.path` setting to point to a malicious executable.
