# Vulnerabilities

## Vulnerability: Arbitrary Executable Path Override via Malicious Workspace Settings

- **Description:**
  A threat actor can supply a malicious repository that contains workspace configuration files (for example, a *.vscode/settings.json* or a Deno configuration file) with a manipulated setting for `"deno.path"`. This setting tells the extension which executable to use when starting its processes (for instance, the Deno language server or Deno CLI tasks). The extension reads this value without further validation and, when starting the language server (or running tasks), passes it directly to the process execution API.
  **Step by step:**
  1. The attacker creates a repository that includes a workspace settings file (or Deno configuration file) with an entry similar to:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
     Alternatively, a relative path like `"../../evil"` can be used to point outside the expected directory.
  2. The victim opens the repository in Visual Studio Code and (if prompted) trusts the workspace.
  3. During activation, the extension calls the helper function `getDenoCommandPath()` (in *client/src/util.ts*), which in turn calls `getWorkspaceConfigDenoExePath()` to read the `"deno.path"` configuration value without any sanity checking.
  4. When the extension later starts the Deno language server (in *client/src/commands.ts*, within `startLanguageServer()`), it uses the (malicious) path provided by the configuration in the call to spawn a new process using VSCode’s `ProcessExecution` API.
  5. As a result, the malicious executable is launched on the victim’s machine, effectively resulting in remote code execution in the context of the user.

- **Impact:**
  This vulnerability allows an attacker to execute an arbitrary program on the victim’s machine. An attacker-controlled executable might perform any action (for example, writing files, installing malware, or exfiltrating data) with the privileges of the user running VSCode.

- **Vulnerability Rank:**
  Critical

- **Currently Implemented Mitigations:**
  - The extension attempts to resolve the command path by checking if the provided value is absolute and, if not, resolving it relative to one of the workspace folders.
  - However, no explicit checks (such as whitelisting, signature verification, or even a confirmation prompt) exist to ensure that the resolved executable is the expected Deno binary.

- **Missing Mitigations:**
  - **Input Validation/Sanitization:** The value of `"deno.path"` should be validated against a whitelist or expected pattern (for example, ensuring that it points to a binary named “deno” in known safe directories).
  - **User Confirmation:** The extension could prompt the user to confirm if a workspace configuration overrides the default executable path.
  - **Security Context Enforcement:** The extension might also check that such critical settings are not coming solely from the workspace before using them (for example, by requiring an explicit override from the user).

- **Preconditions:**
  - The victim must open and trust a workspace provided by the attacker.
  - The repository must include workspace configuration (or a Deno configuration file) that defines `"deno.path"` with a value controlled by the attacker and pointing to an executable under the attacker’s control.

- **Source Code Analysis:**
  - In **client/src/util.ts**, the function `getWorkspaceConfigDenoExePath()` retrieves the configuration value:
    ```ts
    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath;
      }
    }
    ```
    Here, the value (which comes directly from the workspace settings) is not validated or sanitized.
  - The function `getDenoCommandPath()` checks whether the provided path is absolute. If not, it attempts to resolve it relative to each workspace folder without verifying that the resolved file is the expected Deno executable.
  - Later in **client/src/commands.ts** (within `startLanguageServer()`), the return value from `getDenoCommandPath()` is used as the `command` property for starting the language server:
    ```ts
    const command = await getDenoCommandPath();
    // … later used in:
    const serverOptions: ServerOptions = {
      run: { command, args: ["lsp"], options: { env } },
      // ...
    };
    ```
    There is no check to ensure that the `command` is safe; if it originates from a malicious workspace file, that value is trusted and executed.

- **Security Test Case:**
  1. Create a test repository that includes a file such as *./.vscode/settings.json* with the following content:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
  2. In the repository (or in a test workspace folder), place a stand-in executable named `malicious_executable` that—for testing purposes—could simply write a file (e.g., `pwned.txt`) to an observable location or output a distinctive log message.
  3. Open this test repository as a workspace in Visual Studio Code and, when prompted, choose to trust the workspace.
  4. Trigger the Deno extension (for example, by running “Deno: Enable” or any command that initiates the language server).
  5. Verify that the extension spawns the executable located at the path specified by `"deno.path"`. Confirm the malicious action (such as the creation of the file `pwned.txt` or the log message) to demonstrate that arbitrary code execution has occurred.
