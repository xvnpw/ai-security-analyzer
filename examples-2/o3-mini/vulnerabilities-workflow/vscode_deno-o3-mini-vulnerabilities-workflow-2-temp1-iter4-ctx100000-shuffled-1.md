- **Vulnerability Name:** Arbitrary Command Execution via Malicious “deno.path” Configuration
  **Description:**
  The extension reads the Deno executable path from the workspace configuration (via the `deno.path` setting) and uses it directly to launch the Deno language server, debug sessions, and tasks. An attacker who is able to modify a workspace’s settings (for example, by committing a malicious configuration file into a shared repository) can supply a path that points to an attacker-controlled binary (for example, a relative path such as `"./malicious_executable"` or using directory traversal like `"../../malicious.exe"`). When the user opens the workspace and the extension is enabled, the extension will resolve and spawn the binary provided in `deno.path`, leading to arbitrary command execution and full system compromise on the developer’s machine.

  **Impact:**
  Execution of attacker-controlled code on the developer’s system with potentially full system compromise.

  **Vulnerability Rank:** Critical

  **Currently Implemented Mitigations:**
  - The extension uses helper functions (e.g. in `client/src/util.ts`) that perform a simple resolution of relative paths (by resolving against all workspace folders) and verify the existence of the file using `fs.stat()`.
  - However, no further verification (such as checking against a whitelist, validating digital signatures, or confirming that the binary comes from a trusted directory) is performed.

  **Missing Mitigations:**
  - No sanitization or strict validation of the executable path provided via `deno.path`.
  - No policy restricting the allowed locations for the binary (for example, enforcing that it must be an absolute path from a known safe location).
  - No user confirmation or warning is issued when a nonstandard or relative path is used.

  **Preconditions:**
  - The attacker must have the ability to modify the workspace configuration files (for instance, via a shared repository commit or social engineering that convinces the developer to open a compromised workspace).

  **Source Code Analysis:**
  - In `client/src/util.ts`, the function `getDenoCommandPath()` retrieves the `deno.path` setting via `getWorkspaceConfigDenoExePath()` without sanitization.
  - If the path is relative, the code resolves it against each workspace folder using `path.resolve()` and checks for existence using a simple `fs.stat()` call.
  - The resulting path is then returned and later used as the `runtimeExecutable` (in the debug configuration in `client/src/debug_config_provider.ts` and in task-building functions in `client/src/tasks.ts`) without any further checks.
  - This means that if an attacker sets a malicious relative or absolute path, the extension will blindly execute it.

  **Security Test Case:**
  1. Create a test workspace with a file (for example, a “malicious” script) that behaves in a detectable way (for instance, writing a special file or logging a message to a known location).
  2. In the workspace’s `.vscode/settings.json`, add a configuration entry such as:
     ```json
     {
       "deno.path": "./malicious_executable"
     }
     ```
  3. Ensure that the “malicious_executable” file is present in the workspace (or reachable via a crafted relative path) and has appropriate execute permissions.
  4. Open the workspace in Visual Studio Code and trigger the extension’s activation (for example, by running “Deno: Enable” or starting a debug configuration).
  5. Verify that the malicious executable is launched — for instance, check for the creation of the file or for the recorded log message that confirms its execution.
  6. Confirm that the unwanted behavior (indicative of arbitrary code execution) occurs as a result of the malicious configuration.
