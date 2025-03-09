- **Vulnerability Name:** Malicious Workspace Configuration Injection for Deno CLI Processes

  - **Description:**
    The extension loads critical settings (such as the path to the Deno executable, extra CLI flags, or configuration file locations) directly from workspace configuration files (for example, from a project’s .vscode/settings.json). An attacker who controls a repository (or otherwise tricks a victim into opening an untrusted workspace) can supply a malicious configuration that sets keys like `"deno.path"`, `"deno.config"`, or `"deno.codeLens.testArgs"` to attacker‑controlled values. When the extension starts the Deno Language Server, creates tasks, or runs tests, it calls functions (for example, `getDenoCommandPath()` in the client’s utility module and task/build functions in commands.ts) that read these settings and then spawn a new process without properly verifying that the supplied values refer only to a “legitimate” Deno executable or safe CLI arguments. An attacker can, for instance, specify an absolute path to a malicious binary in `"deno.path"`. Once the victim opens the workspace, the extension will use that executable (with additional arguments such as `"lsp"` or those provided in `"deno.codeLens.testArgs"`) to launch the Deno process—inviting arbitrary code execution.

  - **Impact:**
    If exploited, the attacker-controlled configuration would lead to the execution of arbitrary commands on the victim’s machine. This may result in full compromise of the victim’s system because the spawned malicious process can run with the same privileges as the user running Visual Studio Code.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - When resolving a custom executable path (via `"deno.path"`), the extension checks for the existence of the file (using an asynchronous `fs.stat` in `getDenoCommandPath()`).
    - In the case of relative paths, the extension attempts to resolve the path against all workspace folders and falls back if no match is found.
    *Note:* These checks only ensure that the file exists and do not enforce that it is the expected Deno binary.

  - **Missing Mitigations:**
    - **Input Validation/Whitelisting:** There is no rigorous validation that the value supplied by `"deno.path"` (or other settings such as `"deno.config"`) is a known, trustworthy Deno executable.
    - **User Consent or Warning:** The extension does not prompt the user to confirm the use of a workspace‑supplied executable path or CLI arguments before execution.
    - **Sanitization of Arguments:** The extension does not sanitize or constrain additional CLI arguments (e.g. those contributed through `"deno.codeLens.testArgs"`), which could be used to alter runtime behavior unexpectedly.

  - **Preconditions for Exploitation:**
    - The victim must open a workspace (or project) that contains a malicious configuration file (for example, a .vscode/settings.json that has been altered to include attacker‑controlled values).
    - The victim must trust the workspace or not realize that its configuration is overridden by untrusted settings.

  - **Source Code Analysis:**
    - In **client/src/util.ts → getDenoCommandPath()**:
      The function retrieves the value of the `"deno.path"` setting via the workspace configuration and then—if a relative path is given—resolves it against each workspace folder. For an absolute path, the value is returned directly. No additional checks are performed to ensure that the resolved path points to a genuine Deno executable.
    - In **client/src/commands.ts (function startLanguageServer)**:
      The command to start the Deno Language Server is obtained by calling `getDenoCommandPath()`. The returned value (which may be attacker‑controlled if a malicious workspace configuration is present) is then used as the `command` parameter in a `LanguageClient` startup configuration.
    - In **client/src/commands.ts (function test)** and elsewhere (for tasks and debug configurations):
      Similar patterns occur where configuration keys like `"deno.codeLens.testArgs"`, `"deno.config"`, and `"deno.importMap"` are read and then directly injected into the arguments array that is passed to the spawned process. Even though the processes are started via VS Code’s API (using `new vscode.ProcessExecution(...)` with an arguments array), the lack of strict validation means an attacker can control which binary is run or which arguments are passed.

  - **Security Test Case:**
    1. **Setup a Malicious Workspace Configuration:**
       - Create a test workspace containing a `.vscode/settings.json` file with the following content:
         ```json
         {
           "deno.path": "/tmp/malicious_executable",
           "deno.codeLens.testArgs": ["--malicious-flag", "payload"]
         }
         ```
       - On the test system, create a dummy executable at `/tmp/malicious_executable` (ensure it is marked as executable). For example, the dummy executable might simply write a file (e.g., `/tmp/hacked.txt`) to indicate execution:
         ```bash
         #!/bin/bash
         echo "Malicious payload executed" > /tmp/hacked.txt
         ```
    2. **Open the Workspace in VS Code with the Deno Extension Enabled:**
       - Launch VS Code and open the test workspace.
       - Since the extension reads the workspace configuration immediately on activation, it will call `getDenoCommandPath()` and resolve `"deno.path"` to `/tmp/malicious_executable`.
    3. **Trigger a Deno Process Spawn:**
       - Run a command that forces the extension to spawn a Deno process (for example, run the _Deno: Enable_ command to start the Language Server or trigger a test command that spawns a process).
    4. **Verify Exploitation:**
       - Confirm that the dummy malicious executable was executed (e.g., check for the existence and contents of `/tmp/hacked.txt`).
       - Observe in the extension’s output or via other side effects that the supplied CLI arguments (including `"--malicious-flag"`) were passed to the malicious executable.
    5. **Conclusion:**
       - Successful execution of the dummy payload verifies that the extension accepts unsanitized configuration values, allowing an attacker to control the spawned process.
