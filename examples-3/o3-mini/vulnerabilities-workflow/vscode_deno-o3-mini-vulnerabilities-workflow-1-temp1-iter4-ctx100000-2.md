# Vulnerabilities

---

## 1. Arbitrary Command Execution via Malicious “deno.path” Setting

**Description:**
The extension reads the configuration setting “deno.path” from the workspace (for example, from a repository’s .vscode/settings.json). This setting is used to resolve the command that starts the Deno language server. No sanitization or validation is performed on the value of “deno.path”. An attacker who controls the repository can supply a value that points to a malicious executable (or a shim script) rather than a trusted Deno binary. When the victim—who has not reconfigured or vetted their settings—opens the workspace, the extension will resolve and spawn the malicious command for both normal and debug server runs.

**Impact:**
If successfully exploited, the malicious executable will run with the privileges of the victim’s VS Code process. This results in full remote code execution; attacker-controlled code will run on the victim’s machine, effectively compromising the integrity and security of the entire system.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension fetches the “deno.path” value via the VS Code configuration API but does not verify that the value points to a trusted executable (e.g. by checking its absolute path, signature, or location).

**Missing Mitigations:**
- Validate and sanitize the “deno.path” value to ensure that only known safe paths or executables are accepted.
- Consider requiring explicit user confirmation if a nonstandard executable is detected, particularly when the value is supplied through workspace settings rather than user settings.

**Preconditions:**
- The victim must open a workspace (i.e. a repository) that contains a manipulated `.vscode/settings.json` which sets “deno.path” to a malicious executable.
- The victim’s workspace trust (or lack thereof) must allow the settings to be applied without further notice.

**Source Code Analysis:**
1. In **util.ts**, the function `getWorkspaceConfigDenoExePath()` retrieves the “deno.path” setting using:
   ```ts
   const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
   ```
   This value is taken directly from the workspace with no sanitization or validation.

2. The unsanitized value is then used directly in `getDenoCommandPath()`, a function which is called by `startLanguageServer()` in **commands.ts**.

3. Finally, the Deno language server (and other subprocesses, such as tasks) is launched using the attacker‑controlled command value, meaning that the malicious executable will be spawned when VS Code starts the language server.

**Security Test Case:**
1. Create a test repository that includes a `.vscode/settings.json` file with the following entry:
   ```json
   {
     "deno.path": "./malicious.sh"
   }
   ```
   Include in the repository a script named `malicious.sh` that, for example, writes a file to disk or displays a message indicating unauthorized execution.

2. Open the repository in VS Code (ensuring workspace trust is enabled) so that the extension reads the custom settings.

3. Observe that the extension uses the supplied “deno.path” value when starting the language server. An expected side effect (such as writing of the file or displaying an alert) will confirm that `malicious.sh` was executed instead of the trusted Deno CLI executable.

4. Verify that the malicious script runs with the privileges of the victim’s VS Code process.

---

## 2. Environment Variable Injection via Malicious “envFile” Setting

**Description:**
Within the extension, when starting the language server or running tests, the code retrieves an “envFile” configuration value from the workspace settings. This value is then concatenated with the workspace folder’s path using `path.join()` and read using file system operations. No restrictions are imposed to prevent directory traversal or ensure that the file remains confined within a trusted directory. An attacker controlling the repository can supply an “envFile” entry (again, via `.vscode/settings.json`) that points outside the intended workspace directory. The file’s contents are then parsed by the dotenv library and merged into the environment passed to the spawned process. Through the injected environment variables, the attacker can alter the behavior of the Deno language server or any spawned Deno task—potentially causing it to load unexpected code or libraries, leading to remote code execution.

**Impact:**
By injecting carefully selected environment variables, an attacker may modify how the Deno process operates, potentially influencing it to perform unauthorized actions or execute arbitrary commands. This manipulation can lead to remote code execution, compromising the system running the VS Code extension.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The extension uses `path.join()` with the workspace folder URI and the “envFile” value when building the file path, but it does not validate that the resulting path is confined to a specific, trusted directory.

**Missing Mitigations:**
- Sanitize the “envFile” input to ensure that it does not include directory traversal tokens (e.g., “..”) or resolve to files outside the workspace.
- Enforce that only files within a trusted sub‑directory (or on an approved allow‑list) are used for loading environment variables.

**Preconditions:**
- The victim must open a workspace containing a manipulated `.vscode/settings.json` that specifies an “envFile” with directory traversal patterns or that points to an unintended file location.
- The referenced file must exist and contain environment variable definitions that can affect the operation of the spawned process.

**Source Code Analysis:**
1. In **commands.ts**, within both the `startLanguageServer()` and `test()` functions, the code retrieves the “envFile” setting using:
   ```ts
   const denoEnvFile = config.get<string>("envFile");
   ```

2. This value is concatenated with the workspace folder’s path by calling:
   ```ts
   const denoEnvPath = path.join(workspaceFolder.uri.fsPath, denoEnvFile);
   ```
   There is no subsequent check to ensure that `denoEnvPath` remains within a safe directory.

3. The file located at `denoEnvPath` is then read and parsed with `dotenv.parse`, and its contents are merged into the environment variables that are used for launching a subprocess, which may lead to inadvertent execution of injected commands.

**Security Test Case:**
1. Prepare a repository with a `.vscode/settings.json` file that sets “envFile” to a traversal path, such as:
   ```json
   {
     "envFile": "../malicious.env"
   }
   ```

2. Place a file named `malicious.env` one directory above the workspace (or simulate its presence) containing test environment variables (for example, a variable like `MALICIOUS_FLAG=1` or a variable that modifies a runtime option).

3. Open the repository in VS Code so that the extension reads the “envFile” setting and attempts to load its contents.

4. Verify—by logging or by observing a change in the behavior of the spawned Deno language server—that the environment variables from `malicious.env` are indeed injected into the process.

5. Confirm that applying proper directory traversal prevention (or enforcing a confined file path policy) prevents the environment variable injection.

---
