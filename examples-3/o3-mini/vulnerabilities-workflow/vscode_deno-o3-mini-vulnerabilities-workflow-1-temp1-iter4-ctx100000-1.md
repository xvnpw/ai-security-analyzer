# Vulnerability List

## Arbitrary Executable Path Injection via Workspace Settings (“deno.path”)

- **Description:**
  The extension looks up its configuration in the workspace settings without validating the source of critical execution parameters. In particular, the “deno.path” setting is read from the workspace configuration (using `workspace.getConfiguration(EXTENSION_NS).get("path")` in the utility module) and later directly passed to spawn the Deno language server (in the `startLanguageServer` command). An attacker who supplies a malicious repository can commit a customized `.vscode/settings.json` file with the following properties:
  1. Enable the Deno extension (e.g., by setting `"deno.enable": true`).
  2. Override the “deno.path” setting with a path to an attacker‑controlled executable (e.g., `"deno.path": "/path/to/malicious_executable"`).

  When a victim opens such a repository, the extension’s startup sequence (via `startLanguageServer`) will call `getDenoCommandPath()` which returns the attacker‑supplied executable path without additional validation. As a result, the extension spawns this executable—in effect allowing the attacker to run arbitrary code on the victim’s machine.

- **Impact:**
  An attacker can achieve remote code execution (RCE) on the victim’s system by getting the extension to run an arbitrary executable. This could lead to compromise of the user’s environment, data theft, or further lateral movement.

- **Vulnerability Rank:**
  Critical

- **Currently Implemented Mitigations:**
  There are no safeguards in the code against using a workspace‑supplied “deno.path”. The extension simply retrieves the value from the configuration and passes it into the process‑spawning API.

- **Missing Mitigations:**
  - Input validation or sanitization on the “deno.path” setting should be performed (for example, ensuring that the path points only to known trusted binaries or checking that it is an absolute path that the user has explicitly approved).
  - Alternatively, a prompt or confirmation step should be introduced before using workspace‑provided sensitive settings.

- **Preconditions:**
  - The victim opens a repository that contains a malicious `.vscode/settings.json` file with `"deno.enable": true` and a manipulated `"deno.path"` value pointing to an attacker-controlled executable.
  - The attacker must have prepared an executable (or shim) on the victim’s computer at the specified location (or arranged for the victim to acquire one) so that when the extension spawns it, malicious code is run.

- **Source Code Analysis:**
  1. In **client/src/util.ts**, the function `getDenoCommandPath()` reads the “deno.path” configuration via:
     ```javascript
     const command = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
     ```
     There is no filtering or verification on the returned value.
  2. In **client/src/commands.ts** (within the `startLanguageServer` function), the extension calls `await getDenoCommandPath()` and then uses the returned value as the executable path in the `LanguageClient`’s server options.
  3. Since no additional checks are made on the path, a malicious workspace configuration can force the extension to spawn an executable chosen by the attacker.

- **Security Test Case:**
  1. **Setup a Malicious Repository:**
     Create a sample repository that includes a `.vscode/settings.json` file with at least the following content:
     ```json
     {
       "deno.enable": true,
       "deno.path": "/path/to/malicious_executable"
     }
     ```
  2. **Prepare the Malicious Executable:**
     Place a simple script (e.g., one that writes a file, logs a message, or otherwise indicates execution) at `/path/to/malicious_executable` on the test system.
  3. **Open the Repository in VS Code:**
     Launch Visual Studio Code and open the malicious repository.
  4. **Observe the Extension Activation:**
     The extension’s startup routine will invoke `getDenoCommandPath()`, retrieve the malicious “deno.path”, and then spawn the executable via `startLanguageServer`.
  5. **Verify Malicious Behavior:**
     Confirm that the malicious executable is indeed executed (for example, by checking for the file created or the log/message produced) and that arbitrary commands supplied by the attacker are run.
  6. **Cleanup and Remediation Verification:**
     After verifying, remove the malicious settings and executable, then test that a proper executable path is used or that a user confirmation is now required if mitigation is implemented.
