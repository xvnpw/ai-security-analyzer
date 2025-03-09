### Vulnerability List

- Vulnerability Name: Command Injection via `deno.path` setting
- Description:
    1. A user can configure the `deno.path` setting in VS Code to specify the path to the Deno executable.
    2. This setting is intended to allow users to point the extension to a specific Deno CLI installation if it's not in the environment path or if they want to use a specific version.
    3. However, the extension does not validate or sanitize the `deno.path` setting.
    4. A malicious actor can trick a user into setting `deno.path` to a path that includes malicious commands. For example, a user might be convinced to set `deno.path` to `/path/to/malicious.sh`, where `malicious.sh` is a script containing harmful commands like `#!/bin/bash\n rm -rf /`.
    5. When the extension starts the Deno language server or executes any Deno CLI command (e.g., via tasks or testing code lenses), it uses the `deno.path` setting to determine the executable to run.
    6. If `deno.path` is set to a malicious script, the extension will execute this script instead of the legitimate Deno CLI, leading to command injection.
- Impact:
    - Arbitrary command execution on the user's system with the privileges of the VS Code process.
    - This can lead to various malicious activities, including data theft, system compromise, installation of malware, or denial of service.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - None. The extension directly uses the `deno.path` setting without any validation or sanitization.
- Missing mitigations:
    - Input validation and sanitization of the `deno.path` setting.
    - Restricting execution to only the legitimate Deno CLI executable.
    - Ideally, verifying the executable against a known good hash or signature, though this might be complex. A simpler approach would be to ensure the path points to an actual deno executable and not a script.
- Preconditions:
    - The user must have the VS Code Deno extension installed and enabled.
    - The user must be tricked into setting the `deno.path` setting to a malicious path. This could be achieved through social engineering, by convincing the user that it's necessary for some feature, or by a workspace configuration that overrides user settings if the user opens a malicious workspace.
- Source code analysis:
    1. File: `client/src/util.ts`
    2. Function: `getDenoCommandPath()` is responsible for resolving the Deno command path.
    3. The function retrieves the path from VS Code settings using `getWorkspaceConfigDenoExePath()`.
    4. If `deno.path` is set, the function returns it directly without any validation:
       ```typescript
       function getWorkspaceConfigDenoExePath() {
         const exePath = workspace.getConfiguration(EXTENSION_NS)
           .get<string>("path");
         // it is possible for the path to be blank. In that case, return undefined
         if (typeof exePath === "string" && exePath.trim().length === 0) {
           return undefined;
         } else {
           return exePath; // Directly returns user-provided path
         }
       }
       ```
    5. File: `client/src/commands.ts`
    6. Function: `startLanguageServer()` uses the path returned by `getDenoCommandPath()` to start the language server.
    7. The `command` variable from `getDenoCommandPath()` is directly passed to `serverOptions.run.command` and `serverOptions.debug.command`:
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
    8. The `LanguageClient` uses `child_process.spawn` (or similar) under the hood to execute the command. This directly executes whatever is specified in the `command` variable, leading to command injection if a malicious path is provided in `deno.path` setting.

- Security test case:
    1. Create a malicious script, for example `malicious.sh` with the following content:
       ```bash
       #!/bin/bash
       echo "Malicious script executed!"
       touch /tmp/pwned_by_deno_extension # Indicator of successful command injection
       /usr/bin/deno "$@" # Optionally forward arguments to the real deno, if deno is in /usr/bin/deno and you want the extension to function somewhat normally for testing.
       ```
       Make sure to make it executable: `chmod +x malicious.sh`
    2. In VS Code, open settings (Ctrl+,).
    3. Search for "deno.path".
    4. Set the `Deno › Path` setting to the absolute path of the malicious script, e.g., `/path/to/malicious.sh`.
    5. Reload VS Code or restart the Deno language server by executing command "Deno: Restart Language Server".
    6. Observe the output. You should see "Malicious script executed!" in the output, and the file `/tmp/pwned_by_deno_extension` should be created.
    7. To further confirm, try running any Deno command through the extension, such as "Deno: Cache" or running a test code lens. The malicious script will be executed every time the extension tries to invoke the Deno CLI.
