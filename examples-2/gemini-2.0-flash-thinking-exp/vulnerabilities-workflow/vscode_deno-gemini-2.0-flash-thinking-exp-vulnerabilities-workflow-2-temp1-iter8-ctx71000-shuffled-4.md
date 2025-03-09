- Vulnerability Name: Command Injection via Deno Test Settings

- Description:
  1. An attacker can trick a user into opening a Visual Studio Code workspace containing a Deno project.
  2. The attacker persuades the user to modify the workspace settings for the Deno extension. Specifically, the attacker encourages the user to add malicious command-line arguments to either the `deno.testing.args` setting (used by the Test Explorer) or the `deno.codeLens.testArgs` setting (used by CodeLens test runner). This could be achieved through social engineering or by providing a workspace configuration file with pre-set malicious arguments.
  3. When the user subsequently executes Deno tests, either through the CodeLens "Run Test" action or via the Test Explorer, the Deno extension spawns a Deno CLI process to run the tests.
  4. The extension, without proper sanitization, directly incorporates the user-provided arguments from the `deno.testing.args` or `deno.codeLens.testArgs` settings into the command line executed by the Deno CLI.
  5. If the injected arguments contain shell commands (e.g., using command separators like `;`, `&`, or `|`), these commands will be executed by the system shell during the test execution, leading to arbitrary code execution on the user's machine with the privileges of the user running VS Code.

- Impact:
  Critical. Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on the user's machine. This could lead to complete system compromise, data theft, malware installation, or other malicious activities.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  No mitigations are currently implemented in the project to prevent command injection via these settings. The extension directly passes the provided arguments to the Deno CLI without any sanitization or validation. The default value for `deno.codeLens.testArgs` is `[ "--allow-all" ]`, which, while not a vulnerability itself, grants excessive permissions to the test execution and does not mitigate the command injection risk.

- Missing Mitigations:
  - Input sanitization: The extension should sanitize or validate the values provided in the `deno.testing.args` and `deno.codeLens.testArgs` settings to prevent the injection of arbitrary shell commands. This could involve disallowing shell command separators or any characters that could be used for command injection.
  - User warning: Display a clear warning to the user when they attempt to modify the `deno.testing.args` or `deno.codeLens.testArgs` settings, highlighting the security risks associated with providing untrusted command-line arguments.
  - Principle of least privilege: Reconsider the default `"--allow-all"` argument. If specific permissions are needed for tests, they should be explicitly configured and documented, rather than granting all permissions by default. Alternatively, remove default arguments entirely and require users to explicitly specify necessary flags, encouraging a more security-conscious configuration.

- Preconditions:
  - The user must have the "Deno for Visual Studio Code" extension installed and enabled.
  - The user must have the Deno CLI installed on their system and accessible via the configured path or environment path.
  - The attacker must be able to trick the user into:
    - Opening a workspace under the attacker's control, or
    - Persuading the user to manually modify the workspace settings and inject malicious arguments into `deno.testing.args` or `deno.codeLens.testArgs`.
  - The user must then execute Deno tests using either CodeLens or the Test Explorer for the injected commands to be executed.

- Source Code Analysis:
  1. File: `client/src/commands.ts`
  2. Function: `test`
  3. Locate the code block where test arguments are retrieved from configuration and the `deno test` command is constructed:
     ```typescript
     export function test(
       _context: vscode.ExtensionContext,
       extensionContext: DenoExtensionContext,
     ): Callback {
       return async (uriStr: string, name: string, options: TestCommandOptions) => {
         // ...
         const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
         const testArgs: string[] = [
           ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting
         ];
         // ...
         const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

         const definition: tasks.DenoTaskDefinition = {
           type: tasks.TASK_TYPE,
           command: "test",
           args, // User controlled args are passed directly here
           // ...
         };
         // ...
         const task = tasks.buildDenoTask(
           workspaceFolder,
           denoCommand,
           definition, // Task definition with vulnerable args
           `test "${name}"`,
           args,
           ["$deno-test"],
         );
         // ...
         await vscode.tasks.executeTask(task); // Task execution, leading to command injection
         // ...
       };
     }
     ```
  4. The code retrieves the `deno.codeLens.testArgs` setting using `config.get<string[]>("codeLens.testArgs")`.
  5. These retrieved arguments are then directly spread into the `args` array: `const args = ["test", ...testArgs, ...];`.
  6. The `args` array is used to define the `DenoTaskDefinition`, which is then executed using `vscode.tasks.executeTask(task)`.
  7. `vscode.tasks.executeTask` in VS Code executes commands via the system shell. Because the `testArgs` are not sanitized, a malicious user can inject shell commands into these settings, which will be executed when the test task is run.
  8. The same vulnerability exists for `deno.testing.args` which is used when running tests from the Test Explorer, although the code snippet above specifically shows `deno.codeLens.testArgs`. The logic for `deno.testing.args` will follow a similar vulnerable pattern.

- Security Test Case:
  1. Prerequisites:
     - Ensure Visual Studio Code is installed.
     - Install the "Deno for Visual Studio Code" extension.
     - Install the Deno CLI (version >= 1.13.0).
     - Create a new, empty folder for the workspace.
     - Inside the workspace folder, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("command injection test", () => {
         console.log("Test running");
       });
       ```
  2. Vulnerability Injection:
     - Open the newly created workspace folder in Visual Studio Code.
     - Go to "File" -> "Preferences" -> "Settings" (or "Code" -> "Settings" on macOS).
     - Select the "Workspace" settings tab.
     - In the settings search bar, type `deno.codeLens.testArgs`.
     - Click on "Edit in settings.json" to modify the workspace settings.
     - Add the following JSON configuration to your `.vscode/settings.json` file:
       ```json
       {
         "deno.codeLens.testArgs": [
           "--allow-all",
           "; touch /tmp/deno_pwned ;"
         ]
       }
       ```
       *Note: This payload is for Linux/macOS. For Windows, you could use `; New-Item -ItemType file /tmp/deno_pwned.txt ;` but file creation in `/tmp` might be restricted. A safer test on Windows might involve creating a file in the user's temp directory.*
     - Save the `settings.json` file.
  3. Triggering the Vulnerability:
     - Open the `test.ts` file in the editor.
     - Observe the "Run Test" CodeLens appearing above the `Deno.test` definition.
     - Click on the "Run Test" CodeLens.
  4. Verification of Exploitation:
     - Open a terminal in your system.
     - Check if the file `/tmp/deno_pwned` has been created by running the command: `ls /tmp/deno_pwned` (or the equivalent command for your chosen payload and OS).
     - If the file `/tmp/deno_pwned` exists, it confirms that the injected command `touch /tmp/deno_pwned` was executed as part of the `deno test` command, demonstrating successful command injection.
     - Additionally, observe the "Output" panel in VS Code (if it's shown by the test execution). You should see the output of the `deno test` command, and potentially any output or errors from your injected malicious command, although `touch` is silent on success.
