### Vulnerability List

- Vulnerability Name: Command Injection in Test Code Lens and Test Task Arguments
- Description:
    1. The VSCode Deno extension allows users to configure arguments for the `deno test` command through the `deno.codeLens.testArgs` and `deno.testing.args` settings.
    2. These settings are directly used to construct the command line arguments for the `deno test` command executed by the extension when running tests via code lens or tasks.
    3. A malicious user can craft a repository with a `.vscode/settings.json` file that sets `deno.codeLens.testArgs` or `deno.testing.args` to include malicious commands.
    4. When a victim opens this malicious repository in VSCode with the Deno extension enabled and attempts to run tests using the "Run Test" code lens or via tasks, the malicious commands injected through `deno.codeLens.testArgs` or `deno.testing.args` will be executed by the system.
- Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine by injecting malicious commands into the `deno.codeLens.testArgs` or `deno.testing.args` settings.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    None. The code directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` without any sanitization or validation.
- Missing Mitigations:
    Input sanitization or validation for `deno.codeLens.testArgs` and `deno.testing.args`. The extension should either:
        - Sanitize the arguments to remove or escape shell-sensitive characters.
        - Warn users about the security risks of modifying these settings, especially when opening repositories from untrusted sources.
        - Ideally, avoid directly passing user-provided strings as command line arguments to shell commands. Consider using an array format for arguments and let `vscode.ProcessExecution` handle argument escaping.
- Preconditions:
    1. Victim has VSCode installed with the "Deno for VSCode" extension enabled.
    2. Victim opens a malicious repository that includes a `.vscode/settings.json` file with malicious commands in `deno.codeLens.testArgs` or `deno.testing.args`.
    3. Victim attempts to run tests using the "Run Test" code lens or via tasks.
- Source Code Analysis:
    1. `client/src/commands.ts`:
        - In the `test` function, configuration values for `deno.codeLens.testArgs` are retrieved:
          ```typescript
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []),
          ];
          ```
        - These `testArgs` are directly used in constructing the `args` array passed to `buildDenoTask`.
    2. `client/src/tasks.ts`:
        - In `buildDenoTask` function, `vscode.ProcessExecution` is used with user-controlled arguments:
          ```typescript
          const exec = new vscode.ProcessExecution(
            process,
            args,
            definition,
          );
          ```
- Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a file named `.vscode/settings.json` with the following content:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-read",
               "--allow-write",
               "--allow-net",
               "--allow-run",
               "--allow-env",
               "--allow-hrtime",
               "--allow-ffi",
               "--unstable",
               "; touch /tmp/pwned ; #"
           ]
       }
       ```
       (This command injection attempts to create a file `/tmp/pwned` on Linux/macOS. For Windows, a similar command like `cmd /c type nul > %TEMP%\pwned.txt` could be used.)
    3. Inside `malicious-repo`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("vulnerable test", () => {
         console.log("Running test");
       });
       ```
    4. Open VSCode and open the `malicious-repo` directory. Ensure the Deno extension is enabled for this workspace.
    5. Open `test.ts`. You should see the "Run Test" code lens above `Deno.test`.
    6. Click on "Run Test".
    7. After the test execution finishes, check if the file `/tmp/pwned` (or `%TEMP%\pwned.txt` on Windows) was created. If it was, the command injection is successful.
