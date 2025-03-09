### Vulnerability List:

* Vulnerability Name: Command Injection via Deno Test Arguments (`deno.codeLens.testArgs` / `deno.testing.args`)
    * Description:
        1. A threat actor crafts a malicious repository.
        2. The malicious repository includes a `.vscode/settings.json` file.
        3. In the `.vscode/settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` setting to include command injection payload, for example: `["--allow-all", "; touch injected.txt"]`.
        4. A victim clones and opens this malicious repository in VSCode with the Deno extension enabled.
        5. The victim opens a test file (e.g., `test.ts`) within the repository.
        6. The Deno extension displays a "▶ Run Test" code lens above the test definition.
        7. The victim clicks on the "▶ Run Test" code lens.
        8. The Deno extension executes the `deno test` command.
        9. Due to the injected payload in `deno.codeLens.testArgs`, arbitrary commands are executed on the victim's system.

    * Impact: Arbitrary code execution on the victim's machine with the privileges of the VSCode process. This can lead to data theft, installation of malware, or complete system compromise.
    * Vulnerability Rank: high
    * Currently Implemented Mitigations: None. The extension directly uses the values from `deno.codeLens.testArgs` setting without any sanitization or validation when constructing the `deno test` command.
    * Missing Mitigations: Implement input sanitization or validation for the `deno.codeLens.testArgs` and `deno.testing.args` settings. Ensure that no shell metacharacters or command separators can be injected into the command line arguments. Consider using parameterized commands or escaping arguments properly before passing them to the shell.
    * Preconditions:
        1. The victim has the VSCode Deno extension installed and enabled.
        2. The victim opens a malicious repository in VSCode.
        3. The malicious repository contains a `.vscode/settings.json` file with a command injection payload in the `deno.codeLens.testArgs` or `deno.testing.args` setting.
        4. The victim interacts with the "Run Test" code lens in a test file within the malicious repository.

    * Source Code Analysis:
        1. `client\src\commands.ts`: In the `test` function, the extension retrieves the `deno.codeLens.testArgs` configuration:
        ```typescript
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []),
        ];
        ```
        2. It then constructs the `deno test` command arguments by directly including `testArgs`:
        ```typescript
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        ```
        3. The `args` are passed to `buildDenoTask` function in `client\src\tasks.ts`:
        ```typescript
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args,
          env,
        };
        const task = tasks.buildDenoTask(workspaceFolder, denoCommand, definition, `test "${name}"`, args, ["$deno-test"]);
        ```
        4. In `client\src\tasks.ts`, the `buildDenoTask` function creates a `ProcessExecution` with the unsanitized `args`:
        ```typescript
        export function buildDenoTask( ... , definition: DenoTaskDefinition, ...): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process,
            args, // Unsanitized arguments from settings
            definition,
          );
          return new vscode.Task( ..., exec, ...);
        }
        ```
        5. Finally, `vscode.tasks.executeTask(task)` is called, executing the command with the injected arguments.

    * Security Test Case:
        1. Create a new folder named `vscode_deno_test_vuln`.
        2. Inside `vscode_deno_test_vuln`, create a folder `.vscode`.
        3. Inside `.vscode`, create a file `settings.json` with the following content:
        ```json
        {
            "deno.enable": true,
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; touch command_injection_test_args.txt"
            ]
        }
        ```
        4. Inside `vscode_deno_test_vuln`, create a file `test_file.ts` with the following content:
        ```typescript
        Deno.test("testExample", () => {
          console.log("Running testExample");
        });
        ```
        5. Open the `vscode_deno_test_vuln` folder in VSCode. Ensure the Deno extension is enabled for this workspace.
        6. Open `test_file.ts`.
        7. Observe the "▶ Run Test" code lens above `Deno.test`. Click on "▶ Run Test".
        8. After the test execution completes, verify if a file named `command_injection_test_args.txt` has been created in the `vscode_deno_test_vuln` folder. The presence of this file indicates successful command injection.

* Vulnerability Name: Command Injection via Deno Unstable Features (`deno.unstable`)
    * Description:
        1. A threat actor prepares a malicious repository.
        2. The repository includes a `.vscode/settings.json` file.
        3. In `.vscode/settings.json`, the `deno.unstable` setting is configured with a command injection payload as an "unstable feature", such as: `["sloppy-imports", " ; touch injected_upgrade.txt"]`.
        4. A victim clones and opens the malicious repository in VSCode with the Deno extension enabled.
        5. The victim may trigger an upgrade process, either manually by using the "Deno: Upgrade" command (if available) or automatically when prompted by the extension for an upgrade.
        6. The Deno extension constructs and executes the `deno upgrade` command.
        7. Due to the injected payload within the `deno.unstable` setting, arbitrary commands are executed on the victim's system during the upgrade process.

    * Impact: Arbitrary code execution on the victim's machine with the privileges of the VSCode process. This can lead to malware installation, data exfiltration, or complete system takeover.
    * Vulnerability Rank: high
    * Currently Implemented Mitigations: None. The extension directly iterates through the `deno.unstable` array and constructs command-line flags without any sanitization.
    * Missing Mitigations: Sanitize or validate the `deno.unstable` setting. Ensure that the "unstable features" are treated as literal feature names and not as injectable command parts. Prevent interpretation of shell metacharacters or command separators within these settings.
    * Preconditions:
        1. The victim has the VSCode Deno extension installed and activated.
        2. The victim opens a malicious repository in VSCode.
        3. The repository includes a `.vscode/settings.json` with a command injection payload within the `deno.unstable` array.
        4. The victim triggers the "Deno Upgrade" functionality, which can be initiated manually or through extension prompts.

    * Source Code Analysis:
        1. `client\src\commands.ts`: In the `test` function, the extension retrieves the `deno.unstable` configuration:
        ```typescript
        const unstable = config.get("unstable") as string[] ?? [];
        for (const unstableFeature of unstable) {
          const flag = `--unstable-${unstableFeature}`;
          if (!testArgs.includes(flag)) {
            testArgs.push(flag);
          }
        }
        ```
        2. `client\src\upgrade.ts`: In `denoUpgradePromptAndExecute` function, similar logic applies for the `deno upgrade` command:
        ```typescript
        const args = ["upgrade"];
        const unstable = config.get("unstable") as string[] ?? [];
        for (const unstableFeature of unstable) {
          args.push(`--unstable-${unstableFeature}`);
        }
        ```
        3. In both cases, the `unstableFeature` from the `deno.unstable` setting is directly used to construct the command flag `--unstable-${unstableFeature}` without sanitization.
        4. The constructed `args` array, containing potentially malicious flags, is then used in `buildDenoTask` (as described in Vulnerability 1) and executed via `vscode.tasks.executeTask`.

    * Security Test Case:
        1. Create a new folder named `vscode_deno_upgrade_vuln`.
        2. Inside `vscode_deno_upgrade_vuln`, create a folder `.vscode`.
        3. Inside `.vscode`, create a file `settings.json` with the following content:
        ```json
        {
            "deno.enable": true,
            "deno.unstable": [
                "sloppy-imports",
                " ; touch command_injection_unstable.txt"
            ]
        }
        ```
        4. Open the `vscode_deno_upgrade_vuln` folder in VSCode. Ensure Deno extension is enabled.
        5. To reliably trigger the "Deno Upgrade", you might need to either:
            a.  Manually execute the "Deno: Upgrade" command if it is exposed in the command palette.
            b.  Simulate an upgrade scenario where the extension would prompt for an upgrade (this might require more setup or modification of the extension's environment).
            c.  Temporarily modify the extension code (e.g., in `client\src\extension.ts` or `client\src\commands.ts`) to directly call `denoUpgradePromptAndExecute` to force the upgrade process.
        6. After triggering the upgrade process and it completes (or fails), check for the file named `command_injection_unstable.txt` in the `vscode_deno_upgrade_vuln` folder. If this file exists, it confirms command injection vulnerability via the `deno.unstable` setting.
