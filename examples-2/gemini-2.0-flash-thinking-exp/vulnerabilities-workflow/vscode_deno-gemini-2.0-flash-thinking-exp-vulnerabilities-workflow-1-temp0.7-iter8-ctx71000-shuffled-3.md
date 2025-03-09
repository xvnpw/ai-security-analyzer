### Vulnerability List for vscode-deno Extension

* Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args`

* Description:
    A malicious repository can include a `.vscode/settings.json` file that sets the `deno.codeLens.testArgs` or `deno.testing.args` configuration options to inject arbitrary shell commands. When a victim opens this repository in VSCode with the Deno extension installed and subsequently uses the "Run Test" code lens or the Test Explorer feature, the injected commands will be executed on their machine.

    Steps to trigger the vulnerability:
    1. An attacker creates a malicious repository.
    2. Within this repository, the attacker creates a `.vscode/settings.json` file.
    3. In the `.vscode/settings.json` file, the attacker sets either `deno.codeLens.testArgs` or `deno.testing.args` to an array of strings, including a malicious command. For example:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch malicious_file.txt"
           ]
       }
       ```
    4. The attacker hosts this malicious repository publicly (e.g., on GitHub).
    5. A victim, who has the "vscode-deno" extension installed, clones or opens this malicious repository in VSCode.
    6. The victim opens a Deno test file (e.g., a file containing `Deno.test(...)`).
    7. The victim either clicks the "Run Test" code lens that appears above the test declaration or runs tests via the VSCode Test Explorer.
    8. The Deno extension executes the test command, incorporating the malicious arguments from the `.vscode/settings.json` file.
    9. The injected command, in this example `touch malicious_file.txt`, is executed on the victim's system.

* Impact:
    Remote Code Execution (RCE). Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's local system, including data theft, malware installation, and further unauthorized activities.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    No mitigations are currently implemented in the project to prevent command injection through `deno.codeLens.testArgs` and `deno.testing.args`. The extension directly reads these configuration values and uses them to construct and execute Deno CLI commands without any sanitization or validation.

* Missing Mitigations:
    - Input Sanitization: The extension should sanitize or validate the values provided in `deno.codeLens.testArgs` and `deno.testing.args` configuration settings. It should remove or escape any characters or sequences that could be used for command injection (e.g., semicolons, backticks, pipes, etc.).
    - User Warning and Confirmation: When the extension detects that `deno.codeLens.testArgs` or `deno.testing.args` are being set by workspace configuration (e.g., through `.vscode/settings.json`), it should display a warning to the user, highlighting the potential security risk. The extension could also request explicit user confirmation before executing any tasks with these potentially modified arguments.
    - Restrict Configuration Scope: Consider restricting the scope at which `deno.codeLens.testArgs` and `deno.testing.args` can be set. For instance, disallowing workspace-level settings for these security-sensitive options and only allowing user-level configuration could reduce the attack surface from malicious repositories.

* Preconditions:
    1. The victim has the "vscode-deno" extension installed and enabled in VSCode.
    2. The victim opens a workspace or folder in VSCode that contains a malicious `.vscode/settings.json` file.
    3. The malicious `.vscode/settings.json` file configures either `deno.codeLens.testArgs` or `deno.testing.args` to include injected commands.
    4. The workspace contains a Deno test file that triggers the display of the "Run Test" code lens, or the victim uses the Test Explorer to run tests.
    5. The victim interacts with the test features by clicking "Run Test" code lens or executing tests through Test Explorer.

* Source Code Analysis:
    1. `client/src/commands.ts`: The `test` function is responsible for constructing and executing Deno test commands triggered by code lens or Test Explorer.
    2. `client/src/commands.ts`: Inside the `test` function, the `deno.codeLens.testArgs` configuration is retrieved using `config.get<string[]>("codeLens.testArgs")`.
    [client/src/commands.ts#L523-L525](https://github.com/denoland/vscode_deno/blob/main/client/src/commands.ts#L523-L525)
    ```typescript
    const testArgs: string[] = [
      ...(config.get<string[]>("codeLens.testArgs") ?? []),
    ];
    ```
    3. `client/src/commands.ts`: These retrieved `testArgs` are directly incorporated into the command arguments array without any sanitization.
    [client/src/commands.ts#L543](https://github.com/denoland/vscode_deno/blob/main/client/src/commands.ts#L543)
    ```typescript
    const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
    ```
    4. `client/src/tasks.ts`: The `buildDenoTask` function is used to create a VSCode Task with `vscode.ProcessExecution`. The unsanitized `args` array is passed directly to `ProcessExecution`.
    [client/src/tasks.ts#L29](https://github.com/denoland/vscode_deno/blob/main/client/src/tasks.ts#L29)
    ```typescript
    const exec = new vscode.ProcessExecution(
      process,
      args, // Unsanitized arguments
      definition,
    );
    ```
    5. Visualization of data flow:

    ```mermaid
    graph LR
        subgraph VSCode Configuration
            A[deno.codeLens.testArgs] --> B(getConfiguration);
        end

        subgraph client/src/commands.ts - test()
            B --> C{config.get("codeLens.testArgs")};
            C --> D[testArgs Array];
            D --> E{Command Args Construction};
            E --> F[args Array];
        end

        subgraph client/src/tasks.ts - buildDenoTask()
            F --> G(ProcessExecution);
            G --> H[vscode.Task Execution];
        end

        H --> I[System Command Execution];
    ```

* Security Test Case:
    1. Create a new directory named `malicious-deno-repo`.
    2. Inside `malicious-deno-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch malicious_file.txt"
           ]
       }
       ```
    4. Inside `malicious-deno-repo`, create a file named `test_vuln.ts` with the following content:
       ```typescript
       Deno.test("command injection test", () => {
           console.log("Test running");
       });
       ```
    5. Open the `malicious-deno-repo` directory in VSCode. Ensure the Deno extension is active.
    6. Open the `test_vuln.ts` file in the editor.
    7. Observe the "▶ Run Test" code lens appearing above the `Deno.test` declaration.
    8. Click on the "▶ Run Test" code lens.
    9. After the test execution (which might succeed or fail), check the `malicious-deno-repo` directory for a new file named `malicious_file.txt`.
    10. If `malicious_file.txt` exists, it confirms that the command injection was successful, as the `touch malicious_file.txt` command was executed as part of the test execution process.
