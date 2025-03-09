## Vulnerability List

- Vulnerability Name: Command Injection in `deno.codeLens.testArgs`

- Description:
    An attacker can inject arbitrary commands into the `deno test` command line by manipulating the `deno.codeLens.testArgs` setting within the workspace's `.vscode/settings.json` file. When a victim opens a malicious repository containing such a manipulated settings file and subsequently attempts to run a test using the CodeLens feature, the injected commands will be executed on their machine.

    Steps to trigger the vulnerability:
    1. An attacker creates a malicious repository.
    2. The attacker adds a `.vscode/settings.json` file to the repository.
    3. Within this `settings.json` file, the attacker sets the `deno.codeLens.testArgs` configuration to include malicious commands. For example:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch malicious_file; #"
           ]
       }
       ```
    4. The attacker hosts this malicious repository and lures a victim to open it in VSCode with the Deno extension installed and enabled.
    5. The victim opens a Deno project file (e.g., a test file) in the opened malicious repository.
    6. The victim uses the "Run Test" CodeLens displayed above a test definition to execute the test.
    7. Upon test execution, the injected command from `deno.codeLens.testArgs` setting is executed.

- Impact:
    Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to complete system compromise, data theft, or further malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    None. The extension directly uses the values from the `deno.codeLens.testArgs` setting without any sanitization or validation.

- Missing Mitigations:
    Input validation and sanitization for the `deno.codeLens.testArgs` setting are missing. The extension should validate and sanitize the arguments provided in this setting to prevent command injection. Ideally, only expected arguments should be allowed, and any potentially harmful characters or command separators should be removed or escaped.

- Preconditions:
    1. The victim has the VSCode Deno extension installed and enabled.
    2. The victim opens a malicious repository in VSCode.
    3. The malicious repository contains a `.vscode/settings.json` file with a manipulated `deno.codeLens.testArgs` setting.
    4. The victim attempts to run a Deno test using the CodeLens "Run Test" action within the malicious repository.

- Source Code Analysis:
    1. **`client\src\commands.ts`**: The `test` function is responsible for handling the execution of tests triggered by CodeLens.
    2. Inside the `test` function, the `testArgs` array is constructed by retrieving the `deno.codeLens.testArgs` setting directly from the workspace configuration:
       ```typescript
       const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
       const testArgs: string[] = [
           ...(config.get<string[]>("codeLens.testArgs") ?? []),
       ];
       ```
    3. This `testArgs` array, which now potentially contains attacker-injected commands, is passed directly to the `buildDenoTask` function.
    4. **`client\src\tasks.ts`**: The `buildDenoTask` function creates a `vscode.Task` using `vscode.ProcessExecution`. The `args` array, which includes the potentially malicious `testArgs`, is directly passed to `ProcessExecution` without any further validation or sanitization:
       ```typescript
       const exec = new vscode.ProcessExecution(
           process,
           args, // args array contains unsanitized user input from settings
           definition,
       );
       ```
    5. `vscode.ProcessExecution` then executes the Deno command with the provided arguments, leading to the execution of injected commands.

- Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("Vulnerable Test", () => {
           console.log("Test is running");
       });
       ```
    3. Inside `malicious-repo`, create a directory named `.vscode`.
    4. Inside `.vscode`, create a file named `settings.json` with the following content to inject a command to create a file named `pwned.txt`:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch pwned.txt; #"
           ]
       }
       ```
    5. Open the `malicious-repo` directory in VSCode with the Deno extension enabled.
    6. Open the `test.ts` file.
    7. Locate the "▶ Run Test" CodeLens above the `Deno.test` definition and click it.
    8. After the test execution completes, check the `malicious-repo` directory.
    9. Verify that a new file named `pwned.txt` has been created in the `malicious-repo` directory. This confirms that the command injection was successful and arbitrary commands could be executed.
