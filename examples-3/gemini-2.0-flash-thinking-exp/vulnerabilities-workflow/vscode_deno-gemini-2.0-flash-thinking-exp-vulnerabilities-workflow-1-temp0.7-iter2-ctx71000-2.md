### Vulnerability List

* Vulnerability Name: Command Injection via `deno.path` setting
* Description:
    1. A threat actor crafts a malicious repository containing a `.vscode/settings.json` file.
    2. Within this `settings.json`, the threat actor sets the `deno.path` configuration to a malicious executable path. For example: `"deno.path": "/path/to/malicious.sh"` or on Windows `"deno.path": "C:\\path\\to\\malicious.bat"`. This malicious "deno" executable could be a script or binary designed to execute arbitrary commands.
    3. The victim opens this malicious repository in VSCode with the Deno extension installed and enabled.
    4. The Deno extension attempts to locate and execute the Deno CLI using the path specified in `deno.path` setting.
    5. Instead of executing the legitimate Deno CLI, the extension executes the malicious script or binary provided by the attacker.
    6. The malicious executable then executes arbitrary commands on the victim's machine under the context of the VSCode process.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine, potentially leading to data theft, malware installation, or complete system compromise.
* Vulnerability Rank: Critical
* Currently implemented mitigations: None. The extension relies on the user-provided path without proper validation.
* Missing mitigations:
    * Input validation and sanitization for the `deno.path` setting. The extension should verify that the provided path points to a valid Deno executable and does not contain malicious commands or path traversal sequences.
    * Consider restricting the allowed characters in the `deno.path` setting to only alphanumeric characters, path separators, and specific allowed symbols.
    * Implement checks to ensure the executable is actually a Deno binary and not a script or other malicious file.
* Preconditions:
    * The victim has the VSCode Deno extension installed and enabled.
    * The victim opens a malicious repository containing a crafted `.vscode/settings.json` or the user has globally set a malicious `deno.path` in their VSCode settings.
* Source code analysis:
    1. File: `client/src/util.ts`
    2. Function: `getDenoCommandPath()`
    3. This function retrieves the `deno.path` setting from VSCode configuration using `workspace.getConfiguration(EXTENSION_NS).get<string>("path")`.
    ```typescript
    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS)
        .get<string>("path");
      // it is possible for the path to be blank. In that case, return undefined
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath;
      }
    }
    ```
    4. The `getDenoCommandPath` function then returns this user-provided path without any validation or sanitization.
    ```typescript
    export async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath();
      // ...
      return command ?? await getDefaultDenoCommand();
    }
    ```
    5. This path is then used in `client/src/commands.ts` in `startLanguageServer` function to spawn the Deno language server process:
    ```typescript
    const serverOptions: ServerOptions = {
      run: {
        command, // user-provided path
        args: ["lsp"],
        options: { env },
      },
      debug: {
        command, // user-provided path
        args: ["lsp"],
        options: { env },
      },
    };
    const client = new LanguageClient( ... serverOptions, ... );
    await client.start();
    ```
    6. The `command` variable, which is the user-controlled `deno.path`, is directly used as the executable command in `child_process.spawn` (implicitly used by `LanguageClient`). This allows for command injection if the user provides a malicious path.

* Security test case:
    1. Create a new directory named `vscode_deno_test_repo`.
    2. Inside `vscode_deno_test_repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content.
        * On Linux/macOS:
        ```json
        {
          "deno.path": "./malicious.sh"
        }
        ```
        * On Windows:
        ```json
        {
          "deno.path": ".\\malicious.bat"
        }
        ```
    4. Inside `vscode_deno_test_repo`, create a malicious executable file:
        * On Linux/macOS, create a file named `malicious.sh` with the following content and make it executable using `chmod +x malicious.sh`:
        ```bash
        #!/bin/bash
        echo "Vulnerable to Command Injection!" > output.txt
        echo "Malicious script executed with arguments: $*" >> output.txt
        whoami >> output.txt
        ```
        * On Windows, create a file named `malicious.bat` with the following content:
        ```bat
        @echo off
        echo Vulnerable to Command Injection! > output.txt
        echo Malicious script executed with arguments: %* >> output.txt
        whoami >> output.txt
        ```
    5. Open the `vscode_deno_test_repo` directory in VSCode.
    6. Ensure the Deno extension is enabled for this workspace (you might be prompted to enable it, or you can manually enable it via the command palette or settings).
    7. Trigger any Deno extension feature that starts the language server. For example, open a TypeScript or JavaScript file in the workspace.
    8. After a short delay, check the `vscode_deno_test_repo` directory for a file named `output.txt`.
    9. If the vulnerability is present, `output.txt` will be created and contain the output from the malicious script, including "Vulnerable to Command Injection!", the arguments passed to the script, and the output of the `whoami` command. This confirms that the malicious script specified in `deno.path` was executed by the extension.

* Vulnerability Name: Command Injection via Test Arguments Settings (`deno.codeLens.testArgs`, `deno.testing.args`)
* Description:
    1. A threat actor crafts a malicious repository containing a `.vscode/settings.json` file.
    2. Within this `settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` configuration to include malicious command arguments. For example: `"deno.codeLens.testArgs": ["--allow-read", "--allow-write", "--", "; touch injected.txt"]`.
    3. The victim opens this malicious repository in VSCode with the Deno extension installed and enabled.
    4. The victim executes a Deno test, either via code lens "Run Test" action or through the VSCode testing explorer.
    5. The Deno extension constructs the `deno test` command, incorporating the attacker-controlled arguments from `deno.codeLens.testArgs` or `deno.testing.args` settings without sufficient sanitization.
    6. When the `deno test` command is executed, the injected malicious arguments are passed to the Deno CLI, leading to command injection. In the example above, `; touch injected.txt` will be appended and executed as a separate command after the `deno test` command.
* Impact: Remote Code Execution (RCE). An attacker can inject arbitrary commands that are executed when Deno tests are run, potentially leading to data theft, malware installation, or system compromise.
* Vulnerability Rank: High
* Currently implemented mitigations: None. The extension directly passes the arguments to the Deno CLI without validation.
* Missing mitigations:
    * Input validation and sanitization for the `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension should validate that the arguments are safe and do not contain command injection sequences.
    * Consider using a safer method to pass arguments to the Deno CLI, such as programmatically constructing the arguments instead of directly concatenating strings.
    * Warn users about the security risks of modifying these settings, especially when opening untrusted workspaces.
* Preconditions:
    * The victim has the VSCode Deno extension installed and enabled.
    * The victim opens a malicious repository containing a crafted `.vscode/settings.json` or the user has globally set malicious test arguments in their VSCode settings.
    * The victim executes Deno tests using the code lens or test explorer feature.
* Source code analysis:
    1. File: `client/src/commands.ts`
    2. Function: `test()`
    3. This function retrieves `deno.codeLens.testArgs` from VSCode configuration:
    ```typescript
    const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
    const testArgs: string[] = [
      ...(config.get<string[]>("codeLens.testArgs") ?? []),
    ];
    ```
    4. These `testArgs` are directly incorporated into the command line arguments for `deno test`:
    ```typescript
    const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
    const definition: tasks.DenoTaskDefinition = {
      type: tasks.TASK_TYPE,
      command: "test",
      args, // testArgs are included here
      env,
    };
    // ... task execution ...
    ```
    5. The `args` array, including user-controlled `testArgs`, is passed to `ProcessExecution` which will execute the command. No sanitization or validation is performed on `testArgs` before execution.

* Security test case:
    1. Create a new directory named `vscode_deno_test_repo_testargs`.
    2. Inside `vscode_deno_test_repo_testargs`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
        ```json
        {
          "deno.codeLens.testArgs": ["; touch injected_testargs.txt"]
        }
        ```
    4. Inside `vscode_deno_test_repo_testargs`, create a file named `test.ts` with a simple Deno test:
        ```typescript
        import { assertEquals } from "https://deno.land/std/assert/mod.ts";

        Deno.test("simple test", () => {
          assertEquals(1, 1);
        });
        ```
    5. Open the `vscode_deno_test_repo_testargs` directory in VSCode.
    6. Ensure the Deno extension is enabled.
    7. Open the `test.ts` file. You should see the "▶ Run Test" code lens above the `Deno.test` declaration.
    8. Click on the "▶ Run Test" code lens to execute the test.
    9. After the test execution completes, check the `vscode_deno_test_repo_testargs` directory for a file named `injected_testargs.txt`.
    10. If the vulnerability is present, `injected_testargs.txt` will be created, indicating that the command injection in `deno.codeLens.testArgs` was successful and arbitrary commands were executed during test execution.

* Vulnerability Name: Command Injection via Tasks Definitions (`tasks.json`, `deno.json(c)`)
* Description:
    1. A threat actor crafts a malicious repository containing a `.vscode/tasks.json` or `deno.json(c)` file.
    2. Within these configuration files, the threat actor defines a task with malicious commands in the `command` and/or `args` properties of a `DenoTaskDefinition`. For example, in `tasks.json`:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": ["`; touch injected_task.txt`"]
            }
          ]
        }
        ```
    3. The victim opens this malicious repository in VSCode with the Deno extension installed and enabled.
    4. The Deno extension parses the `tasks.json` or `deno.json(c)` file and registers the defined tasks in the VSCode task system.
    5. The victim manually executes the malicious task from the VSCode Tasks: Run Task... menu or the Deno Tasks sidebar.
    6. The Deno extension executes the defined task, directly using the attacker-provided `command` and `args` without proper sanitization.
    7. The injected commands within `command` or `args` are executed by the shell during task execution, leading to command injection. In the example above, `; touch injected_task.txt` will be executed as a separate command.
* Impact: Remote Code Execution (RCE). An attacker can define malicious tasks that execute arbitrary commands when run by the victim, potentially leading to data theft, malware installation, or system compromise.
* Vulnerability Rank: High
* Currently implemented mitigations: None. The extension relies on task definitions from workspace files without validation or sandboxing.
* Missing mitigations:
    * Input validation and sanitization for task definitions in `tasks.json` and `deno.json(c)`. The extension should validate `command` and `args` properties to prevent command injection.
    * Consider providing a warning to users when tasks from workspace files are detected, especially in untrusted workspaces, highlighting the potential security risks of executing arbitrary tasks.
    * Explore sandboxing or safer execution mechanisms for tasks to limit the impact of command injection vulnerabilities.
* Preconditions:
    * The victim has the VSCode Deno extension installed and enabled.
    * The victim opens a malicious repository containing a crafted `.vscode/tasks.json` or `deno.json(c)` file with malicious task definitions.
    * The victim manually executes the malicious task from the VSCode task menu or sidebar.
* Source code analysis:
    1. File: `client/src/tasks.ts` and `client/src/tasks_sidebar.ts`
    2. Functions: `buildDenoTask()` in `tasks.ts`,  `DenoTaskProvider.provideTasks()` and `DenoTasksTreeDataProvider` in `tasks_sidebar.ts`.
    3. The `DenoTaskProvider` reads task definitions and creates `vscode.Task` objects using `buildDenoTask()`.
    4. `buildDenoTask()` directly uses the `command` and `args` from `DenoTaskDefinition` to create a `ProcessExecution`:
    ```typescript
    export function buildDenoTask(
      // ...
      definition: DenoTaskDefinition,
      // ...
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process, // deno command path
        args,    // user-provided args from task definition
        definition,
      );

      return new vscode.Task( ... , exec, ... );
    }
    ```
    5. The `ProcessExecution` will execute the `process` with the provided `args`. If a malicious `tasks.json` or `deno.json(c)` is provided, the `args` will contain attacker-controlled commands, leading to command injection.

* Security test case:
    1. Create a new directory named `vscode_deno_test_repo_tasks`.
    2. Inside `vscode_deno_test_repo_tasks`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `tasks.json` with the following content:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": ["; touch injected_task.txt"],
              "label": "Malicious Task"
            }
          ]
        }
        ```
    4. Open the `vscode_deno_test_repo_tasks` directory in VSCode.
    5. Ensure the Deno extension is enabled.
    6. Open the VSCode command palette (Ctrl+Shift+P or Cmd+Shift+P) and type "Tasks: Run Task". Select "Tasks: Run Task".
    7. From the task list, select "deno: Malicious Task".
    8. After the task execution completes, check the `vscode_deno_test_repo_tasks` directory for a file named `injected_task.txt`.
    9. If the vulnerability is present, `injected_task.txt` will be created, indicating that the command injection in the task definition was successful and arbitrary commands were executed when the task was run.
