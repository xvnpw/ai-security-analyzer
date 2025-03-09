## Combined Vulnerability List

This document consolidates vulnerabilities identified in the VSCode Deno extension from multiple lists, removing duplicates and providing comprehensive descriptions for each unique vulnerability.

### 1. Command Injection via `deno.path` Setting

- **Description:**
    1. A threat actor creates a malicious repository designed to exploit the VSCode Deno extension.
    2. Within this repository, the attacker includes a `.vscode/settings.json` file.
    3. In the `settings.json` file, the `deno.path` setting is maliciously configured to point to an attacker-controlled executable path that includes injected commands. For example, `"deno.path": "/path/to/malicious_script with injected command"`.
    4. A victim, unaware of the threat, clones or opens this malicious repository in VSCode with the Deno extension enabled.
    5. When the Deno extension activates for this workspace or attempts to utilize the Deno CLI for features like Language Server Protocol (LSP) initialization, testing, tasks, or upgrades, it reads the `deno.path` setting from `.vscode/settings.json`.
    6. The `getDenoCommandPath` function in `client/src/util.ts` is used to retrieve this configured path.
    7. Subsequently, the extension attempts to start the Deno Language Server or execute other Deno commands using the path specified in `deno.path` as the command.
    8. Due to the lack of sanitization or validation of the `deno.path` setting, the malicious command embedded within the path is executed by the system shell instead of a legitimate Deno executable. This occurs because `vscode.ProcessExecution` interprets the provided path as a command string, allowing shell injection.

- **Impact:** **Remote Code Execution (RCE)**. Successful exploitation grants the attacker the ability to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can result in a wide range of malicious activities, including:
    - Data exfiltration and theft of sensitive information.
    - Installation of malware, ransomware, or other malicious software.
    - Complete system compromise, allowing the attacker to control the victim's machine for further attacks or botnet participation.

- **Vulnerability Rank:** **Critical**

- **Currently implemented mitigations:**
    - None. The extension directly retrieves and utilizes the value of the `deno.path` setting without any form of sanitization, validation, or security checks before spawning a process.
    - The `getDenoCommandPath` function in `client/src/util.ts` only performs a rudimentary check for file existence but does not validate the content of the path or sanitize the command string for shell metacharacters.

- **Missing mitigations:**
    - **Input sanitization for `deno.path` setting**: Implement robust input sanitization for the `deno.path` setting to prevent command injection. The extension should validate that the provided path points to a legitimate Deno executable and does not contain any shell metacharacters or malicious commands. Validation could include checking against a whitelist of allowed characters or using secure path parsing and validation methods.
    - **Restrict configuration scope for `deno.path`**: Limit the configurability of the `deno.path` setting to user or remote settings, disallowing workspace settings to override it. This would prevent malicious repositories from injecting this setting and gaining control.
    - **User warning for workspace `deno.path`**: Implement a warning mechanism to alert users when the `deno.path` setting is set in workspace settings, especially if it deviates from a default or known safe path. Prompting for explicit user confirmation before using a workspace-defined `deno.path` would add an additional layer of security.

- **Preconditions:**
    - The victim must have the VSCode Deno extension installed and activated within VSCode.
    - The victim must open a malicious repository in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `deno.path` setting.
    - The `deno.enable` setting must be true for the workspace, or implicitly enabled through `deno.json` detection or other activation mechanisms.

- **Source code analysis:**
    - **File:** `client/src/util.ts`
    - **Function:** `getDenoCommandPath` and `getWorkspaceConfigDenoExePath`
    - **Code Snippet:**
      ```typescript
      function getWorkspaceConfigDenoExePath() {
        const exePath = workspace.getConfiguration(EXTENSION_NS)
          .get<string>("path");
        return exePath;
      }

      export async function getDenoCommandPath() {
        const command = getWorkspaceConfigDenoExePath();
        return command ?? await getDefaultDenoCommand();
      }
      ```
      - The `getWorkspaceConfigDenoExePath` function retrieves the `deno.path` setting directly from VSCode workspace configuration without any validation.
      - `getDenoCommandPath` then returns this unsanitized path, which is subsequently used to execute Deno commands.

    - **File:** `client/src/commands.ts`
    - **Function:** `startLanguageServer`
    - **Code Snippet:**
      ```typescript
      export function startLanguageServer( /* ... */ ): Callback {
        return async () => {
          const command = await getDenoCommandPath(); // Retrieves unsanitized deno.path
          if (command == null) { return; }
          const serverOptions: ServerOptions = {
            run: {
              command, // Unsanitized command is used directly here
              args: ["lsp"],
              options: { env },
            },
            debug: {
              command, // Unsanitized command is used directly here
              args: ["lsp"],
              options: { env },
            },
          };
          const client = new LanguageClient( /* ... */  serverOptions, /* ... */ );
          await client.start();
        };
      }
      ```
      - The `startLanguageServer` function calls `getDenoCommandPath` to obtain the Deno executable path.
      - This `command`, which can be controlled by a malicious `deno.path` workspace setting, is directly passed as the `command` option in `ServerOptions` for both `run` and `debug` configurations.
      - The `LanguageClient` then uses these `ServerOptions` to spawn the Deno Language Server process, leading to command injection if `deno.path` is malicious.

- **Security test case:**
    1. Create a new directory named `vscode-deno-path-rce-test`.
    2. Inside `vscode-deno-path-rce-test`, create a subfolder named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content to inject a command that creates a file named `pwned-denopath.txt` in the `/tmp` directory (or `%TEMP%` on Windows):
       ```json
       {
         "deno.path": "bash -c 'touch /tmp/pwned-denopath.txt'"
       }
       ```
       (For Windows, use: `"deno.path": "cmd /c echo pwned > %TEMP%\\pwned-denopath.txt"`)
    4. Open the `vscode-deno-path-rce-test` folder in VSCode.
    5. Ensure the Deno extension is activated for this workspace.
    6. Observe if the file `/tmp/pwned-denopath.txt` (or `%TEMP%\\pwned-denopath.txt` on Windows) is created shortly after VSCode loads the workspace and the Deno extension initializes.
    7. If the file is created, the command injection vulnerability via `deno.path` is confirmed.

---

### 2. Command Injection via `deno.task.args` in `tasks.json`

- **Description:**
    1. A threat actor creates a malicious repository and includes a crafted `.vscode/tasks.json` file within it.
    2. This `tasks.json` file defines a Deno task where the `args` field is maliciously crafted to contain shell command injection payloads. For instance, the `args` array might include an element like `"; touch /tmp/malicious-task-file; #"`.
    3. A victim clones or opens this malicious repository in VSCode with the Deno extension installed and activated.
    4. The victim, either through manual invocation (e.g., via "Tasks: Run Task" command or the tasks sidebar) or by being socially engineered to run the malicious task, triggers the execution of the defined Deno task.
    5. When the task is executed, the `buildDenoTask` function in `client/src/tasks.ts` constructs a `vscode.ProcessExecution` object using the `command` and `args` defined in the `tasks.json` file.
    6. Due to the absence of sanitization on the `args` field, the system shell interprets and executes the injected malicious commands embedded within the `args` array. This occurs because `vscode.ProcessExecution` allows shell interpretation of arguments, making it susceptible to command injection when user-controlled input is directly passed without sanitization.

- **Impact:** **Remote Code Execution (RCE)**. Successful exploitation allows the attacker to execute arbitrary shell commands on the victim's machine whenever the victim runs the malicious task. The impact is similar to the `deno.path` vulnerability, potentially leading to full system compromise.

- **Vulnerability Rank:** **High**

- **Currently implemented mitigations:**
    - None. The extension directly uses the task arguments defined in `tasks.json` to construct and execute commands via `ProcessExecution` without any input sanitization or validation.
    - No input sanitization is performed on task arguments before they are passed to the shell.

- **Missing mitigations:**
    - **Sanitize task arguments**: Implement robust sanitization of task arguments to prevent shell command injection. The extension should either strictly disallow shell metacharacters within task arguments or properly escape arguments before passing them to the shell to ensure they are treated as literal arguments and not interpreted as shell commands.
    - **User warning for workspace tasks**: Implement a warning mechanism to alert users about tasks defined in workspace settings, particularly when opening repositories from untrusted sources. A prompt to review and confirm the execution of tasks defined in workspace settings could mitigate the risk of accidental execution of malicious tasks.

- **Preconditions:**
    - The victim must have the VSCode Deno extension installed and activated.
    - The victim must open a malicious repository that contains a malicious `tasks.json` file.
    - The victim must manually run the malicious task defined in the `tasks.json` file.

- **Source code analysis:**
    - **File:** `client/src/tasks.ts`
    - **Function:** `buildDenoTask`
    - **Code Snippet:**
      ```typescript
      export function buildDenoTask(
        target: vscode.WorkspaceFolder,
        process: string,
        definition: DenoTaskDefinition, // definition.args comes from tasks.json
        name: string,
        args: string[], // args is passed directly from definition
        problemMatchers: string[],
      ): vscode.Task {
        const exec = new vscode.ProcessExecution(
          process,
          args, // Unsanitized args from tasks.json are used here
          definition,
        );
        return new vscode.Task( /* ... */ , exec, /* ... */ );
      }
      ```
      - The `buildDenoTask` function directly utilizes the `args` array from the `DenoTaskDefinition`, which is populated from the `tasks.json` file, to create a `ProcessExecution`.
      - The `args` array, sourced directly from the potentially malicious `tasks.json`, is passed without any sanitization, allowing for command injection if malicious arguments are provided in the `tasks.json`.

- **Security test case:**
    1. Create a new folder named `vscode-deno-tasks-rce-test`.
    2. Inside `vscode-deno-tasks-rce-test`, create a subfolder named `.vscode`.
    3. Inside `.vscode`, create a file named `tasks.json` with the following content to inject a command that creates a file named `pwned-task.txt` in the `/tmp` directory (or `%TEMP%` on Windows):
       ```json
       {
         "version": "2.0.0",
         "tasks": [
           {
             "type": "deno",
             "command": "run",
             "args": [
               "`; touch /tmp/pwned-task.txt; #`",
               "mod.ts"
             ],
             "problemMatcher": [
               "$deno"
             ],
             "label": "deno: run with injection"
           }
         ]
       }
       ```
       (For Windows, use: `"args": ["\"; type C:\\windows\\system32\\calc.exe & echo \", "mod.ts"]`)
    4. Create an empty file `mod.ts` in `vscode-deno-tasks-rce-test`.
    5. Open the `vscode-deno-tasks-rce-test` folder in VSCode.
    6. Open the Command Palette (Ctrl+Shift+P) and run "Tasks: Run Task".
    7. Select the task "deno: run with injection".
    8. Observe if the file `/tmp/pwned-task.txt` (or `%TEMP%\\pwned-task.txt` on Windows) is created after running the task.
    9. If the file is created, the command injection vulnerability in tasks via `tasks.json` is confirmed.

---

### 3. Command Injection via Test Arguments (`deno.codeLens.testArgs` / `deno.testing.args`)

- **Description:**
    1. A threat actor crafts a malicious repository to exploit the VSCode Deno extension's test execution features.
    2. The malicious repository includes a `.vscode/settings.json` file.
    3. Inside `.vscode/settings.json`, the attacker sets either `deno.codeLens.testArgs` or `deno.testing.args` setting to inject command payloads. For example, setting `deno.codeLens.testArgs` to `["--allow-all", "; touch /tmp/test-args-pwned.txt"]`.
    4. A victim clones and opens this malicious repository in VSCode with the Deno extension enabled.
    5. The victim opens a test file (e.g., `test.ts`) within the repository.
    6. If using `deno.codeLens.testArgs`, the Deno extension displays a "▶ Run Test" code lens above the test definition. If using `deno.testing.args` and running tasks, the arguments are applied to the test task.
    7. If the victim clicks on the "▶ Run Test" code lens or runs a task that utilizes `deno.testing.args`, the extension executes the `deno test` command, incorporating arguments from the configured settings.
    8. Due to the injected payload in `deno.codeLens.testArgs` or `deno.testing.args`, arbitrary commands are executed on the victim's system when the test command is run.

- **Impact:** **Remote Code Execution (RCE)**. An attacker can execute arbitrary code on the victim's machine with the privileges of the VSCode process. This can lead to serious consequences, including data theft, malware installation, or full system compromise.

- **Vulnerability Rank:** **Critical**

- **Currently implemented mitigations:**
    - None. The extension directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` settings without any sanitization or validation when constructing the `deno test` command.

- **Missing mitigations:**
    - **Input sanitization**: Implement input sanitization and validation for the `deno.codeLens.testArgs` and `deno.testing.args` settings. Ensure that no shell metacharacters or command separators can be injected into the command line arguments.
    - **Parameterized commands or argument escaping**: Consider using parameterized commands or properly escaping arguments before passing them to the shell to prevent command injection.
    - **User warnings**: Warn users about the risks of modifying workspace settings from untrusted sources, especially those related to command execution like test arguments.

- **Preconditions:**
    1. The victim has the VSCode Deno extension installed and enabled.
    2. The victim opens a malicious repository in VSCode.
    3. The malicious repository contains a `.vscode/settings.json` file with a command injection payload in either `deno.codeLens.testArgs` or `deno.testing.args` setting.
    4. If exploiting `deno.codeLens.testArgs`, the victim interacts with the "Run Test" code lens in a test file. If exploiting `deno.testing.args`, the victim executes a Deno task that uses these arguments.

- **Source code analysis:**
    - **File:** `client/src/commands.ts`
    - **Function:** `test`
    - **Code Snippet:**
      ```typescript
      export function test( /* ... */ ): Callback {
        return async (uriStr: string, name: string, options: TestCommandOptions) => {
          const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []), // Unsanitized codeLens.testArgs
            ...(config.get<string[]>("testing.args") ?? []),    // Unsanitized testing.args
          ];
          const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
          const definition: tasks.DenoTaskDefinition = {
            type: tasks.TASK_TYPE,
            command: "test",
            args, // Unsanitized args are passed to task definition
            env,
          };
          const task = tasks.buildDenoTask( /* ... */ , definition, /* ... */ );
          await vscode.tasks.executeTask(task);
        };
      }
      ```
      - The `test` function retrieves `deno.codeLens.testArgs` and `deno.testing.args` configurations and merges them into `testArgs`.
      - These `testArgs` are then directly included in the `args` array for the `deno test` command without sanitization.
      - The `args` array is used to create a `DenoTaskDefinition` and subsequently a `ProcessExecution` in `buildDenoTask`, leading to command injection.

- **Security test case:**
    1. Create a new folder named `vscode-deno-test-args-rce-test`.
    2. Inside `vscode-deno-test-args-rce-test`, create a folder `.vscode`.
    3. Inside `.vscode`, create a file `settings.json` with the following content to inject a command that creates a file named `pwned-testargs.txt` in the `/tmp` directory (or `%TEMP%` on Windows):
       ```json
       {
         "deno.enable": true,
         "deno.codeLens.testArgs": [
           "--allow-all",
           "; touch /tmp/pwned-testargs.txt"
         ]
       }
       ```
       (For Windows, use:
       ```json
       {
         "deno.enable": true,
         "deno.codeLens.testArgs": [
           "--allow-all",
           "; New-Item -ItemType file -Path %TEMP%\\pwned-testargs.txt"
         ]
       }
       ```
       )
    4. Inside `vscode-deno-test-args-rce-test`, create a file `test_file.ts` with the following content:
       ```typescript
       Deno.test("testExample", () => {
         console.log("Running testExample");
       });
       ```
    5. Open the `vscode-deno-test-args-rce-test` folder in VSCode. Ensure the Deno extension is enabled for this workspace.
    6. Open `test_file.ts`.
    7. Observe the "▶ Run Test" code lens above `Deno.test`. Click on "▶ Run Test".
    8. After the test execution completes, verify if a file named `/tmp/pwned-testargs.txt` (or `%TEMP%\\pwned-testargs.txt` on Windows) has been created in the `/tmp` directory (or `%TEMP%` on Windows). The presence of this file indicates successful command injection via `deno.codeLens.testArgs`.

---

### 4. Command Injection via Deno Unstable Features (`deno.unstable`)

- **Description:**
    1. A threat actor prepares a malicious repository designed to exploit the Deno extension's upgrade mechanism.
    2. The repository includes a `.vscode/settings.json` file.
    3. In `.vscode/settings.json`, the `deno.unstable` setting is maliciously configured to include a command injection payload disguised as an "unstable feature". For example, setting `deno.unstable` to `["sloppy-imports", " ; touch /tmp/unstable-pwned.txt"]`.
    4. A victim clones and opens the malicious repository in VSCode with the Deno extension enabled.
    5. The victim may trigger a Deno upgrade process, either manually by using the "Deno: Upgrade" command or automatically if the extension prompts for an upgrade.
    6. During the upgrade process, the Deno extension constructs and executes the `deno upgrade` command, incorporating the "unstable features" from the `deno.unstable` setting as command-line flags.
    7. Due to the injected payload within the `deno.unstable` setting, arbitrary commands are executed on the victim's system as part of the upgrade command execution.

- **Impact:** **Remote Code Execution (RCE)**. An attacker can execute arbitrary code on the victim's machine with the privileges of the VSCode process. This can lead to malware installation, data exfiltration, or complete system takeover, similar to other RCE vulnerabilities described above.

- **Vulnerability Rank:** **High**

- **Currently implemented mitigations:**
    - None. The extension directly iterates through the `deno.unstable` array and constructs command-line flags without any sanitization or validation.

- **Missing mitigations:**
    - **Sanitize `deno.unstable` setting**: Sanitize or validate the `deno.unstable` setting. Ensure that the "unstable features" are treated as literal feature names and not as injectable command parts. Prevent interpretation of shell metacharacters or command separators within these settings.
    - **Whitelist unstable features**: Consider whitelisting allowed "unstable features" to prevent injection of arbitrary strings as feature names.
    - **User warning for unstable features**: Warn users if workspace settings configure unstable features, particularly from untrusted repositories, and explain potential risks associated with enabling unstable features from unknown sources.

- **Preconditions:**
    1. The victim has the VSCode Deno extension installed and activated.
    2. The victim opens a malicious repository in VSCode.
    3. The repository includes a `.vscode/settings.json` with a command injection payload within the `deno.unstable` array.
    4. The victim triggers the "Deno Upgrade" functionality, either manually or through extension prompts.

- **Source code analysis:**
    - **File:** `client/src/upgrade.ts`
    - **Function:** `denoUpgradePromptAndExecute`
    - **Code Snippet:**
      ```typescript
      export async function denoUpgradePromptAndExecute(context: ExtensionContext, extensionContext: DenoExtensionContext) {
        const config = vscode.workspace.getConfiguration(EXTENSION_NS);
        const args = ["upgrade"];
        const unstable = config.get("unstable") as string[] ?? []; // Unsanitized unstable features
        for (const unstableFeature of unstable) {
          args.push(`--unstable-${unstableFeature}`); // Directly using unstableFeature in command flag
        }
        // ... rest of the upgrade command execution using buildDenoTask and vscode.tasks.executeTask ...
      }
      ```
      - The `denoUpgradePromptAndExecute` function retrieves the `deno.unstable` setting from configuration.
      - It iterates through the `unstable` array and directly constructs command-line flags using each `unstableFeature` without any sanitization.
      - These constructed arguments are then used in the `deno upgrade` command, leading to potential command injection via malicious entries in `deno.unstable`.

- **Security test case:**
    1. Create a new folder named `vscode-deno-upgrade-rce-test`.
    2. Inside `vscode-deno-upgrade-rce-test`, create a folder `.vscode`.
    3. Inside `.vscode`, create a file `settings.json` with the following content to inject a command that creates a file named `pwned-unstable.txt` in the `/tmp` directory (or `%TEMP%` on Windows):
       ```json
       {
         "deno.enable": true,
         "deno.unstable": [
           "sloppy-imports",
           "; touch /tmp/pwned-unstable.txt"
         ]
       }
       ```
        (For Windows, use:
        ```json
        {
          "deno.enable": true,
          "deno.unstable": [
            "sloppy-imports",
            "; New-Item -ItemType file -Path %TEMP%\\pwned-unstable.txt"
          ]
        }
        ```
        )
    4. Open the `vscode-deno-upgrade-rce-test` folder in VSCode. Ensure Deno extension is enabled.
    5. Open the command palette (Ctrl+Shift+P or Cmd+Shift+P) and execute "Deno: Upgrade". You might need to have an older version of Deno CLI installed for the upgrade prompt to appear, or you can manually trigger the command if the prompt doesn't show up.
    6. Confirm the upgrade if prompted.
    7. After the upgrade process completes (or starts), check for the file named `/tmp/pwned-unstable.txt` (or `%TEMP%\\pwned-unstable.txt` on Windows) in the `/tmp` directory (or `%TEMP%` on Windows). If this file exists, it confirms command injection vulnerability via the `deno.unstable` setting during the upgrade process.
