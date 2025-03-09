## Vulnerability List

### 1. Vulnerability Name: Command Injection in Deno Tasks via Malicious Workspace Configuration

- Description:
    1. The VSCode Deno extension allows users to define Deno tasks within their workspace configuration (e.g., `tasks.json`, `deno.json`).
    2. The extension reads task definitions, including the `command` and `args` properties, from these configuration files.
    3. The `DenoTaskProvider` and `DenoTasksTreeDataProvider` components in `tasks_sidebar.ts` and `tasks.ts` parse these task definitions.
    4. When a user executes a Deno task (e.g., via the tasks sidebar or command palette), the extension uses `vscode.tasks.executeTask` to run the specified Deno command with the provided arguments.
    5. If a malicious user provides a workspace configuration file with a crafted Deno task definition, they can inject arbitrary commands into the `command` or `args` properties.
    6. When the victim opens a workspace containing this malicious configuration and executes the crafted Deno task, the injected commands will be executed on the victim's machine with the privileges of the VSCode process.

- Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine. This could lead to complete compromise of the victim's system, including data theft, malware installation, and further propagation of attacks.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - None. The extension directly executes the commands and arguments defined in the workspace configuration without sanitization or validation.

- Missing Mitigations:
    - Input sanitization and validation of task `command` and `args` properties from workspace configuration files. The extension should ensure that these properties only contain expected Deno commands and safe arguments.
    - Principle of least privilege. While not directly mitigating command injection, running the Deno language server and tasks with reduced privileges could limit the impact of a successful exploit.
    - User confirmation before executing tasks from workspace configurations, especially when the configuration source is untrusted.

- Preconditions:
    1. Victim opens a workspace containing a malicious `tasks.json` or `deno.json` file provided by the attacker (e.g., by cloning a malicious repository).
    2. Deno extension is enabled in the workspace.
    3. Victim executes the malicious Deno task, either through the tasks sidebar, command palette, or code lens.

- Source Code Analysis:
    1. **`client\src\tasks_sidebar.ts`:**
        - `DenoTasksTreeDataProvider.prototype.#runSelectedTask` and `DenoTasksTreeDataProvider.prototype.#debugTask` directly use task definitions read from `tasks.json` or `deno.json`.
        - `readTaskDefinitions` function in `util.ts` parses task definitions from JSON files without any sanitization.
        - `buildDenoConfigTask` function in `tasks.ts` constructs a `vscode.Task` object using the command and arguments from the parsed task definition.
        - `tasks.executeTask(task)` is used to execute the constructed task, which will directly execute the command and arguments.

    2. **`client\src\util.ts`:**
        - `readTaskDefinitions` function uses `jsoncParser.parseTree` to parse JSON content, but does not validate or sanitize the extracted `command` or `args` values.

    3. **`client\src\tasks.ts`:**
        - `buildDenoTask` and `buildDenoConfigTask` functions create `vscode.Task` objects. The `vscode.ProcessExecution` class takes the command and arguments directly, and VS Code will execute them without further sanitization when the task is run.

    ```typescript
    // File: client\src\tasks.ts
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition, // DenoTaskDefinition contains user controlled command and args
      name: string,
      args: string[],
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process,
        args, // args are passed directly to ProcessExecution
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
    1. Create a malicious repository with a `tasks.json` file in the root.
    2. In `tasks.json`, define a Deno task with a command injection payload in the `command` or `args` property. For example:

    ```json
    {
      "version": "2.0.0",
      "tasks": [
        {
          "type": "deno",
          "command": "run",
          "args": [
            "`; touch malicious_file.txt`"
          ],
          "problemMatcher": [
            "$deno"
          ],
          "label": "malicious: task"
        }
      ]
    }
    ```

    3. Clone this malicious repository.
    4. Open the cloned repository in VSCode with the Deno extension enabled.
    5. Open the tasks sidebar in VSCode (View -> Tasks -> Run Task...).
    6. Locate and execute the "malicious: task".
    7. Observe that a file named `malicious_file.txt` is created in the workspace, demonstrating command injection.
    8. For a more impactful test, the command can be changed to execute a reverse shell or download and execute a malicious binary.

### 2. Vulnerability Name: Code Injection via Malicious Welcome Page URI Command

- Description:
    1. The VSCode Deno extension displays a welcome page when the extension is first installed or when the "Deno: Welcome" command is executed.
    2. The welcome page is implemented as a webview (`welcome.ts`, `welcome.js`).
    3. The welcome page HTML (`welcome.ts`) contains anchor tags (`<a>`) with custom `data-command` and `data-document`/`data-setting` attributes.
    4. When a user clicks on these links in the webview, the `welcome.js` script sends a message to the extension's main process via `vscode.postMessage`.
    5. The extension's main process (`welcome.ts`) receives these messages and uses a `switch` statement to handle different commands (e.g., "openDocument", "openSetting", "enable").
    6. Specifically, the "openDocument" command in `welcome.ts` takes a `document` property from the message and constructs a `vscode.Uri` using `vscode.Uri.joinPath(this.#extensionUri, message.document)`.
    7. If a malicious user could control the `message.document` value, they could potentially inject malicious code via a crafted URI, leading to path traversal or unexpected file access.
    8. While direct Remote Code Execution is not evident in the current implementation, improper handling of URIs constructed from webview messages could introduce security vulnerabilities if URI handling logic becomes more dynamic in future versions.

- Impact:
    - Code Injection (medium risk).  Currently, the vulnerability could lead to path traversal or unexpected file access within the VSCode context. The risk could escalate to Remote Code Execution if URI handling becomes more dynamic in the future.

- Vulnerability Rank: medium

- Currently Implemented Mitigations:
    - Content Security Policy (CSP) in the welcome page HTML (`welcome.ts`) restricts script sources and other resources, mitigating some XSS risks in the webview itself.
    - The `message.document` value is used in `vscode.Uri.joinPath`, which is intended for path manipulation and might prevent direct code execution in this specific scenario.

- Missing Mitigations:
    - Input validation and sanitization of the `message.document` value in `welcome.ts` before constructing the URI to prevent path traversal attacks.
    - Secure URI handling practices to prevent path traversal or unexpected behavior when processing URIs constructed from webview messages.
    - Limiting URI construction from webview messages to only predefined safe URI paths instead of dynamically joining paths with user-controlled input.

- Preconditions:
    1. Victim has the VSCode Deno extension installed.
    2. Victim opens the welcome page (either on first install or via "Deno: Welcome" command).
    3. Victim clicks on a specially crafted link within the welcome page that triggers the "openDocument" command with a malicious `document` value.

- Source Code Analysis:
    1. **`client\src\welcome.ts`:**
        - `WelcomePanel.prototype.#getHtmlForWebview` constructs the HTML for the welcome page, including anchor tags with `data-document` attributes.
        - `WelcomePanel.prototype.dispose.webview.onDidReceiveMessage` handles messages from the webview.
        - For the "openDocument" command, `vscode.Uri.joinPath` is used with `message.document` to create a URI.

    ```typescript
    // File: client\src\welcome.ts
    #panel.webview.onDidReceiveMessage(
      (message) => {
        switch (message.command) {
          case "openDocument": {
            const uri = vscode.Uri.joinPath( // URI is constructed using message.document
              this.#extensionUri,
              message.document, // message.document is taken directly from webview message
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
        - Adds event listeners to elements with class "Command" to send messages to the extension when clicked.
        - Messages are constructed from `command.dataset`, which contains the `data-document` attribute from the HTML.

- Security Test Case:
    1.  Modify the `client\src\welcome.ts` file (for testing purposes in a development environment) to include a malicious `document` value in one of the anchor tags, for example:

        ```typescript
        // ... in WelcomePanel.prototype.#getHtmlForWebview
        <ul class="Header-links">
          <li><a href="#" class="Command" data-command="openDocument" data-document="../../../../../../../../../../../../../../../../../../etc/passwd">Malicious Link</a></li>
          <li><a href="https://github.com/denoland/vscode_deno/">GitHub</a></li>
          <li><a href="https://discord.gg/deno">Discord</a></li>
        </ul>
        // ...
        ```

    2.  Rebuild and reload the extension in VSCode.
    3.  Open the welcome page ("Deno: Welcome" command).
    4.  Click on the "Malicious Link".
    5.  Observe if the extension attempts to access or display unexpected files based on the crafted path.  While direct access to `/etc/passwd` might be restricted by VS Code, this test demonstrates the vulnerability in URI construction and potential for path traversal attempts within the extension's accessible file system context.
    6.  A more relevant test would be to evaluate if a crafted path could lead to accessing files within the extension's own directory or workspace in unintended ways.
