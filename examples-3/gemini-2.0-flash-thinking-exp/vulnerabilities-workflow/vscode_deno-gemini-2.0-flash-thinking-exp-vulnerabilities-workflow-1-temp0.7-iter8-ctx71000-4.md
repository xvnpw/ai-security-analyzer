### Vulnerability 1: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings

- Vulnerability Name: Command Injection in Test Arguments
- Description:
    1. A threat actor crafts a malicious repository.
    2. The malicious repository includes a `.vscode/settings.json` file.
    3. This `.vscode/settings.json` file modifies the workspace settings to include malicious commands within the `deno.codeLens.testArgs` or `deno.testing.args` settings. For example, injecting shell commands like `; touch poc_rce;` or similar.
    4. A victim opens this malicious repository in VSCode with the Deno extension installed and enabled.
    5. The victim opens a Deno test file, which triggers the display of the "Run Test" code lens.
    6. When the victim clicks the "Run Test" code lens, the extension executes the `deno test` command.
    7. The extension, without sanitizing the `deno.codeLens.testArgs` or `deno.testing.args` settings, incorporates these settings directly into the command line arguments passed to the `deno test` command.
    8. This results in the execution of the injected malicious commands alongside the intended `deno test` command, leading to command injection.
- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to data exfiltration, installation of malware, or complete system compromise.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The extension directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` settings without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization and validation for the `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension should restrict the characters and commands allowed in these settings, or ideally, disallow shell commands altogether.
    - Consider using a safer method for constructing and executing commands, such as parameterized commands or using an API that prevents shell injection.
- Preconditions:
    - The victim has the VSCode Deno extension installed and enabled.
    - The victim opens a malicious repository containing a crafted `.vscode/settings.json` file that injects malicious commands into `deno.codeLens.testArgs` or `deno.testing.args`.
    - The victim opens a Deno test file and clicks the "Run Test" code lens.
- Source Code Analysis:
    - File: `client/src/commands.ts`, function: `test`
    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        const uri = vscode.Uri.parse(uriStr, true);
        const filePath = uri.fsPath;
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting
        ];
        const unstable = config.get("unstable") as string[] ?? [];
        for (const unstableFeature of unstable) {
          const flag = `--unstable-${unstableFeature}`;
          if (!testArgs.includes(flag)) {
            testArgs.push(flag);
          }
        }
        if (options?.inspect) {
          testArgs.push(getInspectArg(extensionContext.serverInfo?.version));
        }
        if (!testArgs.includes("--import-map")) {
          const importMap: string | undefined | null = config.get("importMap");
          if (importMap?.trim()) {
            testArgs.push("--import-map", importMap.trim());
          }
        }
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        const env = {} as Record<string, string>;
        const denoEnvFile = config.get<string>("envFile");
        if (denoEnvFile) {
          if (workspaceFolder) {
            const denoEnvPath = path.join(workspaceFolder.uri.fsPath, denoEnvFile);
            try {
              const content = fs.readFileSync(denoEnvPath, { encoding: "utf8" });
              const parsed = dotenv.parse(content);
              Object.assign(env, parsed);
            } catch (error) {
              vscode.window.showErrorMessage(
                `Could not read env file "${denoEnvPath}": ${error}`,
              );
            }
          }
        }
        const denoEnv = config.get<Record<string, string>>("env");
        if (denoEnv) {
          Object.assign(env, denoEnv);
        }
        const cacheDir: string | undefined | null = config.get("cache");
        if (cacheDir?.trim()) {
          env["DENO_DIR"] = cacheDir.trim();
        }
        if (config.get<boolean>("future")) {
          env["DENO_FUTURE"] = "1";
        }
        const nameRegex = `/^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$/`;
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args,
          env,
        };

        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName();
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );

        task.presentationOptions = {
          reveal: vscode.TaskRevealKind.Always,
          panel: vscode.TaskPanelKind.Dedicated,
          clear: true;
        };
        task.group = vscode.TaskGroup.Test;

        const createdTask = await vscode.tasks.executeTask(task);

        if (options?.inspect) {
          await vscode.debug.startDebugging(workspaceFolder, {
            name,
            request: "attach",
            type: "node",
          });
        }

        return createdTask;
      };
    }
    ```
    The `testArgs` variable is populated directly from `config.get<string[]>("codeLens.testArgs")` without any sanitization. These arguments are then directly passed to `vscode.ProcessExecution`, leading to potential command injection.

- Security Test Case:
    1. Create a new directory for the malicious repository (e.g., `malicious-repo`).
    2. Navigate into the `malicious-repo` directory in your terminal.
    3. Create a `.vscode` subdirectory: `mkdir .vscode`.
    4. Inside `.vscode`, create a `settings.json` file with the following content:
        ```json
        {
            "deno.codeLens.testArgs": ["--allow-read", "--allow-write", "--allow-net", "--allow-run", "; touch poc_rce; "]
        }
        ```
    5. Create a Deno test file named `test.ts` in the root of `malicious-repo` with the following content:
        ```typescript
        import { assertEquals } from "https://deno.land/std@0.218.0/assert/mod.ts";

        Deno.test("example test", () => {
          assertEquals(1 + 1, 2);
        });
        ```
    6. Open the `malicious-repo` directory in VSCode with the Deno extension enabled.
    7. Open the `test.ts` file. You should see the "Run Test" code lens above the `Deno.test` declaration.
    8. Click the "Run Test" code lens.
    9. After the test execution (which should pass), check the `malicious-repo` directory. You should find a new file named `poc_rce`. The creation of this file indicates successful command injection, as the `touch poc_rce` command was executed from the `deno.codeLens.testArgs` setting.

### Vulnerability 2: Command Injection via `deno.path` setting

- Vulnerability Name: Command Injection via Deno Path Setting
- Description:
    1. A threat actor could socially engineer a victim to configure the `deno.path` setting in VSCode to point to a malicious executable instead of the legitimate Deno CLI.
    2. This could be achieved through phishing, misleading instructions, or by tricking the victim into importing and using a malicious configuration file.
    3. Once the `deno.path` setting points to the malicious executable, any operation within VSCode that invokes the Deno CLI (like starting the language server, running tests, formatting, etc.) will execute the malicious script.
    4. The malicious script, having replaced the legitimate Deno CLI, can then execute arbitrary commands on the victim's system.
- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by replacing the Deno executable.
- Vulnerability Rank: High
- Currently Implemented Mitigations: The extension checks if the provided path in `deno.path` exists and is an executable file. However, it does not verify if the executable is actually the legitimate Deno CLI or a malicious replacement.
- Missing Mitigations:
    - Implement stronger validation for the `deno.path` setting. This could include:
        - Verifying the digital signature or checksum of the executable to ensure it is the legitimate Deno CLI.
        - Restricting `deno.path` to only allow absolute paths from known trusted locations.
        - Displaying a clear warning to the user when `deno.path` is changed, especially if it's set to a non-standard location.
    - Consider removing the `deno.path` setting altogether and rely solely on the Deno CLI being available in the system's PATH environment variable, as documented in the extension's README.
- Preconditions:
    - The victim has the VSCode Deno extension installed and enabled.
    - The victim is tricked into changing the `deno.path` setting in VSCode to point to a malicious executable.
    - An action is performed in VSCode that triggers the execution of the Deno CLI (e.g., extension activation, language server start, formatting, testing).
- Source Code Analysis:
    - File: `client/src/commands.ts`, function: `startLanguageServer`
    ```typescript
    export function startLanguageServer(
      context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async () => {
        // ...
        const command = await getDenoCommandPath(); // Resolves deno.path
        if (command == null) {
          // ... error handling ...
          return;
        }
        // ... serverOptions ...
        const serverOptions: ServerOptions = {
          run: {
            command, // Potentially malicious command from deno.path
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // Potentially malicious command from deno.path
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( // Executes the command
          LANGUAGE_CLIENT_ID,
          LANGUAGE_CLIENT_NAME,
          serverOptions,
          {
            outputChannel: extensionContext.outputChannel,
            middleware: {
              workspace: {
                configuration: (params, token, next) => {
                  const response = next(params, token) as Record<string, unknown>[];
                  for (let i = 0; i < response.length; i++) {
                    const item = params.items[i];
                    if (item.section == "deno") {
                      transformDenoConfiguration(extensionContext, response[i]);
                    }
                  }
                  return response;
                },
              },
            },
            ...extensionContext.clientOptions,
          },
        );
        // ... client start ...
      };
    }
    ```
    The `getDenoCommandPath()` function (defined in `client/src/util.ts`) retrieves the path from the `deno.path` setting. This path, if maliciously manipulated, is then directly used as the `command` in `serverOptions` and executed by the `LanguageClient`, leading to potential command injection if the path points to a malicious script.

- Security Test Case:
    1. Create a malicious script (e.g., `malicious_deno.sh`) in a safe directory (e.g., `/tmp` or `C:\temp`). The script should contain:
        ```bash
        #!/bin/bash
        touch /tmp/poc_rce_deno_path_setting  # For Linux/macOS
        # touch C:\temp\poc_rce_deno_path_setting.txt # For Windows
        /path/to/legitimate/deno "$@" # Optionally forward arguments to legitimate deno for functionality
        ```
        Replace `/path/to/legitimate/deno` with the actual path to your legitimate Deno executable if you want to maintain some functionality.
    2. Make the script executable: `chmod +x /tmp/malicious_deno.sh`.
    3. In VSCode, open User Settings (File > Preferences > Settings or Code > Settings > Settings).
    4. Search for "deno.path" and edit the setting to point to your malicious script. For example: `"/tmp/malicious_deno.sh"` (or `"C:\\temp\\malicious_deno.sh"` on Windows).
    5. Reload VSCode (or just restart the Deno Language Server using command "Deno: Restart Language Server").
    6. After VSCode reloads and the Deno extension activates, check the `/tmp` directory (or `C:\temp` on Windows). You should find a new file named `poc_rce_deno_path_setting` (or `poc_rce_deno_path_setting.txt` on Windows). The creation of this file indicates successful command injection, as the malicious script set in `deno.path` was executed upon extension activation.
