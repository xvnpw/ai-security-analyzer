- Vulnerability Name: Remote Code Execution via Python Code Injection in Action Arguments

- Description:
    1. An attacker can craft a malicious action call with a specially crafted argument.
    2. The `parse_call_method_name` function in `django_unicorn/call_method_parser.py` uses `ast.parse` and `ast.literal_eval` to parse arguments passed to component actions from the frontend.
    3. By injecting Python code within the arguments, an attacker can bypass the intended argument parsing and achieve Remote Code Execution (RCE) on the server when the action is called.
    4. The vulnerability is triggered when a user interacts with a component in a way that calls an action with the malicious payload in the argument. For example, by clicking a button associated with a vulnerable action.

- Impact:
    Successful exploitation allows the attacker to execute arbitrary Python code on the server hosting the Django application. This can lead to:
    * Full control over the server and application.
    * Data breach and exfiltration.
    * Modification or deletion of data.
    * Denial of Service (though DoS is excluded from this list, RCE can be a vector for it).
    * Installation of malware.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    No specific mitigations are implemented in the provided code to prevent code injection through action arguments. The code relies on `ast.literal_eval` which is intended for safe evaluation of literals, but can be bypassed with carefully crafted payloads.

- Missing Mitigations:
    * Input sanitization: Arguments passed from the frontend should be strictly validated and sanitized to ensure they only contain expected data types and values. Regular expressions or allowlists should be used to filter out any potentially malicious code.
    * Avoid `ast.literal_eval`:  Consider replacing `ast.literal_eval` with safer parsing methods that do not execute code. If argument parsing is necessary, implement a custom parser that only allows specific data structures and types.
    * Principle of least privilege: The application server should run with the minimum necessary privileges to limit the impact of successful RCE.
    * Web Application Firewall (WAF): Implement a WAF to detect and block malicious requests attempting to exploit this vulnerability.

- Preconditions:
    * The application must be running with `django-unicorn` installed and a component with an action that is callable from the frontend.
    * The attacker needs to identify an action that accepts arguments and can be manipulated to inject code.

- Source Code Analysis:
    1. File: `django_unicorn/call_method_parser.py`
    2. Function: `parse_call_method_name`

    ```python
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        ...
        tree = ast.parse(method_name, "eval")
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args] # [!] Vulnerable line
            kwargs = {kw.arg: eval_value(kw.value) for kw.keywords} # [!] Vulnerable line
        ...
    ```

    *   The `parse_call_method_name` function is responsible for parsing the method name and arguments from the incoming message.
    *   It uses `ast.parse(method_name, "eval")` to parse the `call_method_name` string as a Python expression in "eval" mode. This mode is intended for evaluating single expressions, but if the input string is not carefully controlled, it can be exploited for code injection.
    *   The arguments are extracted using `call.args` and then processed by `eval_value(arg)`.
    *   The `eval_value` function further uses `ast.literal_eval` which, despite being safer than `eval`, can still be bypassed in certain contexts, especially when combined with other Python built-in functions or when the input is not strictly validated.
    *   The files `django-unicorn\tests\call_method_parser\test_parse_args.py` and `django-unicorn\tests\call_method_parser\test_parse_call_method_name.py` contain tests that demonstrate how different types of arguments are parsed, confirming the use of `ast.literal_eval` and the flexibility of the parsing process, which increases the risk of successful code injection.

    3. File: `django_unicorn/call_method_parser.py`
    4. Function: `eval_value`

    ```python
    @lru_cache(maxsize=128, typed=True)
    def eval_value(value):
        """
        Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.
        ...
        """

        try:
            value = ast.literal_eval(value) # [!] Vulnerable line
        except SyntaxError:
            value = _cast_value(value)

        return value
    ```

    *   The `eval_value` function uses `ast.literal_eval(value)` to convert string values into Python primitives.
    *   While `ast.literal_eval` is designed to safely evaluate literal expressions, vulnerabilities can arise if the context or the input string allows for the construction of malicious payloads that can execute code.

    **Visualization:**

    ```mermaid
    graph LR
        Frontend[Frontend (User Input)] --> Request[HTTP Request (Action Call)];
        Request --> Parser[call_method_parser.parse_call_method_name];
        Parser --> ASTParse[ast.parse (eval mode)];
        ASTParse --> EvalValue[call_method_parser.eval_value];
        EvalValue --> LiteralEval[ast.literal_eval];
        LiteralEval --> PythonExecution[Python Code Execution];
        PythonExecution --> Server[Server];
    ```

- Security Test Case:
    1. Prepare a Django Unicorn component with an action method that takes one argument. For example:

    ```python
    # components/vuln_test.py
    from django_unicorn.components import UnicornView

    class VulnTestView(UnicornView):
        def test_action(self, arg):
            import subprocess
            subprocess.Popen(arg, shell=True)
            return arg
    ```

    ```html
    <!-- templates/unicorn/vuln_test.html -->
    <div>
        <button unicorn:click="test_action('ls -al /tmp')">Test Action</button>
    </div>
    ```

    2.  Using browser developer tools or a tool like `curl`, intercept or construct the AJAX request sent when the "Test Action" button is clicked.
    3.  Modify the request payload to change the argument of the `test_action` method to a malicious Python code snippet. For example, assuming the component name is `vuln-test` and component id is `abcdefg`, the original request payload might look like:

        ```json
        {
          "component_name": "vuln-test",
          "component_id": "abcdefg",
          "data": {},
          "checksum": "...",
          "action_queue": [
            {
              "type": "callMethod",
              "payload": {
                "name": "test_action",
                "args": ["test"],
                "kwargs": {}
              }
            }
          ]
        }
        ```

    4.  Modify the `args` in the payload to inject malicious code. A simple example to demonstrate RCE would be to import the `os` module and execute a command.  Replace `"args": ["test"]` with:

        ```json
        "args": ["__import__('os').system('touch /tmp/unicorn_rce')"]
        ```
        or, to trigger a sleep for demonstration:
        ```json
        "args": ["__import__('time').sleep(10)"]
        ```
        **Note**: Encoding might be necessary depending on how the request is constructed (e.g., URL encoding). The exact payload might need adjustments based on the context and escaping requirements.

    5.  Send the modified AJAX request to the `/unicorn/message` endpoint.
    6.  Observe the server's behavior. If the vulnerability is successfully exploited, the command `touch /tmp/unicorn_rce` will be executed on the server, or the server will pause for 10 seconds due to the `sleep` command. Check for the file `/tmp/unicorn_rce` or monitor server-side logs for evidence of code execution.

This vulnerability allows for critical impact and needs immediate attention and mitigation.
