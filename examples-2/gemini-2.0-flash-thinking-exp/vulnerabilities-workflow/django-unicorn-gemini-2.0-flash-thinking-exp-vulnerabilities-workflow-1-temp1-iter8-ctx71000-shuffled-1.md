### Vulnerability List:

#### 1. Code Injection Vulnerability via Action Arguments Parsing

- Description:
    - An attacker can inject arbitrary Python code through action arguments due to insecure parsing of arguments in the `django-unicorn` template tag and method call processing.
    - Step-by-step trigger:
        1.  Identify a component in the application that uses actions and accepts arguments from the template.
        2.  Craft a malicious payload as an argument to a component action. This payload will contain Python code intended for execution on the server.
        3.  Trigger the action from the frontend, sending the malicious payload as an argument.
        4.  The `django-unicorn` backend will parse and evaluate this payload using `ast.literal_eval` or similar functions without sufficient sanitization or validation.
        5.  If successful, the injected Python code will be executed on the server within the context of the Django application.

- Impact:
    - **Critical**. Successful code injection can lead to complete server takeover, data breach, modification of application data, and other severe security breaches. An attacker can execute arbitrary commands on the server, potentially gaining full control of the application and its underlying infrastructure.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - None identified in the provided files that prevent code injection through argument parsing. The project relies on `ast.literal_eval` and similar mechanisms which might be vulnerable if not used carefully. HTML sanitization is present in utility functions, but it does not prevent code injection on the backend as it's not applied to action arguments.

- Missing mitigations:
    - Input sanitization and validation for action arguments on the backend to prevent execution of arbitrary code.
    - Use of secure parsing methods that do not evaluate arbitrary Python code from user input. Consider using a safer approach to convert string representations to Python types, or strictly limit the types and formats of arguments allowed.
    - Implement a strict allowlist for argument types and values if dynamic argument parsing is necessary.

- Preconditions:
    - The application must use `django-unicorn` components that define actions and accept arguments from the frontend.
    - The attacker must be able to trigger these actions with crafted arguments.

- Source code analysis:
    - The file `django_unicorn\docs\source\architecture.md` mentions: "Actions follow a similar path as the models above, however there is a different JSON stucture. Also, the method, arguments, and kwargs that are passed from the front-end get parsed with a mix of `ast.parse` and `ast.literal_eval` to convert the strings into the appropriate Python types (i.e. change the string "1" to the integer `1`)."
    - The code in `django_unicorn\call_method_parser.py` and `django_unicorn\templatetags\unicorn.py` is responsible for parsing action arguments.
    - `eval_value` function in `django_unicorn\call_method_parser.py` still appears to use `ast.literal_eval` which can be dangerous.
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

            ...
            """

            try:
                value = ast.literal_eval(value)
            except SyntaxError:
                value = _cast_value(value)

            return value
        ```
    - In `django_unicorn\templatetags\unicorn.py`, the `unicorn` templatetag parses arguments and kwargs.  The `parse_kwarg` function and the subsequent processing of `args` and `kwargs` in `UnicornNode.render` need to be carefully reviewed for insecure deserialization or code execution vulnerabilities.
    - Files like `django_unicorn\views\objects.py` show the processing of actions in `ComponentRequest` class, where `action_queue` is processed. This confirms the path for actions from frontend to backend.
    - The provided test file `tests\call_method_parser\test_parse_args.py` primarily focuses on correct parsing of different argument types but does not include security-focused test cases that attempt to inject malicious code. The new test files like `tests\views\action_parsers\call_method\test_call_method_name.py` and `tests\views\message\test_calls.py` further illustrate how arguments are parsed and passed to component methods, but still lack security considerations.
    - The presence of `sanitize_html` function in `django_unicorn\utils.py` and its test in `tests\test_utils.py` indicates an awareness of sanitization, but this function is used for output sanitization, not input validation to prevent code injection.

- Security test case:
    - Vulnerability Test Name: Code Injection via Action Arguments
    - Test Description: Attempt to execute arbitrary Python code on the server by injecting a malicious payload through a component action argument.
    - Step-by-step test:
        1.  Deploy a Django application with `django-unicorn` enabled and a component that defines an action accepting string arguments, for example a component with method:
            ```python
            def action_with_arg(self, arg1):
                return os.system(arg1) #Insecure example, DO NOT USE IN PRODUCTION
            ```
            and template:
            ```html
            <button unicorn:click="action_with_arg('echo vulnerable')">Trigger Vulnerability</button>
            ```
        2.  Access the page containing this component in a web browser.
        3.  Open browser developer tools to intercept network requests (or use a proxy like Burp Suite).
        4.  Click the "Trigger Vulnerability" button.
        5.  Observe the network request sent to the `django-unicorn` endpoint.
        6.  Modify the action argument in the request payload (e.g., in browser developer tools or proxy) to a malicious Python command, such as: `'__import__("os").system("id")'` or `'__import__("subprocess").run(["touch", "/tmp/pwned"])'`. URL-encode or properly escape the payload if needed to ensure it's correctly transmitted in the HTTP request.
        7.  Send the modified request to the server.
        8.  Check the server logs or application behavior to confirm if the injected command (`id` or `touch /tmp/pwned` in examples) was executed. If successful, the server logs should show the output of the `id` command, or the file `/tmp/pwned` should be created on the server.
        9.  If the command is successfully executed, it confirms the code injection vulnerability.
