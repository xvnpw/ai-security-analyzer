### Vulnerability List:

* Vulnerability Name: Remote Code Execution via Argument Injection in Component Actions
* Description:
An attacker can inject arbitrary Python code as arguments to component actions by crafting a malicious `call_method_name` string in the AJAX request to the `/unicorn/message` endpoint. The `parse_call_method_name` function in `django_unicorn\call_method_parser.py` uses `ast.literal_eval` to parse arguments, which, while intended for safe evaluation of literals, can be bypassed or misused in combination with type coercion or other parts of the framework to achieve unintended code execution. Although `ast.literal_eval` is designed to prevent arbitrary code execution, vulnerabilities might arise from complex interactions with the rest of the framework, especially if type coercion or custom classes are involved in processing these evaluated literals.

Steps to trigger:
1. Identify a component action that accepts arguments.
2. Craft a malicious `call_method_name` string that includes Python code within the arguments.
3. Send an AJAX request to `/unicorn/message` with the crafted `call_method_name` as part of the payload.
4. If the injected code is successfully parsed and executed by the server, remote code execution can be achieved.

* Impact:
Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server, potentially leading to full system compromise, data breach, or denial of service.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
None identified in the provided files that specifically prevent argument injection in component actions. The documentation mentions CSRF protection, but this is to prevent CSRF attacks, not RCE. The use of `ast.literal_eval` is intended as a mitigation, but it might be insufficient.

* Missing Mitigations:
Input sanitization and validation for arguments passed to component actions. Specifically:
    - Implement strict input validation to ensure arguments conform to expected types and formats.
    - Avoid using `ast.literal_eval` or similar functions directly on user-provided input for complex argument parsing if possible. If it is necessary, ensure that the context in which the evaluated literals are used is completely safe and cannot be manipulated to execute arbitrary code.
    - Consider using safer parsing methods or libraries that are specifically designed to prevent code injection.
    - Implement runtime checks to verify the type and content of arguments before they are passed to component methods.

* Preconditions:
    - The application must be using django-unicorn framework.
    - The application must have components with actions that accept arguments.
    - An attacker must be able to send AJAX requests to the `/unicorn/message` endpoint.

* Source Code Analysis:
    1. File: `django_unicorn\django_unicorn\call_method_parser.py`
    2. Function: `parse_call_method_name(call_method_name: str)`
    3. The function uses `ast.parse(method_name, "eval")` to parse the `call_method_name` string.
    4. It then iterates through `call.args` and `call.keywords` and uses `eval_value` to process each argument.
    5. Function `eval_value(value)` uses `ast.literal_eval(value)` to convert strings to Python primitives.
    6. Although `ast.literal_eval` is used, the overall process of parsing method names and arguments from a string provided directly from the request payload without sufficient validation is risky.
    7. There is no explicit sanitization or validation of the `call_method_name` string or the parsed arguments before they are used to call methods on the component.

    ```mermaid
    graph LR
        A[Client Request with call_method_name] --> B(parse_call_method_name);
        B --> C{ast.parse};
        C -- Success --> D{Iterate call.args and call.keywords};
        D --> E(eval_value);
        E --> F{ast.literal_eval};
        F -- Returns Parsed Value --> G[Method Call with Parsed Args];
        C -- Failure --> H[Error Handling];
        F -- SyntaxError --> H;
        B -- Returns method_name, args, kwargs --> G;
        G --> I[Component Method Execution];
        I --> J[Vulnerable if args are not sanitized];
    ```

* Security Test Case:
    1. Setup a Django application with django-unicorn installed.
    2. Create a component with a method that accepts an argument and is vulnerable to command injection if the argument is not sanitized. For example, a component with a method like:

    ```python
    # vulnerable_component.py
    from django_unicorn.components import UnicornView
    import os

    class VulnerableComponentView(UnicornView):
        def execute_command(self, command):
            os.system(command) # DON'T DO THIS IN PRODUCTION - VULNERABLE CODE

    ```

    3. Create a template that includes this component and has a button that triggers the `execute_command` action, allowing to pass an argument from the frontend. For simplicity, we can directly call the method with a hardcoded malicious command in the template for testing:

    ```html
    {% load unicorn %}
    <div unicorn:id="testComponent" unicorn:name="vulnerable-component">
        <button unicorn:click="execute_command('touch /tmp/unicorn_rce_test')">Trigger RCE</button>
    </div>
    ```

    4. Start the Django development server.
    5. Open the page in a browser where the component is rendered.
    6. Click the "Trigger RCE" button.
    7. Check if the file `/tmp/unicorn_rce_test` is created on the server. If the file is created, it confirms Remote Code Execution.

    **Note:** This test case is a simplified example to demonstrate the vulnerability. A real-world attack might require more sophisticated injection techniques and a more practical vulnerable method in the component. This test case is for demonstration purposes only and should be performed in a controlled testing environment.
