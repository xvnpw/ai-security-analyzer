- Vulnerability Name: Server-Side Template Injection via Action Method Arguments

- Description:
    1. An attacker can manipulate the arguments passed to a Django Unicorn component's action method through template attributes like `unicorn:click`.
    2. The `parse_call_method_name` function in `django_unicorn/call_method_parser.py` uses `ast.parse` to parse these method calls, including arguments, from strings received from the client-side.
    3. If an attacker crafts a malicious string as an argument, `ast.parse` could be exploited to execute arbitrary Python code on the server when the component attempts to process the action.
    4. This is possible because the parsed arguments are directly evaluated within the server-side component context.

- Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server, potentially leading to full system compromise, data breach, or denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None identified in the provided code files. The code relies on `ast.parse` without any explicit sanitization or validation of the input `call_method_name` before parsing.

- Missing Mitigations:
    - Input sanitization: Implement robust sanitization of `call_method_name` in `parse_call_method_name` to remove or neutralize any potentially malicious code before parsing with `ast.parse`.
    - Input validation: Validate the structure and content of `call_method_name` to ensure it conforms to expected patterns and does not contain unexpected or dangerous constructs.
    - Use safer parsing methods: Explore if `ast.literal_eval` or other safer parsing mechanisms can be used instead of `ast.parse` for handling action method arguments, limiting the parsing capability to only literal values and preventing code execution.
    - Sandboxing or isolation: Consider running component logic in a sandboxed environment to limit the impact of potential RCE vulnerabilities.

- Preconditions:
    - The application must be using Django Unicorn and have components that handle actions with arguments passed from the template (e.g., using `unicorn:click="method(user_input)"`).
    - An attacker needs to be able to influence the arguments passed to the action method, typically through user-controlled input that gets rendered into the template.

- Source Code Analysis:
    1. **File:** `django_unicorn/call_method_parser.py`
    2. **Function:** `parse_call_method_name(call_method_name: str)`
    3. **Line:** `tree = ast.parse(method_name, "eval")` - This line uses `ast.parse` to parse the `method_name` string, which can contain arguments.
    4. **Line:** `statement = tree.body[0].value` - Extracts the expression from the parsed AST tree.
    5. **Line:** `if tree.body and isinstance(statement, ast.Call):` - Checks if the parsed expression is a function call.
    6. **Line:** `args = [eval_value(arg) for arg in call.args]` - Extracts arguments from the function call and processes them using `eval_value`.
    7. **Line:** `kwargs = {kw.arg: eval_value(kw.value) for kw in call.keywords}` - Extracts keyword arguments and processes them using `eval_value`.
    8. **Vulnerability:** The `method_name` string, which is derived from template attributes potentially influenced by user input, is directly parsed by `ast.parse`.  `ast.parse` is designed to parse full Python code and is not safe for processing untrusted input as it can be abused to execute arbitrary code. While `eval_value` uses `ast.literal_eval` which is safer, the initial parsing using `ast.parse` is the critical point of vulnerability.
    9. **Test Files Analysis**: Examining the test files, specifically `django-unicorn\tests\call_method_parser\test_parse_call_method_name.py`, `django-unicorn\tests\call_method_parser\test_parse_args.py`, and `django-unicorn\tests\call_method_parser\test_parse_kwarg.py`, reveals that the tests focus on the functional correctness of parsing various argument types (integers, strings, dictionaries, lists, kwargs). However, there is a lack of security-focused test cases that attempt to inject malicious payloads or validate input sanitization. This absence of security testing in the provided test suite further highlights the vulnerability as a critical unaddressed risk. The tests confirm the parsing logic, but do not explore potential abuse of `ast.parse`.

    **Visualization:**

    ```
    User Input (via template attribute) --> call_method_name string --> ast.parse(method_name, "eval") --> Python code execution
    ```

- Security Test Case:
    1. **Precondition:** Deploy a Django application using django-unicorn with a component that has an action method that takes an argument and is called from the template. For example, a component with the following structure:

    ```python
    # components/vulnerable_component.py
    from django_unicorn.components import UnicornView

    class VulnerableComponentView(UnicornView):
        name = "World"

        def set_name(self, new_name):
            self.name = new_name
            return True # just to have return value
    ```

    ```html
    <!-- templates/unicorn/vulnerable-component.html -->
    <div>
        Hello {{ name }}
        <button unicorn:click="set_name('{{ user_input }}')">Set Name</button>
    </div>
    ```

    Assume `user_input` in the template context is controllable by the attacker.

    2. **Attack Step:** Craft a malicious payload for `user_input` that will be injected into the `unicorn:click` attribute. A payload to execute arbitrary code could be:
       ```python
       '); import os; os.system('touch /tmp/pwned'); x = ('
       ```
       This payload attempts to break out of the string context in the template and inject Python code. The intention is to execute `os.system('touch /tmp/pwned')` on the server.

    3. **Template Rendering:**  Render a Django template that includes the vulnerable component, passing the malicious payload as `user_input` context variable.

    ```html
    <!-- templates/test_template.html -->
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'vulnerable-component' user_input=user_payload %}
    </body>
    </html>
    ```

    In the Django view:

    ```python
    # views.py
    from django.shortcuts import render

    def test_view(request):
        user_payload = "'); import os; os.system('touch /tmp/pwned'); x = ('"
        return render(request, 'test_template.html', {'user_payload': user_payload})
    ```

    4. **Trigger the Action:** Access the rendered page in a browser and click the "Set Name" button. This will send an AJAX request to the server with the crafted `call_method_name`.

    5. **Verify RCE:** Check if the command `touch /tmp/pwned` was executed on the server. If the file `/tmp/pwned` is created, it confirms Remote Code Execution. You can check the server logs for any errors or unusual activity that might indicate code execution. Alternatively, you can use a less intrusive payload like `'); __import__('time').sleep(10); x = ('` to check for command execution by observing a delay in the server response.

    6. **Expected Result:** If vulnerable, clicking the button should result in the execution of the injected Python code on the server. In this test case, the file `/tmp/pwned` should be created on the server's filesystem, or a delay should be observed if using the sleep payload. If the vulnerability is mitigated, the server should process the request without executing the injected code, and no file `/tmp/pwned` should be created, and no delay observed.
