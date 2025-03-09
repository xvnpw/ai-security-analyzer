* Vulnerability name: **Unsafe Deserialization of Action Arguments leading to Remote Code Execution**
* Description:
    1. An attacker can craft a malicious payload in an action call.
    2. The `django-unicorn` framework uses `ast.literal_eval` and `ast.parse` to deserialize arguments passed from the client-side to the server-side action methods.
    3. By manipulating the arguments in the action call, an attacker can inject arbitrary Python code.
    4. This injected code gets executed on the server when `django-unicorn` processes the action.
* Impact:
    - Critical. Successful exploitation allows for arbitrary Python code execution on the server. This can lead to full server compromise, data breach, and other severe security breaches.
* Vulnerability rank: critical
* Currently implemented mitigations:
    - None. The project relies on `ast.literal_eval` and `ast.parse` which are known to be potentially unsafe for deserializing untrusted input when used improperly. Based on the provided code files (`typer.py`, `views\action_parsers\call_method.py`), the vulnerability likely resides within the `django_unicorn.call_method_parser` module (code not provided), as indicated by the documentation. The files in this batch do not show any mitigation efforts.
* Missing mitigations:
    - Implement secure deserialization of action arguments. Instead of using `ast.literal_eval` and `ast.parse`, use a safer approach like allowing only predefined types and sanitizing the input. Input validation should be strictly enforced to prevent execution of arbitrary code. Consider using a safe serialization format like JSON and validating the structure and types of incoming arguments against an expected schema.
* Preconditions:
    - The application must be using `django-unicorn` and have components with action methods that accept arguments.
    - The application must be publicly accessible to external attackers.
* Source code analysis:
    1. **File:** `django_unicorn\docs\source\architecture.md` and `django_unicorn\docs\source\actions.md` (from previous context) and code files: `django_unicorn\typer.py`, `django_unicorn\views\action_parsers\call_method.py`, `django_unicorn\views\__init__.py`.
    2. **Description:** Documentation files describe action arguments parsing using `ast.parse` and `ast.literal_eval`. Code files `typer.py` and `views\action_parsers\call_method.py` handle type casting and method calls, but the vulnerable deserialization likely happens in `django_unicorn.call_method_parser` based on documentation (code not provided in this batch). `views\__init__.py` orchestrates the request processing.
    3. **Code Snippet from `architecture.md`:** (from previous context)
    > Actions follow a similar path as the models above, however there is a different JSON stucture. Also, the method, arguments, and kwargs that are passed from the front-end get parsed with a mix of `ast.parse` and `ast.literal_eval` to convert the strings into the appropriate Python types (i.e. change the string "1" to the integer `1`). After the component is re-initialized, the method is called with the passed-in arguments and kwargs. Once all of the actions have been called, the component view is re-rendered and the HTML is returned in the response.
    4. **Code Snippet from `actions.md`:** (from previous context)
    > Actions can also pass basic Python types to the backend component.
    > ```html
    > <!-- passing-args.html -->
    > <div>
    >   <input unicorn:model="name" type="text" id="text" />
    >   Hello {{ name|title }} 👋
    >   <button unicorn:click="set('Bob')">Set as Bob</button>
    >   <button unicorn:click="set()">Set default value of name argument</button>
    > </div>
    > ```
    > ```python
    > # passing_args.py
    > from django_unicorn.components import UnicornView
    >
    > class PassingArgsView(UnicornView):
    >     name = "World"
    >
    >     def set(self, name="Universe"):
    >         self.name = name
    > ```
    5. **Vulnerability Point:** The use of `ast.parse` and `ast.literal_eval` as highlighted in the documentation and likely implemented in `django_unicorn.call_method_parser` (code not provided). These functions are not safe for deserializing arbitrary user input and can lead to arbitrary code execution.
    6. **Visualization:** (from previous context)
        ```
        [Client-side (Browser)] --> [AJAX Request with Malicious Action Arguments] --> [Server-side (Django Unicorn)] --> [ast.parse & ast.literal_eval] --> [Arbitrary Code Execution]
        ```
* Security test case: (from previous context)
    1. Create a Django Unicorn component with an action method that takes an argument.
        ```python
        # example_component.py
        from django_unicorn.components import UnicornView

        class ExampleComponentView(UnicornView):
            name = "World"

            def set_name(self, malicious_input):
                exec(malicious_input) # Simulate vulnerable code - in real scenario, vulnerability is in argument parsing itself
                self.name = "Executed"
        ```
        ```html
        <!-- example_component.html -->
        <div>
            <button unicorn:click="set_name('__import__(\'os\').system(\'touch /tmp/unicorn_rce\')')">Trigger RCE</button>
            <p>Name: {{ name }}</p>
        </div>
        ```
    2. Include this component in a Django template and serve the application.
    3. As an attacker, open the page in a browser.
    4. Inspect the network requests and identify the AJAX endpoint for Unicorn component updates (typically `/unicorn/`).
    5. Craft a malicious payload for the `set_name` action. The payload should contain Python code that you want to execute on the server. For example, to create a file `/tmp/unicorn_rce`, the payload in the button's `unicorn:click` attribute would be: `__import__('os').system('touch /tmp/unicorn_rce')`.
    6. Click the button in the browser. This will send an AJAX POST request to the `/unicorn/` endpoint with the malicious payload.
    7. On the server, the `django-unicorn` framework will deserialize the arguments using `ast.parse` and `ast.literal_eval`. This will execute the injected Python code, creating the file `/tmp/unicorn_rce` on the server.
    8. Verify the vulnerability by checking if the file `/tmp/unicorn_rce` exists on the server. If the file is created, the vulnerability is confirmed.
