### Vulnerability List

- Vulnerability Name: Class Pollution via Custom Type Instantiation
- Description:
    1. An attacker can trigger a component action that accepts a custom class as an argument with a type hint.
    2. The attacker crafts a malicious request, providing a JSON payload for the custom class argument that is designed to exploit the class's constructor.
    3. Django-unicorn's `cast_value` function in `typer.py` attempts to instantiate the custom class using the provided JSON data as keyword arguments to the constructor: `value = _type_hint(**value)`.
    4. If the custom class constructor (`__init__` method) is vulnerable to class pollution, for example by directly setting attributes based on the input without sanitization, the attacker can pollute the class or its instances.

- Impact:
    - High
    - Class Pollution. An attacker may be able to modify the attributes of the custom class, potentially affecting other parts of the application that use this class. In some scenarios, depending on the custom class implementation, this could potentially lead to Remote Code Execution if class pollution can be leveraged to modify critical application behavior.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code attempts to instantiate custom classes directly from user-provided data without sanitization in `django_unicorn\typer.py` in the `cast_value` function.

- Missing Mitigations:
    - Input validation and sanitization for custom class constructor arguments.
    - Restrict instantiation of arbitrary custom classes based on user input.
    - Documentation warning to developers about the security risks of using custom classes as action arguments, especially regarding constructor security.

- Preconditions:
    - The application must use a Unicorn component with an action method that accepts a custom class as an argument with a type hint.
    - The custom class constructor must be vulnerable to class pollution if provided with malicious input.

- Source Code Analysis:
    1. File: `django_unicorn\typer.py`
    2. Function: `cast_value(type_hint, value)`
    3. Code snippet:
       ```python
       if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
           value = _type_hint(**value)
           break
       else:
           value = _type_hint(value)
           break
       ```
    4. Visualization:
       ```
       [External Request] --> [Unicorn Component Action] --> cast_value(type_hint, value)
                                                                  |
                                                                  V
                                                        [Custom Class Instantiation] _type_hint(**value) or _type_hint(value)
                                                                  |
                                                                  V
                                                         [Class Pollution if constructor is vulnerable]
       ```
    5. Step-by-step explanation:
        - When a Unicorn component action is triggered with arguments, the `cast_value` function is called to convert the string representation of arguments to their Python types based on type hints.
        - If the type hint is a custom class (including Pydantic models and dataclasses), `cast_value` attempts to instantiate this class.
        - For Pydantic models and dataclasses, it uses keyword arguments (`**value`). For other custom classes, it uses positional arguments (if applicable).
        - The `value` dictionary here comes directly from the deserialized JSON payload from the client request.
        - If a custom class constructor is not carefully implemented and directly sets attributes from the input dictionary without validation or sanitization, a malicious user can craft a JSON payload to include unexpected keys. These keys might correspond to class attributes or methods, leading to class pollution when the class is instantiated.

- Security Test Case:
    1. Create a Django application with a Unicorn component.
    2. Define a custom class `PollutedClass` with a vulnerable constructor in `components/polluted_component.py`:
       ```python
       class PollutedClass:
           def __init__(self, value, polluted_attribute=None):
               self.value = value
               if polluted_attribute:
                   PollutedClass.polluted_attribute = polluted_attribute  # Class pollution vulnerability

           polluted_attribute = "original_value" # Class attribute to pollute

       from django_unicorn.components import UnicornView

       class PollutedView(UnicornView):
           def take_polluted_class(self, obj: PollutedClass):
               print(f"PollutedClass.polluted_attribute before: {PollutedClass.polluted_attribute}")
               print(f"obj.value: {obj.value}")
               print(f"PollutedClass.polluted_attribute after: {PollutedClass.polluted_attribute}")
               self.call("js_alert", PollutedClass.polluted_attribute) # Call JS alert to show polluted value

           def render(self): # Dummy render method to avoid errors
               return super().render()
       ```
    3. Create a template `unicorn/polluted-component.html`:
       ```html
       <div>
           <button unicorn:click="take_polluted_class({'value': 'test', 'polluted_attribute': 'malicious_value'})">Trigger Pollution</button>
       </div>
       ```
    4. Create a view and include the component in a template.
    5. Run the Django application.
    6. Open the page with the Unicorn component in a browser.
    7. Open browser developer tools to observe JavaScript alerts and console output.
    8. Click the "Trigger Pollution" button.
    9. Observe in the browser's console and the JavaScript alert that `PollutedClass.polluted_attribute` has been changed to `'malicious_value'`, demonstrating class pollution.
