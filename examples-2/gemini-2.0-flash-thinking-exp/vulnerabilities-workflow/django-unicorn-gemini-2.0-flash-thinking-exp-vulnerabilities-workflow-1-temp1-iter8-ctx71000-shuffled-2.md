## Vulnerability List for django-unicorn project

Based on the provided project files, the following high-rank vulnerability has been identified:

- **Object Injection via Type Hinted Method Arguments and Properties**
    - Description:
        1. An attacker sends a crafted JSON request to the `/message/` endpoint.
        2. The request is designed to trigger a component method that accepts an argument with a class type hint or to update a component property with a class type hint. This can be a custom class, Pydantic model, or dataclass.
        3. The attacker manipulates the `payload` within the request, specifically crafting the method arguments or property value as a JSON object. This object is designed to instantiate a malicious object when the `cast_value` function is invoked.
        4. The `cast_value` function, when encountering a class type hint and a dictionary-like value, attempts to instantiate the hinted class. This is done using either `_type_hint(**value)` or `_type_hint(value)`.
        5. If the constructor (`__init__` method) of the instantiated class is designed to perform actions with security implications (e.g., executing system commands, file operations), or if the instantiated object is used in a manner that leads to further exploitation, a vulnerability is triggered. This can lead to remote code execution or arbitrary object manipulation.
        6. This vulnerability is also applicable to component properties. When a component's state is updated via a `syncInput` action, the same vulnerable `cast_attribute_value` and `cast_value` chain is used, leading to potential object injection when setting properties with class type hints.
    - Impact:
        - **Critical**: In scenarios where a carefully crafted payload leads to remote code execution, the impact is critical.
        - **High**: Even if direct remote code execution is not immediately achievable, arbitrary object manipulation, information disclosure, or other significant security breaches can result, leading to a high-severity impact. The ability to control object instantiation is a serious security risk.
    - Vulnerability rank: critical
    - Currently implemented mitigations:
        - Checksum validation on the request body: This prevents tampering with the overall request data but does not mitigate object injection within the data itself, as a crafted malicious payload can still have a valid checksum.
        - Type casting using `cast_value`: While intended for type conversion, the current implementation of `cast_value` facilitates the vulnerability by enabling class instantiation from user-controlled data based on type hints.
    - Missing mitigations:
        - Input validation and sanitization: Implement strict validation and sanitization of user-provided data before it is used for class instantiation. This should include checks to ensure that the provided data conforms to expected formats and does not contain malicious payloads.
        - Restriction of Type Hint Classes: Limit the types of classes permissible for type hinting method arguments and properties. Ideally, only primitive data types or a whitelist of safe, project-defined classes should be allowed. Disabling automatic class instantiation based on arbitrary type hints from user input would be a strong mitigation.
        - Context-Aware Input Handling: Develop context-aware input handling mechanisms that consider the expected type and intended use of each method argument and property. This could involve using custom deserialization logic that safely handles complex types without resorting to direct instantiation from raw user data.
    - Preconditions:
        - A Django Unicorn component must have either:
            - A method that takes an argument with a class type hint (custom class, Pydantic model, or dataclass).
            - A property with a class type hint that can be updated via user input (e.g., through `syncInput`).
        - The class designated in the type hint must have a constructor or `__init__` method, or subsequent usage patterns, that are susceptible to object injection attacks. This often involves classes where instantiation with attacker-controlled parameters can lead to unintended and potentially harmful operations (like command execution, file access, etc.).
    - Source code analysis:
        1. **`django_unicorn/typer.py` -> `cast_value`**: The `cast_value` function is central to this vulnerability. It checks if a type hint is a Pydantic model or dataclass. If so, it attempts to instantiate the class using `value = _type_hint(**value)`. For other classes it tries `value = _type_hint(value)`. The `value` being passed is directly derived from user input without sufficient validation.
        2. **`django_unicorn/components/unicorn_view.py` -> `_set_property`**: When a component property is set, `_set_property` is called, which in turn uses `cast_attribute_value(self, name, value)`. This function then calls `cast_value`, making property setting vulnerable.
        3. **`django_unicorn/views/action_parsers/call_method.py` -> `_call_method_name`**: Similarly, when component methods are called, `_call_method_name` uses `cast_value(arg_type_hint, arg_value)` to process arguments.  `arg_value` is directly from the request, leading to potential object injection via method arguments.

        ```mermaid
        graph LR
            A[User Request] --> B(/message/ endpoint)
            B --> C[ComponentRequest]
            C --> D[Action Parsing (_call_method_name or _set_property)]
            D --> E[cast_value in typer.py]
            E --> F[Class Instantiation with User Data (_type_hint(**value) or _type_hint(value))]
            F --> G[Potential Object Injection]
        ```

    - Security test case:
        1. Vulnerable Component Code (`example/unicorn/components/vulnerable_component.py`):
            ```python
            from django_unicorn.components import UnicornView

            class CustomObject:
                def __init__(self, command):
                    import os
                    os.system(command) # Vulnerable!

            class VulnerableView(UnicornView):
                def vulnerable_method(self, obj: CustomObject):
                    pass
            ```
        2. Vulnerable Component Template (`example/templates/unicorn/vulnerable_component.html`):
            ```html
            {# example/templates/unicorn/vulnerable_component.html #}
            <button unicorn:click="vulnerable_method({ 'command': 'echo vulnerable' })">Trigger Vulnerability</button>
            ```
        3. View for Rendering Component (`example/views.py`):
            ```python
            from django.shortcuts import render
            from django.views.generic import TemplateView

            class VulnerableViewTemplate(TemplateView):
                template_name = 'vulnerable_template.html'
            ```
        4. View Template (`example/templates/vulnerable_template.html`):
            ```html
            {# example/templates/vulnerable_template.html #}
            {% load unicorn %}
            {% component name="example.unicorn.components.vulnerable_component.VulnerableView" %}
            ```
        5. URL Configuration (`example/urls.py`):
            ```python
            from django.urls import path
            from example.views import VulnerableViewTemplate

            urlpatterns = [
                path('vulnerable', VulnerableViewTemplate.as_view(), name='vulnerable_view'),
            ]
            ```
        6. Steps to Execute Test:
            - Deploy the Django application with the vulnerable component and view.
            - Access the `/vulnerable` page in a browser to render the component.
            - Identify the component ID from the rendered HTML (e.g., inspect the `unicorn:id` attribute of the root element). Let's assume it is `testcomponentid`.
            - Craft a POST request using `curl` or a similar tool to send a message to the component:
              ```bash
              curl -X POST -H "Content-Type: application/json" -d '{"data":{},"checksum":"<CHECKSUM>","id":"testcomponentid","epoch":1678886400,"actionQueue":[{"type":"callMethod","payload":{"name":"vulnerable_method(obj={\"command\":\"touch /tmp/unicorn_vuln\"})"}}]}' http://your-app-domain/message/example.unicorn.components.vulnerable_component.VulnerableView
              ```
              Replace `<CHECKSUM>` with the SHA256 checksum of `{"data":{}}` generated using the project's `SECRET_KEY` and `generate_checksum` function.
            - After sending the request, access the server and check for the file `/tmp/unicorn_vuln`. If the file exists, it indicates successful command execution due to object injection. For a less intrusive test, use `{"command":"whoami"}` and observe the output in server logs if practical.

This vulnerability allows for potential Remote Code Execution and is ranked as critical. Immediate patching is highly recommended.
