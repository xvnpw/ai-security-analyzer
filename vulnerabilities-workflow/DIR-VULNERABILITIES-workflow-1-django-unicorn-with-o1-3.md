### Vulnerability List:

* **Vulnerability Name:** Remote Code Execution via Template Injection in Component Arguments

* **Description:**
    An attacker can inject template code into component arguments, leading to remote code execution on the server when the template is rendered. This is possible because the `unicorn` template tag does not properly sanitize arguments passed to components, and these arguments are directly rendered within the component template.

    **Steps to Trigger:**
    1. Identify a page that uses a django-unicorn component and accepts arguments in the `unicorn` template tag. For example: `{% unicorn 'my-component' arg1=user_input %}`.
    2. Craft a malicious input for `user_input` that contains Django template code designed to execute arbitrary Python code. For example: `{% import os %}{{ os.system('whoami') }}`.
    3. Submit a request to the page with the crafted malicious input.
    4. The django-unicorn backend will render the component template, including the injected template code within the argument.
    5. Django's template engine will execute the injected code, leading to remote code execution on the server.

* **Impact:**
    Critical. Successful exploitation allows an attacker to execute arbitrary Python code on the server hosting the django-unicorn application. This could lead to complete compromise of the server and the application's data, including sensitive information, user accounts, and the ability to modify application behavior.

* **Vulnerability Rank:** Critical

* **Currently Implemented Mitigations:**
    None. Based on the provided code, specifically in `django_unicorn/templatetags/unicorn.py`, there is no input sanitization or escaping applied to component arguments before rendering them in the template. The `sanitize_html` function in `django_unicorn/utils.py` is available, but it's not used in the component argument rendering process.  Review of the provided project files (`tests\views\utils\test_set_property_from_data.py` and `pyproject.toml`) does not indicate any implemented mitigations for this vulnerability.

* **Missing Mitigations:**
    - Implement robust input sanitization and escaping for all component arguments passed through the `unicorn` template tag in `django_unicorn/templatetags/unicorn.py`.
    - Consider using Django's built-in `escape` template filter or a similar mechanism to automatically escape arguments before rendering.
    - Alternatively, explore using a templating engine that automatically escapes output by default, or enforce manual escaping of all dynamic content within component templates.
    - Review and audit all existing components that accept arguments to identify and mitigate potential template injection points.

* **Preconditions:**
    - The application must use django-unicorn components and pass arguments to them via the `unicorn` template tag.
    - An attacker must be able to control or influence the values of these arguments, either directly through user input or indirectly through other application vulnerabilities.

* **Source Code Analysis:**

    1. **`django_unicorn/templatetags/unicorn.py`:** This file defines the `unicorn` template tag, which is used to render components in Django templates. The `unicorn` tag's `render` method is where the vulnerability lies.
    2. **`UnicornNode.render` function:** This function is responsible for creating and rendering the component. It retrieves arguments passed to the `unicorn` tag and passes them to the component's template context.
    3. **Argument Handling:** Inside `UnicornNode.render`, arguments passed to the `unicorn` template tag are resolved from the template context and stored in `resolved_kwargs`. These `resolved_kwargs` are directly passed to `UnicornView.create` and eventually end up in the component's template context within the `_render_component_template` function in `django_unicorn/templatetags/unicorn.py`.
    4. **Template Context Creation in `_render_component_template`:** The `_render_component_template` function, called during component rendering, creates a Django `Context` object. Crucially, the `kwargs` (which contain the arguments passed to the `unicorn` tag) are directly unpacked into this context using `**kwargs`. This means any template code injected within these arguments will be directly processed by Django's template engine during rendering.

    **Code Snippet from `django_unicorn/templatetags/unicorn.py` (relevant part):**
    ```python
    class UnicornNode(template.Node):
        def render(self, context):
            ...
            resolved_kwargs = self.kwargs.copy()
            ...
            self.view = UnicornView.create(
                ...
                kwargs=resolved_kwargs, # kwargs are directly passed to component creation
            )
            ...
            rendered_component = self.view.render(init_js=True, extra_context=extra_context)
            return rendered_component
    ```

    **Code Snippet from `django_unicorn/templatetags/unicorn.py` (relevant part - `_render_component_template`):**
    ```python
    def _render_component_template(
        ...
        kwargs: Dict, # kwargs from UnicornNode.render
        context_autoescape: bool,
        ...
    ) -> Tuple[UnicornView, str]:
        ...
        context = Context(
            {
                "component": component,
                "unicorn": {
                    ...
                },
                **component.data,
                **kwargs, # Arguments passed to the template tag are unpacked directly into the context
            },
            autoescape=context_autoescape,
        )
        ...
        html = template.render(context) # Template is rendered with the context, including un-sanitized kwargs
        ...
    ```

    This direct inclusion of `kwargs` into the template context without any sanitization or escaping is the root cause of the template injection vulnerability.  Review of `tests\views\utils\test_set_property_from_data.py` does not reveal any changes related to template rendering or sanitization.

* **Security Test Case:**

    **Assumptions:**
    - We have a Django application running django-unicorn.
    - There is a component named `test_arg_component` and a template `test_arg_component.html` that renders an argument passed to it.
    - The `urls.py` includes a path to a view that renders a template using this component, and allows passing user-controlled data as an argument.

    **Steps:**
    1. Create a component `test_arg_component` in `myapp/components/test_arg_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class TestArgComponentView(UnicornView):
        arg_value = ""

        def mount(self, arg_value="default"):
            self.arg_value = arg_value
    ```

    2. Create a template `test_arg_component.html` in `myapp/templates/unicorn/test_arg_component.html`:
    ```html
    <div>
        Argument Value: {{ arg_value }}
    </div>
    ```

    3. Create a view in `myapp/views.py` to render a template that uses the component and allows passing a GET parameter as an argument:
    ```python
    from django.shortcuts import render

    def test_arg_view(request):
        malicious_arg = request.GET.get('arg', 'safe_value')
        context = {'user_arg': malicious_arg}
        return render(request, 'test_arg_template.html', context)
    ```

    4. Create a template `test_arg_template.html` in `myapp/templates/test_arg_template.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        <h1>Test Argument Component</h1>
        {% unicorn 'test-arg-component' arg_value=user_arg %}
    </body>
    </html>
    ```

    5. Add a path to `urls.py` in `myapp/urls.py` or project level `urls.py`:
    ```python
    from django.urls import path
    from myapp.views import test_arg_view

    urlpatterns = [
        path('test-arg/', test_arg_view, name='test_arg_view'),
    ]
    ```

    6. Access the URL `/test-arg/?arg={% import os %}{{ os.system('whoami') }}` in a browser.
    7. Observe the output of the `whoami` command (or any other injected command) rendered on the page, confirming remote code execution.

This vulnerability allows a remote attacker to execute arbitrary code on the server, making it a **critical security risk**. Immediate mitigation is highly recommended.  The provided project files do not contain any changes that would mitigate this vulnerability, thus it remains a **critical security risk**.
