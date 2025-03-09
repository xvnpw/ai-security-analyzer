### Vulnerability List:

- Vulnerability Name: Server-Side Template Injection via Component Arguments

- Description:
    1. An attacker can craft a malicious URL to a Django Unicorn component by directly accessing a direct view, if one exists, or by embedding a component in a regular Django view.
    2. The attacker adds specially crafted arguments to the component's URL (for direct views) or via template context (for embedded components).
    3. Django Unicorn does not properly sanitize or escape these arguments when passing them to the component's template context.
    4. If the component template uses Django's template language unsafely (e.g., using `{% filter safe %}` or `{{ variable|safe }}` on the component arguments), the attacker can inject malicious template code.
    5. When the component is rendered server-side, the injected template code is executed, leading to Server-Side Template Injection.

- Impact:
    - **Critical**
    - An attacker can achieve Remote Code Execution (RCE) on the server by injecting malicious Python code within the template. This allows full control over the server, data exfiltration, and further attacks on the infrastructure.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - Django's auto-escaping is enabled by default, which mitigates against *typical* XSS in templates, but is ineffective against SSTI if developers use `|safe` filters or `{% filter safe %}` tags on user-controlled data.
    - Django Unicorn implements checksum verification to prevent tampering with component state, but this does not prevent SSTI if the initial arguments are maliciously crafted.

- Missing Mitigations:
    - **Input Sanitization/Escaping:** Django Unicorn should automatically sanitize or escape component arguments before passing them to the template context, regardless of whether `|safe` or `{% filter safe %}` is used in the template. This could involve using Django's `escape` filter by default on all component arguments, or providing a mechanism to explicitly mark arguments as safe if truly needed.
    - **Documentation Warning:**  The documentation should explicitly warn against using `|safe` or `{% filter safe %}` on any data that originates from component arguments or any user-controlled input, highlighting the risk of SSTI.

- Preconditions:
    - The application uses Django Unicorn's direct views or embeds components in Django templates.
    - The component template unsafely uses Django template language features (`|safe` filter or `{% filter safe %}`) on component arguments or other user-controlled data.
    - An attacker must be able to influence the arguments passed to the component, either through URL parameters (for direct views) or template context (for embedded components).

- Source Code Analysis:
    1. **File: django_unicorn/components/unicorn_view.py**
    2. **Function: get_context_data(self, \*\*kwargs)**
    3. This function prepares the context data for rendering the component template.
    4. It includes `self.component_kwargs` directly in the context:
    ```python
    context.update(self.component_kwargs)
    ```
    5. The `component_kwargs` are derived from arguments passed to the `{% unicorn %}` template tag or `as_view` method, which can be directly influenced by the attacker through URL parameters or template context manipulation.
    6. **File: django_unicorn/templatetags/unicorn.py**
    7. **Function: unicorn(parser, token)**
    8. This template tag parses arguments and keyword arguments passed to the `{% unicorn %}` tag and makes them available in `component_kwargs`. There is no sanitization or escaping of these arguments here.
    9. **Vulnerability:** If a developer uses these `component_kwargs` unsafely in their component template, SSTI is possible. For example, if the template contains `{{ component.component_kwargs.unsafearg|safe }}` and the attacker controls the `unsafearg` value, they can inject malicious template code.

- Security Test Case:
    1. Create a Django Unicorn component named `ssti_component` in a Django app, e.g., `webapp`.
    2. Create a component view `webapp/components/ssti_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class SstiComponentView(UnicornView):
        unsafe_input: str = ""
    ```
    3. Create a component template `webapp/templates/unicorn/ssti_component.html` with vulnerable code:
    ```html
    <div>
        <p>Unsafe Input: {% filter safe %}{{ unsafe_input }}{% endfilter %}</p>
    </div>
    ```
    4. Create a Django view to render the component in `webapp/views.py`:
    ```python
    from django.shortcuts import render
    from webapp.components.ssti_component import SstiComponentView

    def ssti_test_view(request):
        return render(request, 'webapp/ssti_template.html', {'unsafe_input': '<b>Initial Value</b>'})
    ```
    5. Create a Django template `webapp/templates/webapp/ssti_template.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'ssti-component' unsafe_input=unsafe_input %}
    </body>
    </html>
    ```
    6. Add URL patterns in `webapp/urls.py`:
    ```python
    from django.urls import path
    from .views import ssti_test_view

    urlpatterns = [
        path('ssti/', ssti_test_view, name='ssti_test_view'),
    ]
    ```
    7. Include `webapp.urls` in project's `urls.py`.
    8. Run the Django development server.
    9. Access the URL `/ssti/?unsafe_input=<img src=x onerror=alert(document.domain)>`.
    10. **Expected Result:** An alert box with the document domain should appear in the browser, demonstrating XSS due to SSTI. To verify RCE, try injecting template code to execute Python code. For example, try to inject `{{ ''.class.mro()[1].subclasses()[408]('__init__').get_specialization()[1](request.environ['PATH_INFO']) }}` (This is a simplified example, real RCE payloads can be more complex and depend on the Django version and environment). Viewing the page source should reveal the rendered output of the injected template code, confirming SSTI.
