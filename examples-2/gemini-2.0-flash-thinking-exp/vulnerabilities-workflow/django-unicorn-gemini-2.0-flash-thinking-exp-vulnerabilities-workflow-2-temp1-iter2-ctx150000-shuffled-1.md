- Vulnerability Name: Server-Side Cross-Site Scripting (XSS) in component rendering

- Description:
    - An attacker can inject malicious JavaScript code into a Django Unicorn component's data.
    - When the component is rendered on the server-side and sent to the user's browser, the injected JavaScript code is executed.
    - This allows the attacker to perform actions such as stealing cookies, session tokens, redirecting users, or performing other malicious actions in the context of the user's browser.
    - This vulnerability can be triggered if user-provided data is directly rendered in Django templates without proper sanitization, especially when using `unicorn:model` to bind user inputs to component properties.
    - The `safe` attribute in Meta class can explicitly mark fields as safe from HTML encoding, which, if misused, can create XSS vulnerabilities.

- Impact:
    - High. Successful exploitation can lead to:
        - Account takeover through session hijacking or credential theft.
        - Data theft or manipulation.
        - Defacement of the website.
        - Redirection to malicious websites.
        - Execution of arbitrary JavaScript code in the victim's browser, potentially leading to further attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Default HTML encoding: Django Unicorn, by default, HTML encodes updated field values to prevent XSS attacks as documented in `docs\source\views.md`.
    - CSRF protection: Django Unicorn uses CSRF tokens to protect its endpoints from malicious actors, as mentioned in `docs\source\faq.md` and `docs\source\troubleshooting.md`. This prevents Cross-Site Request Forgery attacks but not directly XSS.

- Missing Mitigations:
    - No explicit input sanitization or validation is enforced by default within Django Unicorn beyond Django's template auto-escaping, except for form validation which is optional.
    - While Django's auto-escaping is active by default, developers might unknowingly bypass it using the `safe` template filter or the `safe` Meta attribute in components, as documented in `docs\source\views.md`. There's no clear warning against using `safe` with user-provided data within the provided documentation.
    - Missing documentation explicitly warning against the risks of using `safe` with user-provided content and detailing best practices for sanitizing user inputs within Django Unicorn components.

- Preconditions:
    - A Django Unicorn component must be rendering user-provided data in its template.
    - The developer must not be properly sanitizing user-provided data before rendering, or must be explicitly using the `safe` attribute or filter where sanitization is needed.
    - An attacker needs to be able to influence the data that is rendered by the vulnerable component, typically through user input fields bound with `unicorn:model`.

- Source Code Analysis:
    - **`django_unicorn\templatetags\unicorn.py` & `django_unicorn\components\unicorn_template_response.py`**: These files are responsible for rendering the component. `UnicornTemplateResponse.render()` method renders the template and prepares the response. It uses Django's template rendering which by default applies HTML auto-escaping.
    - **`django_unicorn\views\__init__.py`**: The `message` view function handles AJAX requests. It deserializes data, calls component methods, and re-renders the component. The `_process_component_request` function is key, as it's where component rendering happens after user interactions. It uses `component.render(request=request)` to get the HTML. This part relies on Django's template engine for rendering, which is generally safe due to auto-escaping unless explicitly bypassed.
    - **`docs\source\views.md` - `Meta.safe`**: This documentation clearly outlines how to disable HTML encoding for specific fields using the `safe` Meta attribute. This is intended for developers to render trusted HTML, but it can be a vulnerability if used with untrusted user input. The documentation example itself uses `something_safe = ""` and marks it as safe, but doesn't strongly caution against using it with user-generated data.
    - **`docs\source\templates.md` - `Templates are normal Django HTML templates`**: This emphasizes that standard Django templating is used. While this is generally secure due to Django's auto-escaping, the flexibility also means developers must be careful with user input and `safe` usage.

    ```python
    # django_unicorn\views\__init__.py - _process_component_request

    # ...
    # Get set of attributes that should be marked as `safe`
    safe_fields = []
    if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
        if isinstance(component.Meta.safe, Sequence):
            for field_name in component.Meta.safe:
                if field_name in component._attributes().keys():
                    safe_fields.append(field_name)

    # Mark safe attributes as such before rendering
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))  # noqa: S308

    # Pass the current request so that it can be used inside the component template
    rendered_component = component.render(request=request)
    # ...
    ```
    - The code snippet above shows where `Meta.safe` is processed. It uses Django's `mark_safe` which explicitly tells Django *not* to escape the content, making it raw HTML. If `something_safe` component variable contains user input and `Meta: safe = ("something_safe", )` is used, XSS is possible.

- Security Test Case:
    1. Create a Django Unicorn component that displays user input.

        ```python
        # example_app/components/xss_test.py
        from django_unicorn.components import UnicornView

        class XssTestView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input", ) # Simulate developer mistake, marking user input as safe.

            def set_input(self, input_value):
                self.user_input = input_value
        ```

        ```html
        {# example_app/templates/unicorn/xss-test.html #}
        <div>
            <input type="text" unicorn:model="user_input" id="user_input">
            <div id="output">
                {{ user_input }}
            </div>
        </div>
        ```

    2. Create a Django template to include the component.

        ```html
        {# example_app/templates/index.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-test' %}
        </body>
        </html>
        ```

    3. Set up URL and view to render the template

        ```python
        # example_app/views.py
        from django.shortcuts import render

        def index(request):
            return render(request, 'index.html')
        ```
        ```python
        # example_app/urls.py
        from django.urls import path
        from . import views

        urlpatterns = [
            path('', views.index, name='index'),
        ]
        ```
        ```python
        # project/urls.py
        from django.contrib import admin
        from django.urls import path, include
        from example_app import urls as example_app_urls
        import django_unicorn.urls

        urlpatterns = [
            path('admin/', admin.site.urls),
            path("unicorn/", include(django_unicorn.urls)),
            path('', include(example_app_urls)),
        ]
        ```

    4. Access the page in a browser and enter the following payload into the input field: `<img src=x onerror=alert('XSS Vulnerability!')>`

    5. Observe that an alert box pops up with the message "XSS Vulnerability!". This confirms that the JavaScript code was executed, demonstrating a Server-Side XSS vulnerability.

        **Alternatively**, a less intrusive test would be to inject: `<script>document.getElementById('output').textContent = 'XSSed!';</script>` and see if the text in the div with `id="output"` changes to "XSSed!".

    6. Remove `class Meta: safe = ("user_input", )` from the component and repeat steps 4 and 5. Observe that the alert box no longer appears, and the injected code is rendered as text, demonstrating that default HTML encoding prevents the XSS vulnerability.
