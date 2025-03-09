- Vulnerability Name: Cross-Site Scripting (XSS) in Template Rendering via Unsafe String
- Description:
    1. An attacker can inject malicious JavaScript code into a component's property that is marked as 'safe' either through the `Meta.safe` option in the component view or by using the `|safe` template filter.
    2. When this component is rendered, the injected JavaScript code will be executed in the user's browser because Django Unicorn will not escape the HTML content of properties marked as safe.
    3. An attacker can achieve this by controlling the data source of the 'safe' property, for example, through a database field if the component directly renders a Django model field marked as safe.
    4. This allows the attacker to perform actions on behalf of the user, steal session cookies, or redirect the user to malicious websites.
- Impact:
    - High
    - Cross-site scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to account takeover, data theft, session hijacking, and redirection to malicious sites.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Django Unicorn by default HTML-encodes all updated field values to prevent XSS attacks.
    - Developers need to explicitly opt-in to disable HTML encoding by using `Meta.safe` or `|safe` filter.
    - This mitigation relies on developers understanding the security implications of disabling HTML encoding and using it responsibly only when necessary for legitimate purposes.
- Missing Mitigations:
    - No additional sanitization is performed on properties marked as 'safe'.
    - No warnings or guidelines in the documentation strongly discourage the use of 'safe' without careful consideration.
    - It's possible that developers might use 'safe' without fully understanding the risks, especially if they are not security experts.
- Preconditions:
    - A Django Unicorn component renders a property that is marked as 'safe' (using `Meta.safe` or `|safe` filter).
    - An attacker can control or influence the value of this 'safe' property, for example, through a database record, API, or other data source.
- Source Code Analysis:
    1. File: `django_unicorn\views.py`
    2. In `_render_component_template` function, the component's context is prepared.
    3. File: `django_unicorn\serializer.py`
    4. In `dumps` function, `orjson.dumps` is used to serialize the data to JSON for sending to the frontend. By default `orjson` escapes HTML.
    5. File: `django_unicorn\templates.py`
    6. In `unicorn` template tag, the component is rendered using `component.render(**context)`.
    7. File: `django_unicorn\components.py`
    8. In `render` method, `get_template` and `Template.render` are used for rendering the template.
    9. Django template engine by default auto-escapes HTML content unless `|safe` filter is used or autoescape is off.
    10. File: `django_unicorn\docs\source\views.md` and `django_unicorn\docs\source\templates.md`
    11. Documentation explains the usage of `Meta.safe` and `|safe` to bypass HTML escaping, implying that by default, content is escaped unless explicitly marked as safe.
    12. Vulnerability exists when developers intentionally use `safe` and attacker can control the 'safe' content.

- Security Test Case:
    1. Create a Django Unicorn component that renders a property called `unsafe_data` and mark it as safe using `Meta.safe`.
    2. In the component's view, set `unsafe_data` to a string containing malicious JavaScript code, e.g., `<img src=x onerror=alert('XSS')>`.
    3. Create a Django template that includes this component.
    4. Access the template in a web browser.
    5. Observe that the JavaScript code (`alert('XSS')`) is executed, demonstrating the XSS vulnerability.

    **Example code:**

    **File: `myapp/components/xss_safe.py`**
    ```python
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",)

        def mount(self):
            self.unsafe_data = "<img src=x onerror=alert('XSS-safe-meta')>"
    ```

    **File: `myapp/templates/unicorn/xss_safe.html`**
    ```html
    <div>
        {{ unsafe_data }}
    </div>
    ```

    **File: `myapp/views.py`**
    ```python
    from django.shortcuts import render
    from myapp.components.xss_safe import XssSafeView # Import is needed to register component

    def home(request):
        return render(request, 'home.html')
    ```

    **File: `myapp/templates/home.html`**
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-safe' %}
    </body>
    </html>
    ```

    **Steps to test:**
    1.  Run the Django development server.
    2.  Access the `home` URL in your web browser.
    3.  Observe an alert box with the message 'XSS-safe-meta', confirming the XSS vulnerability when using `Meta.safe`.
    4.  Modify `myapp/components/xss_safe.py` to remove `Meta.safe` and update `myapp/templates/unicorn/xss_safe.html` to use `|safe` filter.

    **Modified File: `myapp/components/xss_safe.py`**
    ```python
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        unsafe_data = ""

        def mount(self):
            self.unsafe_data = "<img src=x onerror=alert('XSS-safe-filter')>"
    ```

    **Modified File: `myapp/templates/unicorn/xss_safe.html`**
    ```html
    <div>
        {{ unsafe_data|safe }}
    </div>
    ```
    5.  Refresh the `home` URL in your web browser.
    6.  Observe an alert box with the message 'XSS-safe-filter', confirming the XSS vulnerability when using `|safe` filter.
