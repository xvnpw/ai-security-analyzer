### Vulnerability List for django-unicorn project

- Vulnerability Name: Potential Cross-Site Scripting (XSS) vulnerability due to misuse of `safe` filter/setting
- Description: Django Unicorn allows developers to use the `safe` template filter or `Meta.safe` setting to bypass HTML encoding for specific component properties. If developers mistakenly apply these features to user-controlled data without proper sanitization, it could lead to XSS vulnerabilities. An attacker could inject malicious JavaScript code through user input, and if a developer uses `safe` filter or `Meta.safe` to render this unsanitized input, the code will be executed in the user's browser.

    **Step-by-step trigger:**
    1. A developer creates a Django Unicorn component and defines a property that can be influenced by user input (e.g., through `unicorn:model`).
    2. In the component's template, the developer renders this user-controlled property using the `safe` template filter (e.g., `{{ user_input|safe }}`) or by adding the property name to the `Meta.safe` tuple in the component's view.
    3. An attacker inputs malicious JavaScript code, such as `<script>alert("XSS")</script>`, into the user input field.
    4. When the component is rendered (either initially or after an update triggered by user interaction), the malicious JavaScript code is rendered without HTML encoding due to the `safe` filter/setting.
    5. The user's browser executes the injected JavaScript code, leading to an XSS attack.

- Impact: Successful XSS attacks can allow an attacker to execute arbitrary JavaScript code in the victim's browser. This can lead to session hijacking, cookie theft, defacement of the website, redirection to malicious sites, or other malicious actions performed on behalf of the user.
- Vulnerability Rank: high
- Currently implemented mitigations: Django Unicorn by default HTML encodes all output to prevent XSS. This is a strong default mitigation that is implemented within Django's template engine itself and is automatically applied to all template variables unless explicitly bypassed with the `safe` filter or `Meta.safe` setting in Unicorn components.
- Missing mitigations: Django Unicorn relies on developers to use `safe` filter and `Meta.safe` responsibly. There is no explicit and prominent warning in the documentation about the security risks of using `safe` with unsanitized user input. Missing guidance in the documentation on proper sanitization techniques to use when bypassing HTML encoding with `safe`. The `sanitize_html` utility function in `django_unicorn.utils` is present, but its documentation and purpose might be unclear to developers, potentially leading to misuse as a general XSS sanitizer when it is primarily intended for escaping HTML for JSON serialization, not for general HTML output sanitization in templates. This potential misunderstanding and misuse of `sanitize_html` as a general XSS sanitizer should be explicitly addressed in documentation, clarifying its purpose and limitations for template rendering security.
- Preconditions:
    - A Django Unicorn component is used in the application.
    - A developer uses the `safe` template filter or `Meta.safe` setting within a component's template.
    - The `safe` filter/setting is applied to a component property that is directly or indirectly influenced by user input.
    - User input is not properly sanitized before being rendered with the `safe` filter/setting.
- Source code analysis:
    - Documentation in `docs/source/views.md` and `docs/source/templates.md` describes the `Meta.safe` setting and `safe` template filter, indicating a mechanism to bypass default HTML encoding.
    - Changelog for v0.36.0 mentions HTML encoding as a security fix, suggesting awareness of XSS risks and implementation of default encoding.
    - `django_unicorn/utils.py` contains `sanitize_html` function.
        ```python
        def sanitize_html(html: str) -> SafeText:
            """
            Escape all the HTML/XML special characters with their unicode escapes, so
            value is safe to be output in JSON.

            This is the same internals as `django.utils.html.json_script` except it takes a string
            instead of an object to avoid calling DjangoJSONEncoder.
            """

            html = html.translate(_json_script_escapes)
            return mark_safe(html)  # noqa: S308
        ```
        This function is intended to escape HTML for safe inclusion in JSON, specifically using `_json_script_escapes` which is designed for use with Django's `json_script` template tag. It is not a general-purpose HTML sanitizer for preventing XSS in template output. Developers might mistakenly assume this function is sufficient for sanitizing user input for direct HTML rendering, which is incorrect.
    - `django_unicorn/components/unicorn_template_response.py` handles template rendering using `BeautifulSoup`.
        ```python
        class UnicornTemplateResponse(TemplateResponse):
            # ...
            @timed
            def render(self):
                response = super().render()
                # ...
                soup = BeautifulSoup(content, features="html.parser")
                # ...
                rendered_template = UnicornTemplateResponse._desoupify(soup)
                response.content = rendered_template
        ```
        `BeautifulSoup` is used for parsing and manipulating the HTML structure for adding Unicorn attributes and scripts, but it does not perform XSS sanitization. The HTML sanitization responsibility is delegated to Django's default template engine escaping and the developer's explicit use of `safe` when bypassing this default. The tests in `tests\views\test_process_component_request.py` and `tests\templatetags\test_unicorn_render.py` confirm the default HTML encoding and the behavior of `safe` setting.

- Security test case:
    1. Create a Django Unicorn component named `xss_test`.
    2. Add a property `unsafe_data` to the `XssTestView` component class in `components/xss_test.py`.
    ```python
    # components/xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        unsafe_data = ""

        def set_unsafe_data(self, data):
            self.unsafe_data = data

        def get_unsafe_data(self): # Added method to trigger update from template
            return self.unsafe_data
    ```
    3. Create a template `unicorn/xss_test.html` for the component and use the `safe` filter to render `unsafe_data`.
    ```html
    {# templates/unicorn/xss_test.html #}
    <div>
        <input type="text" unicorn:model="unsafe_data" unicorn:change="get_unsafe_data"> <!-- Trigger update on change -->
        <div id="xss_output">
            {{ unsafe_data|safe }}
        </div>
    </div>
    ```
    4. Create a Django template that includes the `xss_test` component.
    ```html
    {# templates/index.html #}
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test' %}
    </body>
    </html>
    ```
    5. Create a Django view and URL to render the `index.html` template.
    ```python
    # views.py
    from django.shortcuts import render
    from django.views.generic import View

    class IndexView(View):
        def get(self, request):
            return render(request, 'index.html')

    # urls.py
    from django.urls import path
    from .views import IndexView

    urlpatterns = [
        path('', IndexView.as_view(), name='index'),
    ]
    ```
    6. Add the component to `project/urls.py`.
    ```python
    # project/urls.py
    from django.contrib import admin
    from django.urls import include, path
    from example.www.views import IndexView # Import IndexView

    urlpatterns = [
        path("admin/", admin.site.urls),
        path("", IndexView.as_view(), name="index"), # Use IndexView for root path
        # Include django-unicorn urls
        path("unicorn/", include("django_unicorn.urls")),
    ]
    ```
    7. Run the Django development server.
    8. Open the page in a browser and input the following JavaScript payload into the text input: `<script>alert("XSS Vulnerability!")</script>`.
    9. Observe if an alert box with "XSS Vulnerability!" appears after changing focus from input. If it does, the XSS vulnerability is confirmed because the JavaScript code was executed.
    10. Modify the component template `unicorn/xss_test.html` to remove the `safe` filter: `{{ unsafe_data }}`.
    11. Repeat steps 8 and 9. Observe that the alert box should not appear this time, indicating that default HTML encoding is preventing XSS.
