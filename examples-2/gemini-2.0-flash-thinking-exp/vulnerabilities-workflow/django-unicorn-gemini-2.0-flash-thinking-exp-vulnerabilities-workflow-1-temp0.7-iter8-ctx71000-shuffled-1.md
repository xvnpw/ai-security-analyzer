### Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via `safe` Meta Option

* Description:
    1. A Django Unicorn component is created with a property that is intended to render HTML content without escaping. This is achieved by adding the property name to the `safe` tuple within the `Meta` class of the component view.
    2. A template is created to render this component, directly outputting the value of the `safe` property into the HTML without any further sanitization.
    3. An attacker crafts a malicious input containing JavaScript code (e.g., `<img src=x onerror=alert('XSS')>`).
    4. This malicious input is somehow set as the value of the `safe` property in the component (e.g., through URL parameters, form input, or database content).
    5. When the component is rendered, the malicious JavaScript code within the `safe` property is injected directly into the HTML output without sanitization.
    6. When a user's browser renders this page, the injected JavaScript code executes, leading to Cross-Site Scripting.

* Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view the affected page. This can lead to:
    - Account takeover by stealing session cookies or credentials.
    - Defacement of the website.
    - Redirection to malicious websites.
    - Theft of sensitive user data displayed on the page.
    - Performing actions on behalf of the user without their consent.

* Vulnerability Rank: high

* Currently implemented mitigations:
    - By default, Django Unicorn automatically HTML-encodes all component properties to prevent XSS, as mentioned in the documentation ([views.md#safe](https://www.django-unicorn.com/docs/views/#safe)).
    - The documentation ([views.md#safe](https://www.django-unicorn.com/docs/views/#safe)) explicitly warns against using the `safe` Meta option with user-controlled data and recommends sanitizing data even when using `safe`.
    - Test case `tests/views/test_process_component_request.py::test_safe_html_entities_not_encoded` confirms that HTML entities are not encoded when `safe` meta option is used.

* Missing mitigations:
    - Django Unicorn does not provide automatic sanitization for properties marked as `safe`. It relies on developers to understand the security implications and manually sanitize any data that is rendered as safe HTML, especially if the data source is untrusted or user-controlled.
    - There are no built-in functions or helpers within Django Unicorn to assist developers in sanitizing HTML content before marking it as safe.

* Preconditions:
    1. A Django Unicorn component view must have a `Meta` class with a `safe` tuple that includes a property name.
    2. The component's template must render the value of this `safe` property directly into the HTML, without any additional sanitization template filters (like Django's `escape` or `safestr`).
    3. The value of the `safe` property must be influenced by user input or data from an untrusted source that an attacker can control.

* Source code analysis:
    1. **`django_unicorn/views/__init__.py`**:
        - The `_process_component_request` function handles the rendering of components.
        - It retrieves `safe_fields` from the component's `Meta` class.
        ```python
        safe_fields = []
        if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
            if isinstance(component.Meta.safe, Sequence):
                for field_name in component.Meta.safe:
                    if field_name in component._attributes().keys():
                        safe_fields.append(field_name)
        ```
        - It then iterates through `safe_fields` and uses `mark_safe` to mark the corresponding component attributes as safe for HTML rendering.
        ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
        ```
        - The use of `mark_safe` directly injects the string value into the template without HTML escaping. This is the root cause of the XSS vulnerability when used with user-controlled data.
    2. **`tests/views/test_process_component_request.py`**:
        - `test_html_entities_encoded` test case verifies that by default, HTML entities are encoded.
        - `test_safe_html_entities_not_encoded` test case explicitly verifies that when the `safe` option is used, HTML entities are *not* encoded, confirming the intended behavior and the vulnerability.
        ```python
        def test_safe_html_entities_not_encoded(client):
            data = {"hello": "test"}
            action_queue = [
                {
                    "payload": {"name": "hello", "value": "<b>test1</b>"},
                    "type": "syncInput",
                }
            ]
            response = post_and_get_response(
                client,
                url="/message/tests.views.test_process_component_request.FakeComponentSafe",
                data=data,
                action_queue=action_queue,
            )

            assert not response["errors"]
            assert response["data"].get("hello") == "<b>test1</b>"
            assert "<b>test1</b>" in response["dom"] # <--- "<b>test1</b>" is directly in the DOM
        ```
    3. **Visualization**:
        ```mermaid
        graph LR
            A[User Input] --> B(Component Property - safe=True);
            B --> C{Template Rendering};
            C --> D[HTML Output - No Encoding];
            D --> E[User Browser];
            E -- Executes Malicious Script --> F(XSS Vulnerability);
        ```

* Security test case:
    1. Create a new Django app (e.g., `xss_test`) and add it to `INSTALLED_APPS`.
    2. Create a component in `xss_test/components/xss_component.py`:
        ```python
        from django_unicorn.components import UnicornView

        class XSSView(UnicornView):
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
    3. Create a template for the component in `xss_test/templates/unicorn/xss.html`:
        ```html
        <div>
            <p>Unsafe Content:</p>
            <div>{{ unsafe_content }}</div>
        </div>
        ```
    4. Create a Django view in `xss_test/views.py` to render the component and pass user-controlled data to `unsafe_content`:
        ```python
        from django.shortcuts import render
        from .components.xss_component import XSSView

        def xss_test_view(request):
            unsafe_input = request.GET.get('input', '')
            component = XSSView(unsafe_content=unsafe_input)
            return render(request, 'xss_test/xss_page.html', {'component': component})
        ```
    5. Create a template `xss_test/templates/xss_test/xss_page.html` to include the component:
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
            <h1>XSS Vulnerability Test</h1>
            {% unicorn component %}
        </body>
        </html>
        ```
    6. Add a URL pattern to `project/urls.py` to access the view:
        ```python
        from django.urls import path
        from xss_test.views import xss_test_view

        urlpatterns = [
            # ... other urls ...
            path('xss_test/', xss_test_view, name='xss_test'),
        ]
        ```
    7. Run the Django development server.
    8. As an attacker, craft a URL to the `xss_test_view` with a malicious JavaScript payload in the `input` parameter: `http://127.0.0.1:8000/xss_test/?input=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27)%3E`
    9. Open this URL in a web browser.
    10. Observe that an alert box with 'XSS' appears, demonstrating that the JavaScript code was executed. This confirms the XSS vulnerability because the input provided through the URL parameter, rendered as `unsafe_content` (marked as `safe`), was directly injected into the HTML and executed by the browser.

* Recommendation:
    - **Clearly document the security implications of using the `safe` Meta option.** Emphasize that it bypasses default XSS protection and should only be used with extreme caution. The current documentation does this adequately, but it could be made more prominent.
    - **Recommend and ideally provide helper functions or guidelines for developers to sanitize HTML content** before marking it as `safe`. Suggest using established HTML sanitization libraries in Python.
    - **Consider if there are any scenarios where Django Unicorn itself could provide built-in sanitization options** even when `safe` is used, perhaps through configuration or optional parameters. However, be mindful that automatic sanitization might break legitimate use cases for rendering unsanitized HTML. At a minimum, strong warnings and documentation are essential.
