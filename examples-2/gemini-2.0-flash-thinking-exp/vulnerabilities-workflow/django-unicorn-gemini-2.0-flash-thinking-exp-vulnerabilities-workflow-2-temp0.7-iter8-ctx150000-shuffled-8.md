### Vulnerability List

* Vulnerability Name: Unsafe HTML rendering in templates due to misuse of `safe` Meta option

* Description:
    1. A developer creates a Django Unicorn component and defines a property that can be updated via `syncInput` from the client.
    2. In the component's `Meta` class, the developer mistakenly adds this property's name to the `safe` tuple. This is intended for properties that are already sanitized and safe to render as HTML, but in this case, the property might receive unsanitized user input.
    3. The component's template renders this property's value without further escaping.
    4. An attacker crafts a malicious `syncInput` request that includes JavaScript code in the `value` for the vulnerable property.
    5. When the server processes the request, it updates the component's property with the malicious payload because it's marked as `safe`.
    6. The server then renders the component's template, including the malicious JavaScript code directly into the HTML because the `safe` option bypasses HTML escaping for this property.
    7. The browser executes the embedded JavaScript code, leading to Cross-Site Scripting (XSS).

* Impact:
    - Cross-Site Scripting (XSS). An attacker can execute arbitrary JavaScript code in the context of the user's browser when they view the page containing the vulnerable component. This can lead to session hijacking, defacement, redirection to malicious sites, or other malicious actions.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The project provides a `safe` Meta option in `UnicornView` components to allow developers to mark specific properties as safe for HTML rendering, bypassing automatic HTML escaping.
    - HTML escaping is applied by default to component properties when rendering templates to prevent XSS.
    - Test case `test_safe_html_entities_not_encoded` in `test_process_component_request.py` demonstrates the behavior of the `safe` option.

* Missing Mitigations:
    - There is no mechanism to prevent developers from mistakenly adding properties that receive user input to the `safe` tuple.
    - No warnings or checks are in place to highlight potentially unsafe usage of the `safe` option.
    - The documentation should strongly emphasize the security implications of using the `safe` option and provide clear guidelines on when and how to use it safely.

* Preconditions:
    - A Django Unicorn component exists with a property that is:
        - Updatable via `syncInput`.
        - Mistakenly marked as `safe` in the component's `Meta` class.
        - Rendered in the component's template without additional HTML escaping.

* Source Code Analysis:
    1. **`django_unicorn/components/unicorn_template_response.py`**: This file is responsible for rendering the component template. It uses Django's template engine, which by default auto-escapes HTML. However, the `safe` filter or `mark_safe` can bypass this escaping. In the context of django-unicorn, the `safe` Meta option in components dictates when escaping is bypassed.
    2. **`django_unicorn/views/test_process_component_request.py`**:
        - `test_html_entities_encoded`: Shows that by default, HTML entities are encoded when a property is updated via `syncInput`.
        - `test_safe_html_entities_not_encoded`: Demonstrates that when a property is listed in `Meta.safe`, HTML entities are *not* encoded.
    3. **`django_unicorn/components/unicorn_view.py`**: The `UnicornView` class handles component logic. The `Meta.safe` option is used to determine which properties should be considered safe. When rendering the template, if a property is in `safe`, its value will be rendered as is, without escaping.

* Security Test Case:
    1. Create a new Django Unicorn component named `unsafe_component` in `example/unicorn/components/unsafe_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class UnsafeComponentView(UnicornView):
        template_name = "unicorn/unsafe_component.html"
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",) # Mistakenly mark 'unsafe_data' as safe

        def set_unsafe_data(self, value):
            self.unsafe_data = value
    ```
    2. Create a template for the component at `example/unicorn/templates/unsafe_component.html`:
    ```html
    <div>
        <div id="unsafe-content">
            {{ unsafe_data }} {# Render 'unsafe_data' without further escaping #}
        </div>
        <button unicorn:click="set_unsafe_data('Clicked!')">Click Me</button>
        <button unicorn:click="set_unsafe_data('<script>alert(\'XSS Vulnerability!\')</script>')">Trigger XSS</button>
    </div>
    ```
    3. Add a URL route to include this component in `example/www/urls.py`:
    ```python
    from django.urls import path
    from example.unicorn.components.unsafe_component import UnsafeComponentView

    urlpatterns = [
        # ... other paths ...
        path("unsafe-component", UnsafeComponentView.as_view(), name="unsafe-component"),
    ]
    ```
    4. Access the `unsafe-component` view in a browser.
    5. Click the "Trigger XSS" button.
    6. Observe that a JavaScript alert box appears with the message "XSS Vulnerability!". This confirms that the JavaScript code injected via `syncInput` was executed because the `unsafe_data` property was marked as `safe` and rendered without escaping in the template.

This test case demonstrates how misusing the `safe` Meta option can lead to a High severity XSS vulnerability.
