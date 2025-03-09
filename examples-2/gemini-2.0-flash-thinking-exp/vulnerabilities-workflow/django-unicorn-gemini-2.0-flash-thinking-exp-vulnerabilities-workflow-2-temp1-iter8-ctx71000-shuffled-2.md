### Vulnerability List:

- Vulnerability Name: Cross-Site Scripting (XSS) via `Meta.safe` attribute misuse

- Description:
    - A developer might incorrectly use the `Meta.safe` attribute in a Django Unicorn component to mark a component's field as safe, believing it will handle sanitization or when they intend to render raw HTML.
    - If this field is then populated with user-controlled data that is not explicitly sanitized by the developer *before* being assigned to the component's field, it can lead to Cross-Site Scripting (XSS).
    - An attacker can inject malicious JavaScript code into the user-controlled data, for example, by manipulating query parameters, form inputs, or other client-side data sources that feed into the component's properties via mechanisms like `syncInput` actions (as demonstrated in `test_process_component_request.py`).
    - When the component renders the template, and the vulnerable field is used in the template (likely without the `safe` template filter because `Meta.safe` is already applied in component context during rendering), the injected JavaScript code will be executed in the victim's browser. The test `test_safe_html_entities_not_encoded` in `test_process_component_request.py` explicitly shows that fields marked as `safe` are rendered without HTML encoding, confirming the XSS risk if unsanitized user input is used.

- Impact:
    - Successful exploitation of this vulnerability can lead to Cross-Site Scripting (XSS).
    - An attacker can execute arbitrary JavaScript code in the victim's browser in the context of the vulnerable web application.
    - This can lead to various malicious actions, including:
        - Stealing user session cookies, leading to account hijacking.
        - Redirecting users to malicious websites.
        - Defacing the web page.
        - Phishing attacks by displaying fake login forms.
        - Performing actions on behalf of the user without their consent.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Django Unicorn framework by default HTML encodes updated field values to prevent XSS. This default behavior is demonstrated in `test_html_entities_encoded` test case from `test_process_component_request.py`, showcasing that without `Meta.safe`, HTML entities are encoded.
    - Developers need to explicitly use `Meta.safe` to prevent HTML encoding for specific fields. This explicit action is intended to be a conscious decision for cases where raw HTML rendering is required and trusted, but it shifts the responsibility of sanitization to the developer. Mitigation (default encoding) is implemented in `django_unicorn/components/unicorn_view.py` in `serialize_value` method and the bypass using `Meta.safe` is also configured there and used in template rendering context in `django_unicorn/views/__init__.py` in `_process_component_request` function where `mark_safe` is applied to fields listed in `Meta.safe`.

- Missing Mitigations:
    - No built-in mechanism to automatically sanitize data even when `Meta.safe` is used. The framework relies solely on the developer to perform sanitization when using `Meta.safe`.
    - Lack of prominent and clear guidance in documentation that emphasizes the *developer's responsibility* to sanitize user input when using `Meta.safe`. While the documentation may warn about security implications, it needs to explicitly detail recommended sanitization methods and best practices, rather than just stating the risk.

- Preconditions:
    - A Django Unicorn component uses `Meta.safe` attribute for a field.
    - The field marked as `safe` is populated with user-controlled data, potentially through component updates via WebSocket messages and `syncInput` actions as demonstrated in `test_process_component_request.py`.
    - The user-controlled data is not sanitized by the developer before being assigned to the component field.
    - The template renders the field value without further escaping (which is the expected behavior when `Meta.safe` is used, as shown in `test_safe_html_entities_not_encoded`).

- Source Code Analysis:
    - In `django_unicorn/components/unicorn_view.py`, the `_get_component_context` method prepares the context for rendering the component template, and `serialize_value` function is used to process the component's attributes.
    - If a field is listed in `Meta.safe`, `mark_safe` from `django.utils.html` is applied, bypassing Django's automatic HTML escaping.

    ```python
    # django_unicorn/components/unicorn_view.py
    def serialize_value(self, name: str, value: Any) -> Any:
        # ...
        if getattr(meta, "safe", None) and name in meta.safe:
            return mark_safe(value)
        # ...
    ```
    - In `django_unicorn/views/__init__.py`, within the `_process_component_request` function, after the component is processed and before rendering, the code iterates through `safe_fields` and applies `mark_safe`.
    ```python
    # django_unicorn/views/__init__.py
    def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
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
        # ...
    ```

    - This code snippet from `django_unicorn/components/unicorn_view.py` shows that if `safe` is defined in `Meta` and the current field `name` is in the `safe` tuple, the value is marked as safe using `mark_safe`.
    - The template will then render this value without escaping, making it vulnerable to XSS if the value contains malicious code, as further confirmed by the test cases in `test_process_component_request.py`.

- Security Test Case:
    1. Create a Django Unicorn component with a field named `unsafe_content` and mark it as `safe` in `Meta`:

    ```python
    # components/unsafe_component.py
    from django_unicorn.components import UnicornView

    class UnsafeComponentView(UnicornView):
        unsafe_content = ""

        class Meta:
            safe = ("unsafe_content",)
    ```

    2. Create a template for this component that renders `unsafe_content`:

    ```html
    <!-- templates/unicorn/unsafe-component.html -->
    <div>
        {{ unsafe_content }}
    </div>
    ```

    3. Create a Django view that includes this component and allows user input to be passed to the `unsafe_content` field (e.g., via query parameters or a form):

    ```python
    # views.py
    from django.shortcuts import render
    from .components.unsafe_component import UnsafeComponentView

    def unsafe_view(request):
        unsafe_input = request.GET.get('input', '')
        component = UnsafeComponentView()
        component.unsafe_content = unsafe_input
        return render(request, 'unsafe_template.html', {'component': component})
    ```

    4. Create a Django template `unsafe_template.html` to render the component:

    ```html
    <!-- templates/unsafe_template.html -->
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn component %}
    </body>
    </html>
    ```

    5. Run the Django development server.
    6. Access the `unsafe_view` with a malicious payload in the `input` query parameter: `http://127.0.0.1:8000/unsafe-view/?input=<img src=x onerror=alert('XSS Vulnerability')>`
    7. Observe that an alert box with "XSS Vulnerability" is displayed in the browser, demonstrating successful XSS exploitation because the malicious `<img src=x onerror=alert('XSS Vulnerability')>` payload provided via the `input` parameter was executed. This test case is directly analogous to the scenario tested in `test_safe_html_entities_not_encoded` but adapted for a full browser-based test.
