### Vulnerability List

- Vulnerability: Potential Cross-Site Scripting (XSS) due to Misuse of `Meta.safe`

- Description:
    - A developer can declare fields in a Django Unicorn component's `Meta.safe` list.
    - The `_process_component_request` function in `django_unicorn\views\__init__.py` iterates through `Meta.safe` fields and marks the corresponding attributes as safe using `mark_safe` before rendering the component.
    - If a developer mistakenly adds a field to `Meta.safe` that contains user-controlled data without proper sanitization, it can lead to a Cross-Site Scripting (XSS) vulnerability.
    - An attacker can inject malicious JavaScript code into this user-controlled data.
    - When the component is rendered, the injected JavaScript code will be executed in the victim's browser because the field is marked as safe and not escaped by the template engine.

- Impact:
    - High
    - Cross-Site Scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser in the context of the web application.
    - This can lead to various malicious actions, including:
        - Account takeover by stealing session cookies or credentials.
        - Defacement of the website.
        - Redirection of the user to malicious websites.
        - Data theft or manipulation.
        - Installation of malware.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - There are no explicit mitigations in the django-unicorn project to prevent developers from misusing `Meta.safe`.
    - The documentation does not explicitly warn against adding user-controlled, unsanitized data to `Meta.safe`.

- Missing Mitigations:
    - Documentation should be added to clearly warn developers about the security implications of using `Meta.safe`.
    - The documentation should emphasize that `Meta.safe` should only be used for fields that are known to be safe and do not contain user-controlled data or that user-controlled data must be properly sanitized before being assigned to a `Meta.safe` field.
    - Consider adding a security check or warning during development or testing if `Meta.safe` is used with fields that are directly updated from user input without sanitization. (This might be too complex and introduce false positives).

- Preconditions:
    - A developer must create a Django Unicorn component and incorrectly add a field to `Meta.safe` that is updated with user-controlled data without proper sanitization.
    - An attacker must be able to control the data that is bound to this component field, typically via `syncInput` action.

- Source Code Analysis:
    - File: `django_unicorn\views\__init__.py`
    - Function: `_process_component_request`
    ```python
    # django_unicorn\views\__init__.py
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
    - The code iterates through the `safe_fields` list, which is populated from `component.Meta.safe`.
    - For each field in `safe_fields`, it retrieves the attribute value using `getattr` and marks it as safe using `mark_safe` if the value is a string.
    - `mark_safe` tells Django's template engine not to escape this string, which can lead to XSS if the string contains malicious JavaScript code.

- Security Test Case:
    1. Create a new Django Unicorn component named `xss_component` in `example/unicorn/components/xss_component.py` with the following content:
    ```python
    # example/unicorn/components/xss_component.py
    from django_unicorn.components import UnicornView

    class XSSView(UnicornView):
        template_name = "unicorn/xss.html"
        text = ""

        class Meta:
            safe = ["text"]
    ```
    2. Create a template `unicorn/xss.html` in `example/unicorn/templates/unicorn/xss.html` with the following content:
    ```html
    {# example/unicorn/templates/unicorn/xss.html #}
    <div id="xss-component">
        <div id="text-output">{{ text }}</div>
    </div>
    ```
    3. Add a URL path to `example/project/urls.py` to render this component directly:
    ```python
    # example/project/urls.py
    from django.urls import include, path
    from unicorn.components.hello_world import HelloWorldView
    from unicorn.components.xss_component import XSSView # Add import

    urlpatterns = [
        # ...
        path("test", HelloWorldView.as_view(), name="test"),
        path("xss-test", XSSView.as_view(), name="xss-test"), # Add path
    ]
    ```
    4. Create a test case in `tests/views/test_xss.py` to simulate an XSS attack:
    ```python
    # tests/views/test_xss.py
    from tests.views.message.utils import post_and_get_response

    XSS_COMPONENT_URL = "/unicorn/message/unicorn.components.xss_component.XSSView"

    def test_xss_vulnerability(client):
        """
        Test for potential XSS vulnerability when Meta.safe is misused.
        """
        payload = "<img src='x' onerror='alert(\"XSS Vulnerability\")'>"
        data = {"text": payload}
        action_queue = [
            {
                "payload": {"name": "text", "value": payload},
                "type": "syncInput",
            }
        ]
        response = post_and_get_response(
            client,
            url=XSS_COMPONENT_URL,
            data=data,
            action_queue=action_queue,
        )

        assert not response.get("error")
        assert not response["errors"]

        # To manually verify, render the component in browser and check for alert box.
        # Or you can parse the rendered HTML and check if the payload is present without escaping.
        rendered_dom = response["dom"]
        assert payload in rendered_dom
    ```
    5. Run the test case: `pytest tests/views/test_xss.py`
    6. Observe that the test case, when manually inspected, will show that the XSS payload is rendered without escaping, and if rendered in a browser, will execute the `alert("XSS Vulnerability")` JavaScript code, proving the vulnerability.
