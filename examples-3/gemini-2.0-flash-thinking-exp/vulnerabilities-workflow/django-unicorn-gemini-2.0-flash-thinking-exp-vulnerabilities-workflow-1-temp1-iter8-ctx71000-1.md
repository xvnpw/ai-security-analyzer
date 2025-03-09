## Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) due to Improper Use of `safe` Meta Option
- Description:
    1. A developer uses the `safe` Meta option in a Django Unicorn component to prevent HTML encoding for a specific component field.
    2. This field is intended to display user-generated content or data from an external source that is not properly sanitized.
    3. An attacker injects malicious JavaScript code into the user-generated content or external data source.
    4. When the Django Unicorn component renders, the malicious JavaScript code is included in the HTML output without proper encoding because the `safe` Meta option is enabled for the field.
    5. When a user views the page, the attacker's JavaScript code executes in their browser, potentially leading to account takeover, data theft, or other malicious actions.
- Impact: Execution of arbitrary JavaScript code in the victim's browser, leading to potential account compromise, sensitive data disclosure, or other malicious actions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML encodes all component field values to prevent XSS.
    - Developers must explicitly use the `safe` Meta option to disable HTML encoding for specific fields.
- Missing Mitigations:
    - No built-in sanitization or escaping mechanism is enforced when using the `safe` Meta option.
    - Lack of clear documentation warning against using `safe` with unsanitized user-controlled data and recommending proper sanitization methods. While documentation mentions using `safe` to opt-in to previous behavior, it does not explicitly warn against XSS risks in detail when used improperly.
- Preconditions:
    - A Django Unicorn component is implemented with a field that uses the `safe` Meta option.
    - This field displays user-generated content or data from an external source.
    - The developer does not implement proper sanitization of the data before rendering it in the component.
- Source Code Analysis:
    - In `django_unicorn\views.py` within the `UnicornView.render_component` method, the component's template is rendered. When rendering the template context, Django's template engine will use the `safe` filter if explicitly used in the template or if the `safe` attribute is listed in the `Meta` class of the `UnicornView`.
    - The documentation for `views.md` clearly states: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
    - If a developer incorrectly marks a field as `safe` which contains unsanitized user input, the HTML encoding is bypassed, leading to potential XSS.

- Security Test Case:
    1. Create a Django Unicorn component with a field named `unsafe_content` and add `safe = ("unsafe_content",)` to the `Meta` class.
    2. In the component's template, render the `unsafe_content` field: `{{ unsafe_content }}`.
    3. Create a view that renders a template containing this Unicorn component.
    4. In the component's view, set `unsafe_content` to a malicious JavaScript payload, for example: `<img src='x' onerror='alert(\"XSS Vulnerability\")'>`.
    5. Access the view in a web browser.
    6. Observe that the JavaScript alert `XSS Vulnerability` is executed, demonstrating the XSS vulnerability.

```html
<!-- template for test case -->
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

```python
# components.py for test case
from django_unicorn.components import UnicornView

class XssTestView(UnicornView):
    unsafe_content = ""

    def mount(self):
        self.unsafe_content = "<img src='x' onerror='alert(\"XSS Vulnerability\")'>"

    class Meta:
        safe = ("unsafe_content",)
```

**No New Vulnerabilities Found**
