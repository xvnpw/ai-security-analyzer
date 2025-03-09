- Vulnerability Name: Unsafe HTML Rendering with `safe` Meta Option or `|safe` template filter

- Description:
    1. A developer uses `Meta.safe` in a Django Unicorn component or the `|safe` template filter in a component's template to render a component property without HTML encoding.
    2. An attacker crafts malicious input, such as JavaScript code, and injects it into a component property that is marked as `safe`.
    3. When the component is rendered, Django Unicorn will not HTML-encode the malicious input because it is marked as `safe`.
    4. The attacker's malicious JavaScript code is executed in the victim's browser, leading to Cross-Site Scripting (XSS).

- Impact:
    Cross-Site Scripting (XSS). Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser. This can lead to:
    - Account takeover
    - Data theft
    - Redirection to malicious sites
    - Defacement of the website
    - Other malicious activities

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    Django Unicorn, by default, HTML-encodes updated field values to prevent XSS attacks. This is mentioned in `docs\source\views.md` and can be observed in the code where values are rendered in templates without explicit `safe` filter.

- Missing Mitigations:
    The project provides `Meta.safe` and `|safe` template filter to explicitly bypass HTML encoding. While this can be useful in specific scenarios where developers intentionally want to render HTML, it lacks clear guidance and warnings against using it with user-controlled data. Missing mitigations include:
    - **Documentation Warning**: Explicitly warn against using `Meta.safe` or `|safe` filter with user-controlled data in the documentation.
    - **Code Analysis/Linting**:  Potentially introduce a linting rule or code analysis tool to detect usage of `Meta.safe` and `|safe` filter in components that handle user inputs. (This might be too complex for a library to enforce).

- Preconditions:
    1. The developer must use `Meta.safe` in a Django Unicorn component's `Meta` class or use the `|safe` template filter in the component's template.
    2. The component property marked as `safe` must be directly or indirectly influenced by user input (e.g., through `unicorn:model` or arguments passed to actions).

- Source Code Analysis:
    1. **`docs\source\views.md`**:  The documentation explicitly mentions: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This indicates a conscious decision to allow unsafe rendering when explicitly requested.
    2. **`docs\source\templates.md`**: Mentions `unicorn` element attributes and model modifiers but does not explicitly warn about XSS implications of disabling HTML encoding.
    3. **`django_unicorn\components\unicorn_template_response.py`**: The `render` method in `UnicornTemplateResponse` class is responsible for rendering the component. It does not contain any explicit sanitization logic other than the default Django template engine's HTML encoding, which is bypassed when `safe` is used.
    4. **`django_unicorn\views\action_parsers\utils.py`**: The `set_property_value` function sets properties on the component but does not perform any sanitization.
    5. **`django_unicorn\utils.py`**: Contains `sanitize_html` function, but it's not automatically applied to all rendered content in components; it needs to be explicitly used.

    **Visualization:**

    ```
    User Input --> Component Property (marked as safe) --> Django Template (renders without encoding) --> Browser (executes malicious script)
    ```

- Security Test Case:
    1. Create a Django Unicorn component named `xss_component` in a Django app (e.g., `unicorn_xss_test`).
    2. Create a view class `XssView` for this component with a `message` property and set `class Meta: safe = ("message",)`.
    3. Create a template `unicorn/xss_component.html` with `<div id="xss-output">{{ message }}</div><input type="text" unicorn:model="message">`.
    4. Create a Django view and template to include the `xss_component`.
    5. Access the page in a browser.
    6. In the input field, enter malicious JavaScript code, for example: `<img src="x" onerror="alert('XSS Vulnerability!')">`.
    7. Observe that an alert box appears, demonstrating successful XSS.

    **Code Example (component: `unicorn_xss_test/components/xss_component.py`):**
    ```python
    from django_unicorn.components import UnicornView

    class XssView(UnicornView):
        message = ""

        class Meta:
            safe = ("message",)
    ```

    **Code Example (template: `unicorn_xss_test/templates/unicorn/xss_component.html`):**
    ```html
    <div>
        <div id="xss-output">{{ message }}</div>
        <input type="text" unicorn:model="message">
    </div>
    ```

    **Code Example (view to include component in `unicorn_xss_test/views.py`):**
    ```python
    from django.shortcuts import render
    from django.views.generic import TemplateView

    class XssTestView(TemplateView):
        template_name = "xss_test.html"

    def xss_test_view(request):
        return XssTestView.as_view()(request)
    ```

    **Code Example (template to include component `unicorn_xss_test/templates/xss_test.html`):**
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss' %}
    </body>
    </html>
    ```

This vulnerability highlights the importance of developer education and secure coding practices when using features that bypass default security mechanisms. While Django Unicorn provides default XSS protection, explicit unsafe rendering options require careful handling to avoid vulnerabilities.
