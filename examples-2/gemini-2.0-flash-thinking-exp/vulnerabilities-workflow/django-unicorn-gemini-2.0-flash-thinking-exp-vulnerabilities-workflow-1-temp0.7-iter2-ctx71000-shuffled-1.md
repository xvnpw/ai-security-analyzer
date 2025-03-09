### Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe String Rendering

* Description:
    1. An attacker can inject malicious JavaScript code into a component's property.
    2. If the developer uses the `safe` meta option in the component or `safe` template filter in the template for this property, the injected JavaScript code will be rendered without proper escaping.
    3. When a user interacts with the component or the component is re-rendered, the malicious JavaScript code will be executed in the user's browser.

* Impact:
    - Account takeover: An attacker could steal session cookies or other sensitive information, leading to account compromise.
    - Data theft: Malicious scripts can be used to extract data from the page and send it to a remote server controlled by the attacker.
    - Defacement: The attacker can modify the content of the web page, redirect users to malicious websites, or perform other unwanted actions.
    - Full control of the user's browser within the context of the vulnerable web application.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - By default, django-unicorn HTML-encodes updated field values to prevent XSS attacks. This is implemented in the `sanitize_html` function in `django_unicorn.utils.py` and used in `django_unicorn.components.unicorn_template_response.py` during template rendering.
    - Developers must explicitly use the `safe` meta option or the `safe` template filter to render unescaped content. This mechanism is intended as a mitigation, requiring explicit developer action to disable default escaping. The `safe` meta option is handled in `django_unicorn.views.__init__.py` in the `_process_component_request` function where safe attributes are marked using `mark_safe`.

* Missing Mitigations:
    - Clear documentation and warnings about the risks of using `safe` and when it is appropriate. Currently, documentation exists in `docs\source\views.md` and `docs\source\templates.md`, but it may not be prominent enough.
    - Security focused code examples that emphasize secure practices. Examples should consistently demonstrate safe practices and highlight the risks of using `safe`.
    - Potential for static analysis tools or linters to detect usage of `safe` and flag potential risks. No such tools or linters are currently implemented.

* Preconditions:
    - A django-unicorn component has a property that renders user-controlled string data into the template.
    - The developer has used `Meta.safe` or the `safe` template filter for this property, intending to render HTML but inadvertently allowing JavaScript execution.
    - An attacker is able to control or influence the string data that is rendered by the component.

* Source Code Analysis:
    1. **`django_unicorn\utils.py`**: The `sanitize_html` function uses `html.translate(_json_script_escapes)` to escape HTML special characters. This function is used by default to prevent XSS.
    2. **`django_unicorn\components\unicorn_template_response.py`**: The `UnicornTemplateResponse.render` method renders the component and uses `BeautifulSoup` to manipulate the DOM. The `_desoupify` method, which is called at the end of `render`, uses `formatter=UnsortedAttributes()` and `soup.encode()` which by default will HTML-encode special characters unless explicitly bypassed.
    3. **`django_unicorn\views\__init__.py`**: In `_process_component_request`, after component actions are processed and before rendering, the code checks for `Meta.safe` attributes. If a property is listed in `Meta.safe`, it is marked as safe using `mark_safe(value)`. This bypasses the default HTML escaping when the template is rendered.
    4. **`tests\views\test_process_component_request.py`**: `test_html_entities_encoded` confirms that by default, HTML entities are encoded. `test_safe_html_entities_not_encoded` confirms that when `Meta.safe` is used, HTML entities are not encoded, demonstrating the intended but potentially risky behavior.

* Security Test Case:
    1. Create a django-unicorn component named `XssTestComponent` in `example/unicorn/components/xss_test.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        unsafe_string = ""

        class Meta:
            safe = ("unsafe_string",)
    ```
    2. Create a template for the component at `example/unicorn/templates/xss-test.html`:
    ```html
    <div>
        <input type="text" unicorn:model="unsafe_string">
        <div id="output" unicorn:id="xss-output">{{ unsafe_string }}</div>
    </div>
    ```
    3. Create a URL pattern in `example/project/urls.py` to render this component:
    ```python
    from django.urls import path
    from example.unicorn.components.xss_test import XssTestView
    from django_unicorn.views import render_component

    urlpatterns = [
        path('xss-test/', render_component, name='xss_test'),
    ]
    ```
    4. Access the component in a browser by navigating to `/xss-test/`.
    5. In the input field, enter the following malicious payload: `<img src=x onerror=alert('XSS')>`.
    6. Click outside the input field or trigger an update to the component (e.g., by adding a button that triggers an action).
    7. Observe that a JavaScript alert box appears with the message "XSS", demonstrating successful execution of injected JavaScript code.
