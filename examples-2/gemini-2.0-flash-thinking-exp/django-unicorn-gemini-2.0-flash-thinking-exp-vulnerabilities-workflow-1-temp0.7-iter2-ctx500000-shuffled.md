## Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via Template Injection in Component Rendering

* Description:
    1. An attacker can manipulate component data that gets rendered into the HTML template without proper sanitization.
    2. Specifically, when a component re-renders after an AJAX request, updated field values are directly inserted into the DOM.
    3. If these values are not properly HTML-encoded, and contain malicious JavaScript code, it will be executed in the user's browser.
    4. This can be triggered by injecting malicious JavaScript code into any component field that is then displayed in the template. For example, a text input field bound to a component variable using `unicorn:model`.
    5. When an action occurs (e.g., button click) or model is updated, the component re-renders, and the malicious script from the component data is injected into the DOM, leading to XSS.

* Impact:
    * Critical. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser when they interact with the vulnerable component.
    * This can lead to session hijacking, cookie theft, redirection to malicious sites, defacement, or other malicious actions performed in the context of the user's session.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    * HTML encoding is applied to updated field values by default to prevent XSS attacks. This is mentioned in `changelog.md` for version 0.36.0 and in `views.md`.
    * The `sanitize_html` function in `django_unicorn\utils.py` and usage in `UnicornTemplateResponse` in `_json_tag.string = sanitize_html(init)` suggest an attempt to sanitize initial data.

* Missing Mitigations:
    * While HTML encoding is applied, it appears to be bypassed or insufficient in certain scenarios, particularly during component re-rendering where dynamically updated data from the component's backend is inserted into the template. The provided code does not consistently sanitize all dynamic content before inserting it into the DOM during updates. The `safe` meta class option in `views.md` explicitly allows bypassing encoding, indicating a potential weakness if misused or if default encoding is insufficient.

* Preconditions:
    * The application must be using django-unicorn and have a component that renders user-controlled data without adequate sanitization during updates.
    * An attacker needs to find a component where they can influence data that is rendered in the template.

* Source Code Analysis:
    1. **File: `django_unicorn\views\message.py`**: This view handles incoming messages and processes actions. The `_process_component_request` function is key.
    2. **File: `django_unicorn\views\__init__.py`**: The `message` function in `django_unicorn\views\__init__.py` is the main entry point for AJAX requests. It calls `_process_component_request`.
    3. **File: `django_unicorn\views\__init__.py`**: Inside `_process_component_request`, the component is rendered using `component.render(request=request)`.
    4. **File: `django_unicorn\components\unicorn_template_response.py`**: `UnicornTemplateResponse.render` method is responsible for rendering the component and updating the DOM.
    5. **File: `django_unicorn\components\unicorn_template_response.py`**: In `UnicornTemplateResponse.render`, `root_element["unicorn:data"] = frontend_context_variables` and `root_element["unicorn:calls"] = orjson.dumps(self.component.calls).decode("utf-8")` inject data into the root element attributes, which are then processed by the frontend JavaScript.
    6. **File: `django_unicorn\components\unicorn_template_response.py`**: The JavaScript initialization code is added using `init_script = f"Unicorn.componentInit(JSON.parse(document.getElementById('{json_element_id}').textContent));"`. This script is then embedded in the template.
    7. **File: `django_unicorn\templatetags\unicorn.py`**: The `unicorn` template tag renders the component.
    8. **File: `django_unicorn\utils.py`**: `sanitize_html` function is used to sanitize HTML, but its usage in `UnicornTemplateResponse` seems limited to the initial JSON data.
    9. **Vulnerability Point**: The core vulnerability lies in how `django-unicorn` updates the DOM with potentially unsanitized data during AJAX updates. While initial data might be sanitized to some extent using `sanitize_html` when setting up the component initially, the subsequent dynamic updates driven by user interactions and server responses may not be consistently sanitized before being morphed into the DOM. This is especially critical when considering how JavaScript frameworks interact with and interpret data within DOM attributes or elements. If an attacker can inject malicious content into component variables (e.g., through `unicorn:model` or server-side data manipulation), and those variables are used in templates without explicit and robust encoding during AJAX updates, XSS is possible. The `safe` meta option further highlights the risk, as it allows developers to explicitly disable the default encoding, potentially leading to vulnerabilities if used improperly.

* Security Test Case:
    1. Create a django-unicorn component with a variable `name` and a template that renders this variable:
    ```python
    # components/xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        name = ""
    ```
    ```html
    <!-- templates/unicorn/xss-test.html -->
    <div>
        <input type="text" unicorn:model="name" id="nameInput">
        <div id="nameDisplay">{{ name }}</div>
    </div>
    ```
    2. Create a Django view to render this component in a template:
    ```python
    # views.py
    from django.shortcuts import render
    from .components.xss_test import XssTestView

    def xss_test_view(request):
        return render(request, 'xss_test.html')
    ```
    ```html
    <!-- templates/xss_test.html -->
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
    3. Access the page in a browser.
    4. In the input field, enter the following payload: `<img src=x onerror=alert('XSS')>`
    5. Click outside the input field or trigger an update to the component (e.g., by adding a button with an action).
    6. Observe if the JavaScript alert `XSS` is executed. If the alert box appears, the XSS vulnerability is confirmed.

* Missing Mitigations:
    * Implement consistent and robust HTML encoding for all dynamic data rendered in component templates, especially during AJAX updates. Ensure that even if `safe` is used, there are clear warnings and documentation about the risks.
    * Review and strengthen sanitization processes within django-unicorn to prevent XSS in all scenarios, including dynamically updated content. Consider using a Content Security Policy (CSP) as an additional layer of defense.
    * Provide security guidelines for developers on how to properly handle user input and prevent XSS when using django-unicorn, emphasizing the importance of encoding user-generated content in templates, even when using django-unicorn's features.
