### 1. Vulnerability Name: Improper use of `safe` Meta attribute leading to Cross-Site Scripting (XSS)

- **Description:**
    1. A developer uses Django Unicorn and wants to render user-provided content without HTML encoding within a Unicorn component.
    2. To achieve this, they incorrectly apply the `safe` Meta attribute to a component field, believing it will sanitize user input or indicate that the component handles sanitization.
    3. However, the `safe` Meta attribute in Django Unicorn only prevents *output* encoding of the field's value in the template. It does *not* sanitize user input, nor does it imply that the component handles sanitization.
    4. An attacker provides malicious JavaScript code as user input for this field.
    5. When the component re-renders (e.g., after a user interaction or poll update), the template renders the malicious JavaScript code directly into the HTML, bypassing browser-based XSS protection because Django Unicorn has marked the output as `safe`.
    6. The attacker's JavaScript code then executes in the victim's browser, leading to Cross-Site Scripting (XSS).

- **Impact:**
    - **High**
    - Cross-Site Scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, defacement, or other malicious actions performed in the context of the user's session.
    - If an administrator account is compromised, it can lead to a full website takeover.

- **Vulnerability Rank:**
    - **High**

- **Currently Implemented Mitigations:**
    - By default, Django Unicorn HTML-encodes all output to prevent XSS, as introduced in version 0.36.0 (CVE-2021-42053). This is a global mitigation.
    - The documentation for `Meta.safe` ([views.md#safe](views.md#safe)) explains that this attribute *disables* HTML encoding for specific fields, explicitly warning about the security implications and requiring developers to handle sanitization themselves.

- **Missing Mitigations:**
    - No explicit code-level sanitization is automatically applied by Django Unicorn to user inputs before rendering, even when the `safe` Meta attribute is not used. Django Unicorn relies on Django's default template autoescaping and the developer's correct usage of `safe`.
    - There are no warnings or checks in the code to detect potentially unsafe usage of the `safe` Meta attribute, especially if developers misunderstand its purpose.

- **Preconditions:**
    1. A Django Unicorn component renders user-provided input from a field marked as `safe` in the component's Meta class.
    2. The developer incorrectly assumes that the `safe` Meta attribute sanitizes input or indicates that the component handles sanitization.
    3. The developer does not implement any other form of input sanitization for this field.
    4. An attacker can control the user-provided input for this specific field.

- **Source Code Analysis:**
    - **File:** `django_unicorn\views\unicorn_template_response.py`
    - **Function:** `UnicornTemplateResponse.render()`
    - **Code Snippet:**
      ```python
      # File: django_unicorn\django_unicorn\views\unicorn_template_response.py
      # ...
              # Mark safe attributes as such before rendering
              for field_name in safe_fields:
                  value = getattr(component, field_name)
                  if isinstance(value, str):
                      setattr(component, field_name, mark_safe(value))  # noqa: S308
      # ...
      response.content = rendered_template
      ```
    - **Analysis:**
        1. The code iterates through `safe_fields` defined in the component's `Meta` class.
        2. For each field name in `safe_fields`, it retrieves the corresponding value from the component.
        3. If the value is a string, it marks it as safe using `django.utils.safestring.mark_safe`.
        4. `mark_safe` tells Django templates *not* to escape this value during rendering.
        5. **Vulnerability:** If a developer adds a field to `Meta.safe` that contains unsanitized user input, this input will be rendered directly into the HTML without encoding, enabling XSS.
        6. **Visualization:**
           ```
           User Input --> Component Field (marked as safe) --> Template Rendering (no encoding) --> Browser (XSS)
           ```

- **Security Test Case:**
    1. Create a Django Unicorn component named `xss_safe_component` with a field `unsafe_content` and mark it as `safe` in the `Meta` class.
        ```python
        # components/xss_safe_component.py
        from django_unicorn.components import UnicornView

        class XssSafeComponentView(UnicornView):
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
    2. Create a template `unicorn/xss_safe_component.html` that renders the `unsafe_content` field:
        ```html
        # templates/unicorn/xss_safe_component.html
        <div>
            <input type="text" unicorn:model="unsafe_content" />
            <div id="xss-test">{{ unsafe_content }}</div>
        </div>
        ```
    3. Create a Django view and template to include the `xss_safe_component`.
        ```python
        # views.py
        from django.shortcuts import render
        from django.views.generic import TemplateView

        class XSSView(TemplateView):
            template_name = 'xss_test.html'

        # urls.py
        from django.urls import path
        from .views import XSSView
        from unicorn.components.xss_safe_component import XssSafeComponentView

        urlpatterns = [
            path("xss-safe/", XSSView.as_view(), name="xss_safe"),
        ]
        ```
        ```html
        # templates/xss_test.html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            <h1>XSS Test</h1>
            {% unicorn 'xss-safe' %}
        </body>
        </html>
        ```
    4. Run the Django development server.
    5. Open the `xss-safe` view in a browser (e.g., `http://127.0.0.1:8000/xss-safe/`).
    6. In the input field, enter the following XSS payload: `<img src=x onerror=alert('XSS Vulnerability!')>`
    7. Click outside the input field to trigger a component update (or use `unicorn:model.lazy`).
    8. **Expected Result:** An alert box with "XSS Vulnerability!" should appear in the browser, demonstrating that the JavaScript code from the input was executed. This proves the XSS vulnerability due to the improper use of `safe` and lack of sanitization.
