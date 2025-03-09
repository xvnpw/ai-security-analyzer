- Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe Template Rendering
- Description:
  1. An attacker can inject malicious JavaScript code into a component's property.
  2. A developer, intending to render dynamic content without escaping, incorrectly uses the `safe` meta attribute in the component's `Meta` class or the `safe` template filter on a property that is influenced by user input.
  3. When the component is rendered or updated, the injected JavaScript code is executed in the user's browser because the output is not properly sanitized due to the `safe` setting.
- Impact:
  - Critical. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser. This can lead to account takeover, data theft, session hijacking, redirection to malicious sites, or defacement of the application.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
  - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks. This is a general mitigation to prevent XSS in most cases.
  - The documentation highlights the security implications of using `safe` and advises caution.
- Missing Mitigations:
  - No explicit mechanism to prevent developers from using `safe` on user-controlled input without proper sanitization.
  - No built-in mechanism to automatically sanitize data even when `safe` is used (if that is even desired behavior).
  - Lack of code analysis or linting tools to detect potentially unsafe usage of `safe`.
- Preconditions:
  - A developer must use the `safe` meta attribute or `safe` template filter.
  - The property marked as `safe` must be directly or indirectly influenced by user-provided input.
  - The application must render a component containing this property to a victim user's browser.
- Source Code Analysis:
  1. **`docs\source\views.md`**: This documentation file describes the `Meta.safe` option: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This clearly indicates that `safe` disables the default XSS protection.
  2. **`docs\source\templates.md`**: Mentions "Ignore elements" `unicorn:ignore` which might have implications on DOM updates but not directly related to XSS.
  3. **`docs\source\changelog.md`**:  Indicates a previous XSS fix CVE-2021-42053 and reinforces that responses are now HTML encoded by default. This reinforces the importance of HTML encoding and the potential risk when it's bypassed.
  4. **`django_unicorn\views\__init__.py`**: In the `_process_component_request` function, the code iterates through `safe_fields` and marks the corresponding attributes as safe using `mark_safe(value)`. This confirms that the `safe` meta attribute directly bypasses HTML encoding.
     ```python
     # django_unicorn\views\__init__.py
     # ...
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
     This code snippet shows that if a field name is listed in the `safe` tuple within the component's `Meta` class and the field's value is a string, it will be marked as safe using Django's `mark_safe` function before rendering. `mark_safe` tells Django templates not to escape this string, thus bypassing the default HTML encoding and potentially leading to XSS if the content is user-controlled and not properly sanitized before being assigned to the `safe` field.
  5. **`tests\views\test_process_component_request.py`**: This test file contains `test_safe_html_entities_not_encoded` which explicitly tests and confirms that HTML entities are not encoded when `safe` is used, reinforcing the vulnerability.

- Security Test Case:
  1. Create a Django Unicorn component named `xss_component` in a Django application.
  2. In `xss_component.py`, define a component view with a property `unsafe_data` and include `safe = ("unsafe_data",)` in the `Meta` class:
     ```python
     # xss_component.py
     from django_unicorn.components import UnicornView

     class XssComponentView(UnicornView):
         unsafe_data = ""

         class Meta:
             safe = ("unsafe_data", )
     ```
  3. In `xss_component.html`, render the `unsafe_data` property:
     ```html
     {# xss_component.html #}
     <div>
         <div id="xss-target">
             {{ unsafe_data }}
         </div>
         <input type="text" unicorn:model="unsafe_data">
     </div>
     ```
  4. Include the `xss_component` in a Django template that is accessible to an external attacker:
     ```html
     {# index.html #}
     {% load unicorn %}
     <html>
     <head>
         {% unicorn_scripts %}
     </head>
     <body>
         {% csrf_token %}
         {% unicorn 'xss-component' %}
     </body>
     </html>
     ```
  5. Run the Django application.
  6. As an attacker, access the page in a browser that renders `index.html`.
  7. In the input field associated with `unsafe_data`, type in the following payload: `<img src=x onerror="alert('XSS Vulnerability')">`.
  8. Click outside the input field or trigger an update to send the payload to the server (e.g., by adding an action button).
  9. Observe that an alert box appears in the browser with the message "XSS Vulnerability". This confirms that the JavaScript code injected via `unsafe_data` was executed because HTML encoding was bypassed due to `safe` setting, and no further sanitization was performed.
  10. If the alert box appears, the XSS vulnerability is confirmed.

- Vulnerability Name: HTML Injection via Attribute Manipulation
- Description:
  1. An attacker can manipulate attributes of HTML elements within a Django Unicorn component's template by controlling component properties.
  2. When a component re-renders due to user interaction or data updates, the attributes of HTML elements are updated based on the component's properties.
  3. If a developer dynamically sets HTML attributes based on user-controlled component properties without proper sanitization, an attacker can inject arbitrary HTML attributes, including event handlers like `onload`, `onerror`, or `onmouseover`.
  4. When the component is rendered or updated in the user's browser, the injected HTML attributes are included in the DOM, and if they are event handlers containing JavaScript code, they will be executed.
- Impact:
  - High. Successful exploitation allows an attacker to inject arbitrary HTML attributes, leading to potential execution of malicious JavaScript code in the context of the victim's browser if event handler attributes are injected. This can result in actions similar to XSS, such as data theft or redirection, although it might be less critical than full XSS due to potential context and execution limitations of HTML attribute-based injection.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
  - Django Unicorn, by default, HTML-encodes the content of the HTML elements, which mitigates against typical XSS in element content. However, this encoding does not extend to HTML attributes.
  - There are no specific mitigations in place to prevent HTML injection via attribute manipulation.
- Missing Mitigations:
  - Lack of input sanitization for component properties that are used to dynamically set HTML attributes.
  - No built-in mechanism to automatically sanitize HTML attributes or restrict the types of attributes that can be dynamically set.
  - No guidance in the documentation to warn developers about the risks of dynamically setting HTML attributes based on user-controlled input without sanitization.
  - Lack of code analysis or linting tools to detect potentially unsafe dynamic attribute manipulation.
- Preconditions:
  - A developer must dynamically set HTML attributes in the component's template based on component properties.
  - At least one of these component properties must be directly or indirectly influenced by user-provided input.
  - The application must render a component containing these dynamic attributes to a victim user's browser, and the component must be updated based on user input to trigger attribute injection.
- Source Code Analysis:
  1. **`django_unicorn\components\unicorn_template_response.py`**: This file is responsible for rendering the component template. The code uses `BeautifulSoup` to parse and modify the HTML. While BeautifulSoup itself escapes HTML content within tags, it doesn't inherently sanitize HTML attributes. When Django templates render attributes using double curly braces `{{ attribute_value }}`, the values are inserted directly into the attribute string *after* Django's template engine processes them. Django's template engine's default auto-escaping only applies to tag content, not attributes in most contexts.
  2. **`django_unicorn\templatetags\unicorn.py`**, **`django_unicorn\components\unicorn_view.py`**: These files handle component rendering and passing data to the template. They focus on context variables and component properties but do not include specific attribute sanitization logic. The data passed to the template context is the component's attributes which could include user-controlled input.
  3. **Absence of Sanitization**: Review of the provided files does not reveal any explicit HTML attribute sanitization logic within django-unicorn. The focus of sanitization is on the content within HTML tags, as evidenced by the default HTML encoding and the `safe` attribute/filter mechanism designed to *bypass* this content sanitization in specific cases. The files lack any parallel mechanism for controlling or sanitizing HTML attributes dynamically constructed from component properties.
- Security Test Case:
  1. Create a Django Unicorn component named `attribute_injection_component` in a Django application.
  2. In `attribute_injection_component.py`, define a component view with a property `dynamic_attribute` initialized with an empty string:
     ```python
     # attribute_injection_component.py
     from django_unicorn.components import UnicornView

     class AttributeInjectionComponentView(UnicornView):
         dynamic_attribute = ""
     ```
  3. In `attribute_injection_component.html`, set an HTML attribute dynamically using the `dynamic_attribute` property:
     ```html
     {# attribute_injection_component.html #}
     <div>
         <div id="attribute-injection-target" {{ dynamic_attribute }}>
             This div is vulnerable to attribute injection.
         </div>
         <input type="text" unicorn:model="dynamic_attribute">
     </div>
     ```
  4. Include the `attribute_injection_component` in a Django template that is accessible to an external attacker:
     ```html
     {# index.html #}
     {% load unicorn %}
     <html>
     <head>
         {% unicorn_scripts %}
     </head>
     <body>
         {% csrf_token %}
         {% unicorn 'attribute-injection-component' %}
     </body>
     </html>
     ```
  5. Run the Django application.
  6. As an attacker, access the page in a browser that renders `index.html`.
  7. In the input field associated with `dynamic_attribute`, type in the following payload: `onload="alert('HTML Attribute Injection Vulnerability')"`.
  8. Click outside the input field or trigger an update to send the payload to the server.
  9. Observe that an alert box appears in the browser with the message "HTML Attribute Injection Vulnerability". This confirms that the `onload` attribute with injected JavaScript was executed because attribute values are not sanitized, and dynamic attributes are directly rendered.
  10. If the alert box appears, the HTML attribute injection vulnerability is confirmed.
