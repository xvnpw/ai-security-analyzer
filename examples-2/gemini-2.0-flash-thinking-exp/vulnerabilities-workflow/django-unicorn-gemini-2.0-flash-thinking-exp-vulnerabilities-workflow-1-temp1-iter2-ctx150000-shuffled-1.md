### Vulnerability List:

* Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attribute injection in template rendering

* Description:
    1. An attacker can inject malicious HTML attributes by controlling component's properties that are used to render HTML attributes in templates.
    2. When a component with a vulnerable template is rendered, the injected attributes are included in the HTML output without proper sanitization.
    3. If a user interacts with the affected part of the template, the malicious attributes can be triggered, leading to XSS.

* Impact:
    - Account Takeover: An attacker could potentially steal session cookies or credentials, leading to account takeover.
    - Data Theft: Sensitive information displayed on the page could be exfiltrated.
    - Website Defacement: The attacker could modify the content of the website as perceived by the victim.
    - Redirection to Malicious Sites: Users could be redirected to attacker-controlled websites, potentially leading to phishing or malware infections.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - HTML encoding for updated field values to prevent XSS attacks is implemented by default (see `docs/source/views.md#safe` and `docs/source/changelog.md` for version 0.36.0). This mitigation uses Django's `mark_safe` for fields specified in `Meta.safe` of a component, as seen in `django_unicorn/views/__init__.py`.  However, this mitigation is focused on marking explicitly trusted HTML content as safe and primarily addresses content within HTML tags, not HTML attributes. Based on source code analysis of `django_unicorn/components/unicorn_template_response.py`, no specific HTML attribute sanitization is implemented during template rendering.

* Missing Mitigations:
    -  Input sanitization or output encoding for HTML attributes to prevent injection of malicious attributes is missing. The current HTML encoding mechanism using `mark_safe` is not applied to HTML attributes, leaving them vulnerable to injection. The project lacks a mechanism to automatically sanitize or encode attribute values that are dynamically rendered from component properties.

* Preconditions:
    - A component template must use component's properties to dynamically render HTML attributes (e.g., `<div data-attribute="{{ component_property }}">`).
    - An attacker must be able to control the `component_property` value, possibly through `unicorn:model` bindings or URL parameters if the component is used as a direct view.

* Source Code Analysis:
    1. **`django_unicorn/components/unicorn_template_response.py`**: This file handles template rendering. It uses BeautifulSoup for parsing and manipulation. While it includes `sanitize_html` function, this function is used for sanitizing the `init` script content, not for general template output, especially HTML attributes. The `UnsortedAttributes` class is used to maintain attribute order during serialization but does not perform sanitization.
    2. **`django_unicorn/views/__init__.py`**: This file processes component requests and handles rendering. It includes logic to mark fields specified in `Meta.safe` as safe using `mark_safe` before rendering. However, this mechanism seems to be designed for trusted HTML content within tags and does not extend to automatically sanitizing HTML attributes. The code does not include any encoding or sanitization of component properties when they are used to render HTML attributes in templates.
    3. **`django_unicorn/serializer.py`**: This file deals with serialization of component data. It focuses on data type handling and exclusion of fields based on `Meta.exclude` and `Meta.javascript_exclude`. It does not include any HTML attribute sanitization logic.
    4. **`example/unicorn/components/html_inputs.py`**: This example component demonstrates data binding to HTML attributes using `unicorn:model`, but it does not showcase or implement any attribute sanitization.
    5. **`docs/source/views.md#safe`**: Documentation explains the `safe` Meta option for marking fields as safe, but it primarily refers to HTML content within tags, reinforcing the lack of attribute sanitization.

    **Code snippet illustrating potential vulnerability (example scenario - not from provided files, but illustrates the issue):**

    ```html
    <!-- vulnerable_component.html -->
    <div id="vulnerable-div" class="{{ div_class }}" unicorn:view>
      <p>Hello World</p>
    </div>
    ```

    ```python
    # vulnerable_component.py
    from django_unicorn.components import UnicornView

    class VulnerableView(UnicornView):
        div_class = "" # Attacker can control this value

        def mount(self):
            pass
    ```

    In this example, if an attacker can control `div_class` (e.g., through URL parameters if `VulnerableView` is a direct view and `div_class` is passed as a parameter), they could inject malicious classes like `"xss' onload='alert(\"XSS\")'"` which would then be rendered as `<div id="vulnerable-div" class="xss' onload='alert(\"XSS\")'" unicorn:view>`.

* Security Test Case:
    1. Create a new Unicorn component named `AttributeInjectionTest` in your Django application.
    2. Modify the component's template (`attribute_injection_test.html`) to dynamically render an HTML attribute using a component property:

    ```html
    <div id="attribute-injection-div" data-custom-attribute="{{ injected_attribute }}" unicorn:view>
      <p>Test Attribute Injection</p>
    </div>
    ```

    3. Modify the component's view (`attribute_injection_test.py`) to include a property `injected_attribute`:

    ```python
    from django_unicorn.components import UnicornView

    class AttributeInjectionTestView(UnicornView):
        injected_attribute = ""

        def mount(self):
            pass
    ```

    4. Create a Django view and template to include the `AttributeInjectionTest` component, and ensure that you can control the `injected_attribute` property. For simplicity, you can directly set the `injected_attribute` in the component's `mount` method, simulating attacker control:

    ```python
    # In attribute_injection_test.py, modify mount method
    def mount(self):
        self.injected_attribute = "event='mouseover' onmouseover='alert(\"XSS Vulnerability\")'"
    ```

    5. Render the template containing the `AttributeInjectionTest` component in a browser.
    6. Inspect the HTML source code of the rendered page.
    7. Verify that the `data-custom-attribute` in the `div` element contains the injected attribute without proper encoding:

    ```html
    <div id="attribute-injection-div" data-custom-attribute="event='mouseover' onmouseover='alert(&quot;XSS Vulnerability&quot;)'" unicorn:view>
      <p>Test Attribute Injection</p>
    </div>
    ```
    8. Hover your mouse over the "Test Attribute Injection" text.
    9. Observe that the JavaScript `alert("XSS Vulnerability")` is executed, demonstrating the XSS vulnerability.
