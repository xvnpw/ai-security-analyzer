#### 1. Cross-Site Scripting (XSS) via Unsafe HTML Attributes in Templates

- Description:
    1. An attacker crafts a malicious string containing Javascript code.
    2. This malicious string is injected into a component's property, either directly or indirectly via user input (e.g., form input, URL parameters, etc.).
    3. The `set_property_from_data` function in `django_unicorn.views.utils` updates the component's property with the attacker-controlled data.
    4. The component template uses this property to render HTML attributes without proper attribute-specific sanitization.
    5. When the component is rendered or updated, the malicious Javascript code in the HTML attribute is executed in the victim's browser, leading to XSS.

- Impact:
    - **Critical:** Successful XSS can lead to account takeover, session hijacking, sensitive data theft, redirection to malicious sites, and defacement of the application.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - HTML encoding of component data in responses (mentioned in changelog v0.36.0, security fix for CVE-2021-42053). This likely mitigates XSS in HTML content but might not fully cover HTML attributes. The `sanitize_html` function in `django_unicorn/utils.py` is used to escape HTML/XML special characters and is applied to the JSON data within the `<script>` tag in `UnicornTemplateResponse.render`.  `test_utils.py` includes tests for `sanitize_html` function, confirming its basic HTML escaping capabilities. `test_process_component_request.py` shows that HTML entities are encoded by default, but the `safe` meta option bypasses this, indicating potential developer misuse.
    - Django's built-in template escaping is generally applied to template variables, but context-dependent escaping might be missed in certain scenarios, especially with dynamically constructed attributes.

- Missing Mitigations:
    - **Context-Aware Output Encoding for HTML Attributes:** Ensure that all dynamically rendered content within HTML attributes is rigorously encoded specifically for HTML attribute context to prevent script injection. This goes beyond basic HTML escaping and needs to be attribute-specific encoding.  The current `sanitize_html` in `django_unicorn/utils.py` is used for JSON within `<script>` tags, but there's no explicit mechanism in `UnicornTemplateResponse` or `UnicornView` to enforce attribute-specific encoding for template variables rendered into HTML attributes.
    - **Input Sanitization in `set_property_from_data`:** Implement sanitization of user-provided data within the `set_property_from_data` function in `django_unicorn/views/utils.py` before it's used to update component properties. This would ensure that malicious scripts are neutralized before they even reach the template rendering stage.
    - **Content Security Policy (CSP):** Implement a strict CSP to limit the capabilities of the browser in executing inline scripts and loading resources from untrusted origins. This acts as a defense-in-depth mechanism against XSS.
    - **Regular Security Audits and Testing:** Conduct regular security audits and penetration testing, specifically focusing on XSS vulnerabilities in component templates and data handling.

- Preconditions:
    - An attacker needs to find a component template that dynamically renders user-controlled data into HTML attributes *without proper attribute-specific encoding*.
    - The attacker needs to be able to influence the data that is rendered into the attribute, either through direct component properties or indirectly through user inputs that modify component state.

- Source Code Analysis:
    1. **Template Rendering Process:** Django templates are rendered server-side. Django's template engine generally provides auto-escaping to prevent basic XSS in HTML content. However, this auto-escaping might be insufficient for HTML attribute contexts. Developers might also use `safe` filters or tags, potentially bypassing auto-escaping.
    2. **Component Data Handling and `set_property_from_data`:** Django-unicorn components pass data from Python views to Javascript and then render templates. The `serializer.py` (not provided in this batch but analyzed in previous iterations) handles data serialization. The file `views/utils.py` contains the `set_property_from_data` function, which is tested in `test_set_property_from_data.py`. This function is responsible for updating component properties based on data received from the client-side, typically in response to user interactions. The tests in `test_set_property_from_data.py` focus on data type conversion and assignment, but they do not include any checks or logic for sanitizing input data to prevent XSS. If a component property is updated via `set_property_from_data` with unsanitized user input and then rendered into an HTML attribute in the component's template, it can lead to XSS.
    3. **`safe` Meta Option and `sanitize_html`:** The `views.md` documentation (not provided) mentions a `safe` meta option and `safe` template filter which could be misused by developers to output raw HTML into attributes.  While `sanitize_html` function exists in `django_unicorn/utils.py` and is used in `UnicornTemplateResponse.render` to sanitize the JSON init script data, it is not automatically applied to template variables used in HTML attributes or during the property setting process in `set_property_from_data`.  `test_utils.py` and `test_process_component_request.py` confirm the existence and behavior of `sanitize_html` and the `safe` option.
    4. **`UnicornTemplateResponse.render`:** This method in `django_unicorn/components/unicorn_template_response.py` is responsible for rendering the component. It uses `BeautifulSoup` to manipulate the HTML and adds `unicorn:` attributes. While it calls `sanitize_html` to escape the JSON init data within `<script>` tags, it doesn't enforce attribute-specific encoding for dynamically rendered content in the component's HTML template itself. The `_desoupify` method uses `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`, but `UnsortedAttributes` is only for preserving attribute order and not for encoding or escaping.  The file `test_unicorn_template_response.py` tests the `UnicornTemplateResponse` class and its methods, but does not include tests that explicitly check for HTML attribute encoding or sanitization of data handled by `set_property_from_data`.

- Security Test Case:
    1. Create a Django-unicorn component, for example, `AttributeXSSView`, with a property `unsafe_attribute`.
    2. Define the component in `example/unicorn/components/attribute_xss.py`:
    ```python
    from django_unicorn.components import UnicornView

    class AttributeXSSView(UnicornView):
        unsafe_attribute: str = ""
    ```
    3. Create a template for this component in `example/unicorn/templates/unicorn/attribute-xss.html`:
    ```html
    <div unicorn:name="attribute-xss">
        <button data-attribute="{{ unsafe_attribute }}">Click Me</button>
    </div>
    ```
    4. Add URL path to `example/project/urls.py`:
    ```python
    path("attribute-xss", AttributeXSSView.as_view(), name="attribute-xss"),
    ```
    5. Create a view in `example/www/views.py` to render the component:
    ```python
    from django.shortcuts import render
    from example.unicorn.components.attribute_xss import AttributeXSSView

    def attribute_xss_view(request):
        component = AttributeXSSView.as_view()(request=request)
        return render(request, 'www/attribute_xss_page.html', {'component': component})
    ```
    6. Create a template `example/www/attribute_xss_page.html`:
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attribute XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% component component %}
    </body>
    </html>
    ```
    7. Access `/attribute-xss` in the browser. It should render a button with `data-attribute=""`.
    8. In the browser's developer console, execute the following Javascript to dynamically set the `unsafe_attribute` property with a malicious payload:
    ```javascript
    Unicorn.getComponent('attribute-xss').set({'unsafe_attribute': '"><img src=x onerror=alert(\'XSS\')>'});
    ```
    9. Click the "Click Me" button.
    10. Observe if the Javascript code injected via `unsafe_attribute` is executed (i.e., an alert box appears). If the `alert('XSS')` is executed, the vulnerability is confirmed because the malicious payload in the `data-attribute` was not properly encoded for the HTML attribute context.
    11. To further test, try different HTML attributes susceptible to XSS, such as `href` in `<a>` tags or `src` in `<img>` tags, and various XSS payloads. For example, try setting `unsafe_attribute` to `"javascript:alert('XSS')"` in an `href` attribute of an `<a>` tag.
