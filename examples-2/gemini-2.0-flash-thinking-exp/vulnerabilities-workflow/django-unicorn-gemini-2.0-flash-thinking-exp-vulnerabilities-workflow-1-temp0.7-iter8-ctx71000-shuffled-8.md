### Vulnerability List for django-unicorn project:

- Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe HTML Attributes

- Description:
    1. An attacker can inject malicious JavaScript code into HTML attributes within a Django template used by a Unicorn component.
    2. When the component updates and re-renders, the injected JavaScript code in the HTML attribute is executed in the user's browser.
    3. This occurs because django-unicorn does not automatically sanitize HTML attributes, and if a developer uses user-controlled data directly within HTML attributes (even indirectly via template variables), it can lead to XSS.

- Impact:
    - Account Takeover: An attacker could potentially steal session cookies or other sensitive information, leading to account takeover.
    - Data Theft: Malicious scripts can be used to exfiltrate user data or application data.
    - Website Defacement: The attacker can modify the content of the web page seen by the user.
    - Redirection to Malicious Sites: Users could be redirected to phishing or malware-serving websites.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding of updated field values is mentioned in `changelog.md` (version 0.36.0) as a security fix to prevent XSS attacks. This likely refers to the encoding of HTML content within the DOM updates.
    - The documentation for `views.md` mentions `Meta.safe` and `safe` template filter to explicitly allow certain fields to be rendered without HTML encoding. This is intended for developers to use when they are sure the content is safe.

- Missing Mitigations:
    - Lack of automatic sanitization for HTML attributes. While django-unicorn encodes HTML content within tags by default, it appears it does not automatically sanitize HTML attributes.
    - No clear guidance in the documentation about the risks of using user input directly in HTML attributes and how to prevent XSS in this context.

- Preconditions:
    1. The application uses django-unicorn.
    2. A developer uses user-controlled data to dynamically generate HTML attributes in a Unicorn component template.
    3. The application does not sanitize this user-controlled data before embedding it in HTML attributes.

- Source Code Analysis:
    1. **`docs\source\changelog.md`**:  Version 0.36.0 mentions a security fix for CVE-2021-42053 to prevent XSS attacks, stating "responses will be HTML encoded going forward". This suggests that prior versions might have been vulnerable, and the fix focused on encoding HTML content. It does not explicitly mention attribute encoding.
    2. **`docs\source\views.md`**: The `Meta.safe` and `safe` template filter documentation indicates an awareness of XSS risks and provides a way to bypass encoding for specific fields. This implies that by default, encoding is applied to HTML content, but it doesn't guarantee attribute encoding.
    3. **Absence of explicit attribute sanitization**: Review of the provided code snippets and documentation does not reveal any built-in mechanism within django-unicorn to automatically sanitize HTML attributes. The focus seems to be on encoding HTML tag content.
    4. **`django_unicorn\templatetags\unicorn.py`**: This file defines the `unicorn` template tag, which is used to render Unicorn components. While this file handles component rendering, it doesn't include any explicit sanitization of HTML attributes. The focus is on resolving component names, arguments, and kwargs, and rendering the component's template.
    5. **`django_unicorn\components\unicorn_template_response.py`**: This file is responsible for rendering the component's template and handling updates. It uses `BeautifulSoup` to parse and modify the HTML. While `django_unicorn.utils.sanitize_html` is used to sanitize the `init` JSON data embedded in a `<script>` tag, there is no similar sanitization applied to HTML attributes rendered from component data.
    6. **`example\unicorn\components\text_inputs.py`**: This example component has a `testing_xss` property: `testing_xss = "Whatever </script> <script>alert('uh oh')</script>"`. This demonstrates that user-provided or component data assigned to template variables can include potentially malicious HTML/JS. If this data is used in HTML attributes without sanitization, it will lead to XSS.
    7. **`django_unicorn\serializer.py`**: This file focuses on serializing data between the backend and frontend, and does not include any HTML sanitization logic. The functions `dumps` and `loads` handle JSON serialization and deserialization but do not modify HTML content. The file is designed for data transformation and optimization, not for security against XSS in HTML attributes.
    8. **`tests\views\message\test_calls.py`, `django_unicorn\db.py`, `tests\views\action_parsers\call_method\test_call_method_name.py`, `example\unicorn\components\wizard\step2.py`**: These files are related to testing, database models, method call handling, and example components. They do not introduce new information related to HTML attribute sanitization or XSS vulnerabilities.

- Security Test Case:
    1. Create a Django Unicorn component that dynamically renders an HTML element with an attribute whose value is derived from a component property.
    2. In the component's Python view, set the property to a value that includes malicious JavaScript code within an HTML attribute, for example: `"><img src=x onerror=alert(document.domain)>`.
    3. Render the component in a Django template.
    4. Observe if the JavaScript code executes when the component is initially rendered or during an update.
    5. Example Component Template (`xss_attribute.html`):
    ```html
    <div>
        <input type="text" unicorn:model="attribute_value">
        <div id="vuln-div" dynamic-attribute="{{ attribute_value }}"></div>
    </div>
    ```
    6. Example Component View (`xss_attribute.py`):
    ```python
    from django_unicorn.components import UnicornView

    class XssAttributeView(UnicornView):
        attribute_value = ""

        def mount(self):
            pass
    ```
    7. Test Steps:
        a. Access the page with the Unicorn component.
        b. In the input field, enter the payload: `"><img src=x onerror=alert(document.domain)>`.
        c. Trigger an update to the component (e.g., by clicking outside the input field if using `lazy` modifier, or just typing if using default `input` event).
        d. Check if an alert box with the document domain appears. If it does, it confirms the XSS vulnerability.
        e. Inspect the rendered HTML source of the `div#vuln-div` element. It will show the injected attribute value directly without sanitization, confirming the vulnerability in attribute context.
