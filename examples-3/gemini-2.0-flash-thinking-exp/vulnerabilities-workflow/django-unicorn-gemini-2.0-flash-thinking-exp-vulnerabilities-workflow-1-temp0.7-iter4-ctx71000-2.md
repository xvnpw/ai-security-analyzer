## Vulnerability List for django-unicorn Project

- Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe HTML Attributes

- Description:
  1. An attacker can inject malicious JavaScript code into a component's attribute value.
  2. When the component is rendered or updated, django-unicorn might not properly escape the attribute value if it's marked as 'safe' or handled unsafely in the component's code.
  3. The injected JavaScript code then gets executed in the victim's browser when the component is rendered, leading to XSS.
  4. This can be triggered through various component interactions that lead to attribute updates, such as model updates or action responses that modify attributes.

- Impact:
  - High
  - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser within the context of the application.
  - This can lead to session hijacking, defacement of the website, redirection to malicious sites, theft of sensitive user data, and other malicious actions.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
  - According to the changelog for version 0.36.0, django-unicorn implemented a security fix for CVE-2021-42053 to prevent XSS attacks by HTML encoding responses.
  - The documentation mentions the `safe` Meta attribute and template filter, suggesting developers are intended to explicitly mark content as safe when needed, implying that by default content is encoded.
  - `django_unicorn.utils.sanitize_html` function is used in `UnicornTemplateResponse.render` to HTML escape JSON data that is injected into `<script>` tag specifically for `unicorn:data` attribute.
  - Tests in `test_views\test_process_component_request.py` confirm that HTML entities are encoded by default when setting component properties from user input, and that `safe` attribute bypasses this encoding.

- Missing Mitigations:
  - While output encoding is applied by default for component properties, it is explicitly bypassed when developers use the `safe` filter or `Meta.safe` setting.
  - There is no automatic sanitization for HTML attributes when using `safe`. Developers are responsible for sanitizing data before marking it as safe, and if they fail to do so, XSS vulnerabilities can occur.
  - The `sanitize_html` function is specifically used for escaping JSON data within `<script>` tags for `unicorn:data` and is not automatically applied to template variables used in HTML attributes.
  - Lack of clear and prominent documentation warning against the misuse of `safe` and emphasizing the need for manual sanitization when using `safe` filter or `Meta.safe` for HTML attributes.

- Preconditions:
  - The application must be using django-unicorn and rendering components that dynamically update HTML attributes based on user-controlled data or component state.
  - A developer needs to use `safe` filter or `Meta.safe` to render a component property that contains unsanitized user input into HTML attribute.

- Source Code Analysis:
  1. **`django_unicorn\components\unicorn_template_response.py`**:
     - `UnicornTemplateResponse.render` method handles component rendering.
     - It uses `BeautifulSoup` to parse the template and inject component data.
     - **Crucially, while `sanitize_html` is used to encode JSON data within `<script>` tags (specifically for `unicorn:data`), this sanitization is NOT applied to template variables that are directly used to set HTML attributes.**
     - Attributes are set based on the rendered template and the component's context, without any automatic escaping of attribute values derived from component properties *unless* those properties are themselves already escaped or considered safe by the developer.

  2. **`django_unicorn\utils.py`**:
     - `sanitize_html` function is designed to escape HTML/XML special characters specifically for JSON data within `<script>` tags to prevent script injection via component data.
     - **This function is not automatically utilized for general HTML attribute sanitization.**

  3. **`django_unicorn\templatetags\unicorn.py`**:
     - The `unicorn` template tag renders components.
     - It does not perform any HTML sanitization itself.
     - It relies on the component's template and the developer's handling of template variables to ensure security.

  4. **`django_unicorn\views\test_process_component_request.py`**:
     - Tests like `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` demonstrate the default behavior of django-unicorn: **HTML encoding is applied when setting component properties from user input.**
     - The `safe` `Meta` attribute (and by extension, the `safe` template filter) explicitly disables this encoding. This is shown by `test_safe_html_entities_not_encoded`, where using a `safe` property allows raw HTML to be rendered without encoding.

  **Visualization:**

  ```
  Template (with <a href="{{ unsafe_url|safe }}">) --> unicorn template tag --> UnicornView.render --> UnicornTemplateResponse.render
      |                                                                               |
      |                                                                               V
      |                                                                       BeautifulSoup parses HTML
      |                                                                               |
      |                                                                       Adds unicorn:* attributes
      |                                                                               |
      |                                                                       Injects <script> tag with sanitized JSON data (unicorn:data)
      |                                                                               |
      V
  HTML Response (vulnerable if unsafe_url contains malicious code and 'safe' is used without sanitization)
  ```

- Security Test Case:
  1. Create a django-unicorn component that renders an HTML element with an attribute dynamically set from a component property, and explicitly mark this property as `safe` in `Meta.safe`. For example, use an `<a>` tag with `href` attribute.
  2. In the component's Python code, define a property, e.g., `unsafe_url`, and mark it as `safe` in `Meta.safe`. Initialize it with a malicious JavaScript URL, like `"javascript:alert('XSS')"`.
  3. Render this component in a Django template.
  4. Access the page in a browser.
  5. Inspect the rendered HTML source code. Verify if the `<a>` tag's `href` attribute contains the injected JavaScript code directly, without HTML escaping, because it is marked as `safe`.
  6. Click on the link. If the JavaScript code executes (e.g., an alert box pops up), it confirms the XSS vulnerability.

```html
<!-- component template (e.g., xss_link_test.html) -->
<div>
    <a id="xss-link" href="{{ unsafe_url }}">Click me</a>
</div>
```

```python
# component view (e.g., xss_link_test.py)
from django_unicorn.components import UnicornView

class XssLinkTestView(UnicornView):
    unsafe_url = "javascript:alert('XSS')"

    class Meta:
        safe = ("unsafe_url",)
```

**Security Test Case Steps for External Attacker:**
  1. Access the public URL where the django-unicorn component is rendered (containing the `XssLinkTestView` component as defined above).
  2. View the page source in the browser.
  3. Locate the `<a>` tag with `id="xss-link"`.
  4. Examine the `href` attribute of this tag. If it directly contains `javascript:alert('XSS')` without HTML escaping, proceed to the next step.
  5. Click on the "Click me" link.
  6. If an alert box pops up displaying "XSS", it confirms that the XSS vulnerability is present due to the unsafe usage of `safe` and lack of automatic attribute sanitization.

This test case demonstrates that if developers use the `safe` mechanism (either `Meta.safe` or `|safe` filter in templates) without properly sanitizing user-provided or dynamic data that goes into HTML attributes, they can introduce XSS vulnerabilities in django-unicorn applications. The core issue is the explicit bypass of default HTML encoding with `safe` without sufficient guidance and enforcement of sanitization.
