### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe HTML Attributes in Component Templates
- Description:
    1. A threat actor can inject malicious JavaScript code into HTML attributes within a Django Unicorn component template.
    2. When the component is rendered or updated, the injected JavaScript code is executed in the user's browser.
    3. This can occur if user-controlled data is included in HTML attributes without proper sanitization within the component's template.
- Impact:
    - Successful exploitation allows a threat actor to execute arbitrary JavaScript code in the context of a user's browser when they interact with the affected Django Unicorn component.
    - This can lead to various malicious activities, including session hijacking, defacement, sensitive data theft, and redirection to malicious websites.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Django Unicorn HTML-encodes updated field values by default to prevent XSS attacks, as mentioned in `docs\source\views.md` and `docs\source\changelog.md` (fix for CVE-2021-42053).
    - Developers can use the `safe` Meta class attribute in `UnicornView` to explicitly allow a field to be returned without HTML encoding, as documented in `docs\source\views.md`. This requires developers to consciously mark fields as safe.
- Missing Mitigations:
    - While Django Unicorn encodes field values, it is crucial to ensure that all user-provided data rendered within component templates, especially within HTML attributes, is properly sanitized.
    - There is no automatic sanitization for HTML attributes within the component templates themselves. If a developer dynamically constructs HTML attributes based on user input within the template and fails to sanitize, XSS vulnerabilities can still be introduced.
    - The `django_unicorn.utils.sanitize_html` function exists and can be used to sanitize HTML content. However, this function is not automatically applied to user-provided data rendered in HTML attributes within component templates. Developers need to manually use this function to sanitize data before rendering it in HTML attributes.
- Preconditions:
    - The application uses Django Unicorn components and renders user-controlled data within the component templates, specifically within HTML attributes.
    - Developers fail to manually sanitize user-provided data before rendering it in HTML attributes.
- Source Code Analysis:
    - Reviewing the code, particularly `django_unicorn\views\action_parsers\utils.py` which handles setting property values, and `django_unicorn\templatetags\unicorn.py` which renders components, shows that while field values are encoded, the framework does not automatically sanitize user-provided data when it's placed into HTML attributes within templates.
    - The function `set_property_value` in `django_unicorn\views\action_parsers\utils.py` is responsible for updating component properties. While it ensures HTML encoding for the *values* of component fields being updated via user interactions (like `syncInput` actions processed by `django_unicorn\views\action_parsers\sync_input.py`), it does not extend to sanitizing data dynamically placed into HTML attributes directly within the component templates.
    - The `unicorn` template tag in `django_unicorn\templatetags\unicorn.py` and the `UnicornNode` class handle component rendering. They do not include any explicit HTML sanitization for template variables used within HTML attributes.
    - The fix for CVE-2021-42053 focuses on encoding field values during updates, but it does not address the broader issue of unsanitized user input in HTML attributes within component templates.
- Security Test Case:
    1. Create a Django Unicorn component named `AttributeXSS` with the following template (`unicorn/attribute-xss.html`):
        ```html
        <div unicorn:component="attribute-xss">
          <div id="test-attr" data-user="{{ user_input }}">Hello</div>
        </div>
        ```
    2. Create a component view `AttributeXSSView` in `example/unicorn/components/attribute_xss.py`:
        ```python
        from django_unicorn.components import UnicornView

        class AttributeXSSView(UnicornView):
            user_input: str = ""

            def mount(self):
                self.user_input = "initial value"
        ```
    3. Create a Django template to render the component, for example in `example/templates/test_attribute_xss.html`:
        ```html
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Attribute XSS Test</title>
        </head>
        <body>
            {% unicorn 'attribute-xss' %}
            {% unicorn_scripts %}
        </body>
        </html>
        ```
    4. Create a Django URL and view to serve `test_attribute_xss.html`.
    5. Access the page in a browser. Observe that "Hello" is rendered, and inspect the `div#test-attr` element in browser developer tools; you should see `data-user="initial value"`.
    6. As an attacker, craft a URL or form to submit a malicious JavaScript payload for `user_input`. Since the component is initialized with `user_input = "initial value"` and there's no mechanism to directly manipulate it from the outside in this example, modify the `mount` method in `AttributeXSSView` for testing:
        ```python
        class AttributeXSSView(UnicornView):
            user_input: str = ""

            def mount(self):
                if 'malicious_input' in self.request.GET: # or POST
                    self.user_input = self.request.GET['malicious_input'] # or POST
                else:
                    self.user_input = "initial value"
        ```
    7. Now, as an attacker, access the test page with a malicious payload in the URL, e.g., `http://your-test-url/attribute-xss-page/?malicious_input=%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E`.
    8. Render the page and inspect the `div#test-attr` element again. You should see `data-user=""><img src=x onerror=alert(document.domain)>Hello`.
    9. Observe if the JavaScript code injected into the `data-user` attribute executes in the browser (an alert box with the document domain should appear), demonstrating the XSS vulnerability.
