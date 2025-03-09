- Vulnerability Name: Cross-Site Scripting (XSS) in Component Rendering

- Description:
  - An attacker can inject malicious JavaScript code through user-provided data that is bound to a Django Unicorn component's property using `unicorn:model` or passed as arguments to actions.
  - If this user-provided data is rendered in the HTML template without proper sanitization, the malicious JavaScript code can be executed in the victim's browser when the component is rendered or updated.
  - Step-by-step trigger:
    1. An attacker crafts a malicious input containing JavaScript code, for example, `<img src=x onerror=alert('XSS')>`.
    2. The attacker provides this malicious input to a Django Unicorn component, either through form input fields bound with `unicorn:model` or as arguments to an action.
    3. The Django Unicorn backend processes the request and re-renders the component, including the attacker-provided data in the template.
    4. If the template renders this data without sufficient sanitization, the browser executes the injected JavaScript code.

- Impact:
  - Successful exploitation can lead to Cross-Site Scripting (XSS).
  - An attacker can execute arbitrary JavaScript code in the victim's browser, potentially leading to:
    - Account takeover: Stealing session cookies or credentials.
    - Data theft: Accessing sensitive information displayed on the page.
    - Defacement: Modifying the content of the web page.
    - Redirection: Redirecting the user to a malicious website.
    - Further attacks: Using the compromised context to launch other attacks against the user or the application.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - HTML Encoding: As mentioned in the changelog for version 0.36.0, responses are HTML encoded by default to prevent XSS attacks. This is likely implemented in the `django_unicorn.utils.sanitize_html` function and applied during component rendering in `UnicornTemplateResponse.render`.
  - Source code analysis (based on `django_unicorn\utils.py` and `django_unicorn\components\unicorn_template_response.py`): The `sanitize_html` function is used in `UnicornTemplateResponse.render` to encode the HTML content before sending it to the client. This is a global mitigation to prevent XSS.

- Missing Mitigations:
  - Context-Aware Output Encoding: While HTML encoding is a general mitigation, context-aware output encoding is more robust. Depending on the rendering context (HTML tags, attributes, JavaScript, CSS, URLs), different encoding schemes might be needed. It's not clear from the provided files if context-aware encoding is fully implemented, or if it's solely relying on general HTML encoding which might be insufficient in certain scenarios.
  - Input Sanitization: The current mitigation seems to focus on output encoding. Input sanitization, which involves validating and cleaning user inputs on the server-side before processing, could provide an additional layer of defense. It's unclear if any input sanitization is performed beyond Django form validation, which is primarily for data integrity and not necessarily security against XSS.
  - Content Security Policy (CSP): CSP is a browser-based security mechanism that can help mitigate XSS by controlling the resources the browser is allowed to load. CSP is not explicitly mentioned in the provided files as a implemented mitigation.

- Preconditions:
  - The application must be using Django Unicorn components to render user-provided data in HTML templates.
  - There must be a code path where user-provided data (through `unicorn:model` or action arguments) is rendered in the template without being explicitly marked as safe using `|safe` template filter or `Meta.safe` component attribute, assuming that HTML encoding is applied by default as claimed in changelog. If not, then any user data rendered without explicit sanitization is potentially vulnerable.

- Source Code Analysis:
  - File: `django_unicorn\utils.py`
    ```python
    def sanitize_html(html: str) -> SafeText:
        """
        Escape all the HTML/XML special characters with their unicode escapes, so
        value is safe to be output in JSON.
        """
        html = html.translate(_json_script_escapes)
        return mark_safe(html)
    ```
    This function exists and is intended for HTML sanitization.

  - File: `django_unicorn\components\unicorn_template_response.py`
    ```python
    class UnicornTemplateResponse(TemplateResponse):
        def render(self):
            ...
            rendered_template = UnicornTemplateResponse._desoupify(soup)
            self.component.rendered(rendered_template)
            response.content = rendered_template
            ...
    ```
    and
    ```python
    @staticmethod
    def _desoupify(soup):
        soup.smooth()
        return soup.encode(formatter=UnsortedAttributes()).decode("utf-8")
    ```
    The `_desoupify` method, which encodes the HTML, is called in `render`. This confirms that output encoding is implemented. However, the level of encoding (context-aware vs. general HTML encoding) and specific contexts where it's applied need further investigation in the codebase, which is not provided fully. Assuming the claim in changelog is correct, general HTML encoding is applied.

  - Vulnerability point: If `Meta.safe` is used incorrectly or if there are code paths where user data is rendered without going through the default HTML encoding, XSS vulnerabilities could still exist. Also, if context-aware encoding is not fully implemented, certain XSS vectors might bypass the general HTML encoding.

- Security Test Case:
  - Step 1: Create a Django Unicorn component that renders user-provided input.
    ```python
    # example_app/components/xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input = ""
    ```
    ```html
    <!-- example_app/templates/unicorn/xss-test.html -->
    <div>
        <input type="text" unicorn:model="user_input" id="user-input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```
  - Step 2: Create a Django template to include the component.
    ```html
    <!-- example_app/templates/xss_test_page.html -->
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
  - Step 3: Create a Django view to render the template.
    ```python
    # example_app/views.py
    from django.shortcuts import render

    def xss_test_view(request):
        return render(request, 'xss_test_page.html')
    ```
  - Step 4: Add URL to `urls.py`.
    ```python
    # example_app/urls.py
    from django.urls import path
    from .views import xss_test_view

    urlpatterns = [
        path('xss-test/', xss_test_view, name='xss_test_view'),
    ]
    ```
  - Step 5: Access the `xss-test/` page and input the following XSS payload in the text input field: `<img src=x onerror=alert('XSS')>`
  - Step 6: Observe the output in the `output` div.
    - Expected behavior (Mitigation is effective): The XSS payload should be HTML-encoded and rendered as text, not executing the JavaScript alert. The output in the `output` div should be: `&lt;img src=x onerror=alert('XSS')&gt;`
    - Vulnerable behavior (Mitigation is ineffective or bypassed): If the JavaScript alert box appears, it indicates that the XSS mitigation is ineffective, and the application is vulnerable.
