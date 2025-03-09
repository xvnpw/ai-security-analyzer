- Vulnerability name: XSS Vulnerability due to Improper Output Encoding in Components
- Description:
  - Django-unicorn components, when re-rendering after user actions or data updates, may fail to properly encode output, leading to a Cross-Site Scripting (XSS) vulnerability. Specifically, if a component uses the `safe` meta class attribute or template filter and includes user-controlled data without proper sanitization, an attacker can inject malicious JavaScript code that will be executed in the context of the victim's browser.
- Impact:
  - Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser when they interact with a vulnerable component. This can lead to session hijacking, account takeover, sensitive data theft, and other malicious actions on behalf of the victim.
- Vulnerability rank: high
- Currently implemented mitigations:
  - Django Unicorn automatically HTML-encodes updated field values to prevent XSS attacks by default.
  - The project requires CSRF token for AJAX requests.
- Missing mitigations:
  - While auto-encoding is in place by default, the `safe` meta class attribute and the `safe` template filter explicitly allow developers to bypass this encoding. There isn't sufficient built-in protection or clear security guidance for developers about the risks of using these features insecurely when rendering user-controlled data.  The project should provide clearer recommendations and potentially explore safer alternatives or stricter usage guidelines for bypassing output encoding.
- Preconditions:
  - The application uses django-unicorn components.
  - A component uses the `safe` meta attribute or `safe` template filter to render user-controlled data.
  - The user-controlled data is not properly sanitized by the developer before being rendered.
- Source code analysis:
  - In `django_unicorn/views/views.py`, the `_process_component_request` function handles component updates triggered by AJAX requests.
  - Inside `_process_component_request`, the `component.render(request=request)` function is responsible for re-rendering the component's template after processing actions.
  - `django_unicorn/components/unicorn_template_response.py` contains the `UnicornTemplateResponse.render` method, which handles the template rendering and DOM morphing.
  - The `Meta.safe` attribute, as documented in `views.md` and implemented in `django_unicorn/views/views.py`, and the `safe` template filter (documented in `views.md`) are features designed to allow developers to explicitly disable HTML encoding for specific component properties or template variables.
  - While these features offer flexibility, they introduce a security risk if developers use them to render user-controlled data without proper sanitization. In such cases, malicious HTML or JavaScript code injected by an attacker can be executed in a user's browser, leading to XSS.
  - The changelog for version 0.36.0 mentions a security fix for CVE-2021-42053 to prevent XSS attacks, which indicates that XSS vulnerabilities have been a concern in the past and highlights the importance of proper output encoding.
- Security test case:
  - Vulnerability: XSS Vulnerability
  - Component:
    ```python
    # example/unicorn/components/xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        malicious_code = ""

        class Meta:
            safe = ("malicious_code",)
    ```
  - Template:
    ```html
    <!-- example/unicorn/components/xss_test.html -->
    <div>
      <p>Rendered Code:</p>
      <div id="xss-output">
        {{ malicious_code }}
      </div>
      <input type="text" unicorn:model="malicious_code" id="xss-input">
    </div>
    ```
  - View:
    ```python
    # example/www/views.py
    from django.shortcuts import render

    def index(request):
        return render(request, "www/index.html")
    ```
  - Index Template:
    ```html
    <!-- example/www/templates/www/index.html -->
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
  - Test Steps:
    1. Deploy the Django application with the above component and view.
    2. Access the index page in a web browser.
    3. In the input field labeled "malicious_code" (or with `id="xss-input"`), enter the following payload: `<img src=x onerror=alert('XSS-Unicorn')>`.
    4. Click outside the input field or trigger a `blur` event to send the update to the server (or use `unicorn:model.lazy`).
    5. Observe if an alert box with the message "XSS-Unicorn" is displayed in the browser.
  - Expected Result:
    - An alert box with "XSS-Unicorn" should appear, indicating that the JavaScript code from the payload was executed. This confirms the XSS vulnerability because the user-supplied input was rendered without sufficient sanitization due to the use of `safe` meta attribute.
  - Vulnerability Rank: high
