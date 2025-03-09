- Vulnerability Name: Cross-Site Scripting (XSS) due to unsafe HTML rendering

- Description:
    1. A threat actor can inject malicious JavaScript code through user input fields in a Django Unicorn component.
    2. If the component's view does not explicitly mark a field as safe using `Meta.safe` or the `safe` template filter, Django Unicorn will HTML-encode the output by default, mitigating XSS.
    3. However, if a developer mistakenly marks a field containing user-controlled data as safe, or uses the `safe` filter without proper sanitization, the injected JavaScript code will be rendered directly in the user's browser.
    4. This can occur when displaying user-provided content or any data that is not properly sanitized before being marked as safe.
    5. When a victim views the page with the vulnerable component, the injected JavaScript code executes in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

- Impact:
    Successful exploitation of this vulnerability can lead to Cross-Site Scripting (XSS). An attacker can execute arbitrary JavaScript code in the victim's browser. This can result in:
    - Account hijacking: Stealing session cookies or credentials.
    - Data theft: Accessing sensitive information visible to the user.
    - Website defacement: Modifying the content of the web page.
    - Redirection to malicious sites: Redirecting the user to a phishing or malware-distributing website.
    - Actions on behalf of the user: Performing actions as the logged-in user without their consent.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    Django Unicorn by default HTML-encodes all component data rendered in templates to prevent XSS. This is achieved through the `_desoupify` method in `django_unicorn\components\unicorn_template_response.py` which uses `BeautifulSoup` with `HTMLFormatter` and `entity_substitution=EntitySubstitution.substitute_html` for HTML encoding. This behavior is described in `docs\source\changelog.md` (v0.36.0) and `docs\source\views.md`. The documentation for `views.md` also mentions the `safe` attribute in the `Meta` class and the `safe` template filter as ways to bypass this encoding when developers intend to render raw HTML.

- Missing Mitigations:
    While Django Unicorn provides default HTML encoding, it relies on developers to correctly handle user inputs and avoid marking unsafe data as safe. There is no automatic sanitization of data marked as safe. Missing mitigations include:
    - Automatic sanitization of HTML content even when marked as safe.
    - Clearer and more prominent documentation emphasizing the risks of using `safe` and best practices for sanitization.
    - Static analysis tools or linters to detect potential unsafe usage of `safe`.

- Preconditions:
    1. The Django Unicorn application must have a component that renders user-controlled data or data from an untrusted source.
    2. A developer must have either used `Meta.safe` in the component's view or the `safe` template filter on user-controlled data in the template.
    3. The user-controlled data must not be properly sanitized before being rendered as safe.

- Source Code Analysis:
    1. **`django_unicorn\components\unicorn_template_response.py`**: The `UnicornTemplateResponse._desoupify` method is responsible for rendering the component's HTML. It uses `BeautifulSoup` to parse and encode the HTML.
    ```python
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        @staticmethod
        def _desoupify(soup):
            soup.smooth()
            return soup.encode(formatter=UnsortedAttributes()).decode("utf-8")
    ```
    `UnsortedAttributes` is configured to use `entity_substitution=EntitySubstitution.substitute_html`, which ensures HTML encoding by default.
    2. **`tests\components\test_unicorn_template_response.py`**: The test `test_desoupify` verifies the HTML encoding process. While it doesn't directly test XSS prevention, it demonstrates how HTML entities are encoded:
    ```python
    def test_desoupify():
        html = "<div>&lt;a&gt;&lt;style&gt;@keyframes x{}&lt;/style&gt;&lt;a style=&quot;animation-name:x&quot; onanimationend=&quot;alert(1)&quot;&gt;&lt;/a&gt;!\n</div>\n\n<script type=\"application/javascript\">\n  window.addEventListener('DOMContentLoaded', (event) => {\n    Unicorn.addEventListener('updated', (component) => console.log('got updated', component));\n  });\n</script>"  # noqa: E501
        expected = "<div>&lt;a&gt;&lt;style&gt;@keyframes x{}&lt;/style&gt;&lt;a style=\"animation-name:x\" onanimationend=\"alert(1)\"&gt;&lt;/a&gt;!\n</div>\n<script type=\"application/javascript\">\n  window.addEventListener('DOMContentLoaded', (event) => {\n    Unicorn.addEventListener('updated', (component) => console.log('got updated', component));\n  });\n</script>"  # noqa: E501

        soup = BeautifulSoup(html, "html.parser")

        actual = UnicornTemplateResponse._desoupify(soup)

        assert expected == actual
    ```
    This test confirms that HTML special characters within the component's template are encoded by default, which is the intended XSS mitigation.
    3. However, the `Meta.safe` attribute in `UnicornView` and the `safe` template filter can bypass this default encoding. If a developer uses these features on user-controlled data without proper sanitization, XSS vulnerabilities can be introduced, as demonstrated in the security test case below and the existing test `tests\views\test_process_component_request.py` (mentioned in the previous version of this document).

- Security Test Case:
    1. Create a Django Unicorn component that displays user input. For example, create a component named `xss_test` with the following view (`xss_test.py` in your Django app's `components` directory):
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input",) # <--- Mark user_input as safe, making it vulnerable

        def set_input(self, input_text):
            self.user_input = input_text
    ```
    2. Create a template for the component (`xss_test.html` in your Django app's `templates/unicorn` directory):
    ```html
    <div>
        <input type="text" unicorn:model.defer="user_input" id="user-input">
        <button unicorn:click="set_input(user_input)">Set Input</button>
        <div id="output">
            {{ user_input }} <--- Render user input directly, marked as safe in view
        </div>
    </div>
    ```
    3. Create a Django template that includes the `xss_test` component (`test_xss.html` in your Django app's `templates` directory):
    ```html
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
    4. Create a Django view to render the `test_xss.html` template (e.g., in your app's `views.py`):
    ```python
    from django.shortcuts import render

    def test_xss_view(request):
        return render(request, 'test_xss.html')
    ```
    5. Configure a URL in your `urls.py` to access this view:
    ```python
    from django.urls import path
    from .views import test_xss_view

    urlpatterns = [
        path('test-xss/', test_xss_view, name='test_xss'),
    ]
    ```
    6. Access the `test-xss/` URL in a browser.
    7. In the input field, enter the following JavaScript code: `<img src=x onerror=alert('XSS Vulnerability')>`
    8. Click the "Set Input" button.
    9. Observe that an alert box with "XSS Vulnerability" is displayed, proving that the JavaScript code was executed. This confirms the XSS vulnerability because user-provided input was rendered as raw HTML due to the incorrect use of `Meta.safe`.
