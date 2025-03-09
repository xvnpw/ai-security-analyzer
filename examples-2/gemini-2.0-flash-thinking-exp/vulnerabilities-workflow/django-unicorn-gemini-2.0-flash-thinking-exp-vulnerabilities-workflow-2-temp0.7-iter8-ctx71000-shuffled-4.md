- Vulnerability Name: Potential XSS vulnerability when using `safe` Meta option
- Description:
    1. A developer uses the `safe` Meta option in a Django-unicorn component to disable HTML entity encoding for specific variables. This is often done to allow rendering of HTML content.
    2. The template for this component renders these variables directly using template tags like `{{ variable }}` without any additional sanitization.
    3. An attacker provides malicious JavaScript code as user input, which gets bound to one of these `safe` variables through user interactions like form inputs or URL parameters.
    4. When the component re-renders (either on initial load or after an update), the malicious JavaScript code is injected directly into the HTML output without being escaped.
    5. The user's browser executes this malicious script, leading to Cross-Site Scripting (XSS).
- Impact:
    Cross-Site Scripting (XSS). Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view the affected page. This can lead to:
    - Session hijacking: Stealing user session cookies to impersonate the victim.
    - Data theft: Accessing sensitive information from the page or making requests to backend services on behalf of the victim.
    - Defacement: Altering the content of the web page to mislead or harm users.
    - Redirection to malicious websites: Redirecting users to attacker-controlled sites for phishing or malware distribution.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Default HTML Entity Encoding: Django-unicorn, by default, automatically encodes HTML entities for variables rendered in templates. This is a standard security practice that prevents basic XSS attacks by escaping characters that have special meaning in HTML, such as `<`, `>`, `&`, `"`, and `'`.
    - `sanitize_html` function: The `sanitize_html` function in `django_unicorn/utils.py` is used to escape HTML entities in JSON data that is embedded within `<script>` tags for component initialization. This helps to protect against XSS in the component's initialization script, but is not applied to template rendering with `safe` option.
- Missing Mitigations:
    - Security Warning in Documentation: There is no explicit warning in the official documentation to strongly caution developers about the security implications of using the `safe` Meta option. Developers might not fully understand the risks associated with disabling HTML entity encoding, potentially leading to unintentional vulnerabilities.
    - Automatic Sanitization for `safe` variables: Django-unicorn lacks a built-in mechanism to automatically sanitize variables that are marked as `safe`. If developers intend to render user-provided HTML and want to allow some HTML tags while preventing XSS, they need to implement custom sanitization logic themselves. This increases the chance of developers making mistakes and introducing vulnerabilities.
    - Security Test Cases and Best Practices: The project could benefit from more comprehensive security test cases specifically targeting the `safe` Meta option to ensure that it is used correctly and securely. Additionally, providing best practice guidelines in the documentation would help developers to avoid common pitfalls when using `safe`.
- Preconditions:
    - `safe` Meta option is enabled: A Django-unicorn component must have the `safe` Meta option enabled for at least one variable.
    - Direct rendering of user input: The component's template must directly render a variable marked as `safe` that is influenced by user input, without any additional sanitization or escaping.
    - User interaction: An attacker needs to be able to influence the value of the `safe` variable, typically through user input fields, URL parameters, or other means of data binding.
- Source Code Analysis:
    - `django_unicorn\components\unicorn_template_response.py`: This file is responsible for rendering the component's template and processing the output. It uses Django's template engine, which by default, auto-escapes HTML. However, Django-unicorn's `safe` Meta option bypasses this default behavior for specified variables. The `UnicornTemplateResponse._desoupify` method within this file, which converts the BeautifulSoup object back to a string, does not include any HTML sanitization logic, further confirming that variables marked as `safe` are rendered as raw HTML.
    - `tests\views\test_process_component_request.py`: The test suite includes tests like `test_safe_html_entities_not_encoded` which explicitly demonstrates how the `safe` Meta option prevents HTML entities from being encoded. This test confirms that variables marked as `safe` are rendered as raw HTML, which can be dangerous if the content is not properly sanitized and is user-controlled.
    - Code snippet from `tests\views\test_process_component_request.py`:
      ```python
      def test_safe_html_entities_not_encoded(client):
          data = {"hello": "test"}
          action_queue = [
              {
                  "payload": {"name": "hello", "value": "<b>test1</b>"},
                  "type": "syncInput",
              }
          ]
          response = post_and_get_response(
              client,
              url="/message/tests.views.test_process_component_request.FakeComponentSafe",
              data=data,
              action_queue=action_queue,
          )

          assert not response["errors"]
          assert response["data"].get("hello") == "<b>test1</b>"
          assert "<b>test1</b>" in response["dom"] # <--- "<b>test1</b>" is rendered directly without encoding because of `safe`
      ```
    - `django_unicorn\utils.py`: This file contains `sanitize_html` function. While this function exists and can be used for sanitization, it is not automatically applied to variables marked as `safe`. Developers must manually use this or similar sanitization functions when using `safe`, increasing the risk of overlooking sanitization and introducing XSS vulnerabilities.
    - `django_unicorn\views\__init__.py`: This file processes component requests and handles rendering. The code snippet below shows how `safe` fields are marked as safe using `mark_safe` without any sanitization:
      ```python
      # Mark safe attributes as such before rendering
      for field_name in safe_fields:
          value = getattr(component, field_name)
          if isinstance(value, str):
              setattr(component, field_name, mark_safe(value))  # noqa: S308
      ```
- Security Test Case:
    1. Create a new Django app (e.g., `vuln_test`) and add it to `INSTALLED_APPS`.
    2. Inside `vuln_test`, create a `components` directory and a file named `xss_component.py`.
    3. Define the following component code in `xss_component.py`:
        ```python
        from django_unicorn.components import UnicornView

        class XSSComponentView(UnicornView):
            unsafe_data: str = ""

            class Meta:
                safe = ("unsafe_data",)
        ```
    4. Create a template for this component in `vuln_test/templates/unicorn/xss-component.html`:
        ```html
        <div>
            <p>Unsafe Data: {{ unsafe_data }}</p>
        </div>
        ```
    5. Create a view in `vuln_test/views.py` to render this component:
        ```python
        from django.shortcuts import render
        from vuln_test.components.xss_component import XSSComponentView

        def xss_test_view(request):
            return render(request, 'vuln_test/xss_test.html', {"component_name": "vuln_test.components.xss_component.XSSComponentView"})
        ```
    6. Create a template `vuln_test/templates/xss_test.html`:
        ```html
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Test</title>
        </head>
        <body>
            <h1>XSS Vulnerability Test</h1>
            {% unicorn component_name %}
            {% unicorn_scripts %}
        </body>
        </html>
        ```
    7. Configure URLs in `vuln_test/urls.py`:
        ```python
        from django.urls import path
        from . import views

        urlpatterns = [
            path('xss-test/', views.xss_test_view, name='xss_test_view'),
        ]
        ```
    8. Include `vuln_test.urls` in the main `project/urls.py`:
        ```python
        path('vuln/', include('vuln_test.urls')),
        ```
    9. Run the Django development server.
    10. Access the URL `/vuln/xss-test/` in your browser. Initially, you will see "Unsafe Data: ".
    11. Open browser's developer tools (e.g., Chrome DevTools) and go to the "Console" tab.
    12. In the browser's address bar, append the following query parameter to the URL: `?unsafe_data=%3Cscript%3Ealert(%22XSS%22)%3C%2Fscript%3E` which decodes to `?unsafe_data=<script>alert("XSS")</script>`. The full URL will be something like `http://localhost:8000/vuln/xss-test/?unsafe_data=%3Cscript%3Ealert("XSS")</script>`.
    13. Reload the page.
    14. Observe that an alert box with "XSS" appears, indicating that the JavaScript code was executed.
    15. Inspect the HTML source of the page using developer tools. You will see that the `<script>alert("XSS")</script>` is rendered directly within the `<p>Unsafe Data: ...</p>` tag, without HTML entity encoding, confirming the XSS vulnerability.
