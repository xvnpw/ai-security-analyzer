### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) due to `safe` Meta option

- Description:
    1. A developer uses the `safe` option in a django-unicorn component's `Meta` class to disable HTML encoding for a specific field.
    2. This field, intended to be "safe", is rendered in the component's template using template tags like `{{ field_name }}`.
    3. User input is directly or indirectly assigned to this component field, for example through `unicorn:model` binding or programmatically in the component's view.
    4. An attacker crafts malicious JavaScript code as user input.
    5. When the component re-renders and includes the attacker's input (now assigned to the `safe` field), the malicious script is rendered in the HTML without HTML encoding because the `safe` option is enabled.
    6. The victim's browser executes the injected JavaScript code, leading to Cross-Site Scripting.

- Impact:
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser when they interact with the vulnerable django-unicorn component.
    - This can lead to various malicious activities, including:
        - Session hijacking: Stealing session cookies to impersonate the victim and gain unauthorized access to their account.
        - Data theft: Accessing sensitive information displayed on the page or making requests to backend servers on behalf of the victim.
        - Defacement: Altering the content of the web page visible to the victim.
        - Redirection to malicious websites: Redirecting the victim to attacker-controlled websites, potentially for phishing or malware distribution.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, django-unicorn automatically HTML-encodes all data rendered in templates to prevent XSS. This is a strong default mitigation.
    - The documentation mentions the `safe` option and implicitly warns against its misuse by describing it as a way to "explicitly opt-in to previous behavior" (before HTML encoding was enforced).

- Missing Mitigations:
    - **Explicit Security Warning in Documentation:** The documentation for the `safe` option should include a clear and prominent security warning about the risks of disabling HTML encoding and when it is absolutely necessary and safe to use it. It should emphasize that using `safe` on user-controlled data is highly discouraged and can lead to XSS vulnerabilities.
    - **Code Analysis Tooling/Linting:** Consider adding a linting rule or a security check that can detect components using the `safe` option, especially if the field marked as `safe` is associated with user inputs (e.g., used with `unicorn:model`). This would help developers identify potential XSS risks during development.

- Preconditions:
    1. Django application uses django-unicorn.
    2. A django-unicorn component is implemented with a `Meta` class.
    3. The `Meta` class of the component includes a `safe` tuple that lists one or more component fields.
    4. At least one field listed in the `safe` tuple is rendered in the component's template.
    5. The value of the `safe` field can be influenced by user input, either directly or indirectly.

- Source Code Analysis:
    - Based on the documentation (`docs/source/views.md` and `docs/source/changelog.md`), the `safe` Meta option is the intended mechanism to bypass the default HTML encoding.
    - The changelog for version `0.36.0` indicates that HTML encoding was introduced as a security fix for a previous XSS vulnerability, and the `safe` option was introduced to allow developers to opt-out of this encoding when necessary.
    - Examining `django_unicorn/components/unicorn_template_response.py`, the `UnicornTemplateResponse.render()` method is responsible for rendering the component and includes logic for adding attributes like `unicorn:data` and `unicorn:calls` to the root element. While this class handles template rendering and manipulation using BeautifulSoup, it does not directly manage HTML encoding or the `safe` option. The `_desoupify` method in this class handles HTML entities for serializing the DOM, but not for initial rendering in the context of the `safe` option.
    - `django_unicorn/utils.py` includes a `sanitize_html()` function. This function uses `html.translate(_json_script_escapes)` and `mark_safe()`. This function is specifically used to escape HTML special characters for JSON output, particularly for the `json_script` template tag, and is not related to general template rendering or the `safe` option's behavior in component templates.
    - `django_unicorn/templatetags/unicorn.py` contains the `unicorn` template tag, which is used to render components in Django templates. The `UnicornNode.render()` method in this file is responsible for creating and rendering the component. It calls `UnicornView.create()` to instantiate the component and then `component.render()` to render it. The template tag rendering process itself does not include explicit HTML encoding or bypass of it, suggesting the encoding logic and `safe` option handling resides within the `UnicornView` class or Django's template engine.
    - `django_unicorn/tests/views/test_process_component_request.py` includes tests that demonstrate the behavior of the `safe` option. The `test_safe_html_entities_not_encoded` test explicitly uses a `FakeComponentSafe` with `Meta: safe = ("hello",)` and verifies that HTML entities are *not* encoded when this option is enabled, confirming the intended functionality and potential XSS risk when used with user input.
    - The key logic for HTML encoding and the `safe` option is likely within the `UnicornView` class and its rendering process, specifically in how component attributes are passed to the template context and how Django's template engine handles them. Further investigation of `django_unicorn/components/unicorn_view.py` and how template context is created and rendered is needed to pinpoint the exact location of the `safe` option implementation and confirm the XSS vulnerability.

- Security Test Case:
    1. Create a new Django app named `vulntest` and add it to `INSTALLED_APPS`.
    2. Create a django-unicorn component named `xss_safe` within the `vulntest` app using the management command: `python manage.py startunicorn vulntest xss_safe`.
    3. Modify `vulntest/components/xss_safe.py` to include a `safe` field and the `Meta` class with the `safe` option enabled for this field:

    ```python
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",)
    ```

    4. Modify `vulntest/templates/unicorn/xss_safe.html` to render the `unsafe_data` field:

    ```html
    <div>
        <input type="text" unicorn:model="unsafe_data">
        <p>Unsafe Data: {{ unsafe_data }}</p>
    </div>
    ```

    5. Create a Django view in `vulntest/views.py` and a corresponding template `vulntest/templates/index.html` to include the `xss_safe` component:

    ```python
    # vulntest/views.py
    from django.shortcuts import render
    from django.views.generic import TemplateView

    class IndexView(TemplateView):
        template_name = 'index.html'

    index_view = IndexView.as_view()
    ```

    ```html
    {# vulntest/templates/index.html #}
    {% load unicorn %}
    <html>
    <head>
        <title>XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-safe' %}
    </body>
    </html>
    ```

    6. Configure `urls.py` to include the `index_view`:

    ```python
    # urls.py
    from django.urls import path, include
    from vulntest.views import index_view

    urlpatterns = [
        path("unicorn/", include("django_unicorn.urls")),
        path('', index_view, name='index'),
    ]
    ```

    7. Run the Django development server: `python manage.py runserver`.
    8. Access the page in a browser: `http://127.0.0.1:8000/`.
    9. In the input field, enter the following XSS payload: `<img src=x onerror=alert('XSS-Vulnerability')>`.
    10. Click outside the input field or trigger an update (depending on the model modifier used, if any).
    11. **Expected Result:** An alert box with the message "XSS-Vulnerability" should appear, demonstrating that the JavaScript code was executed because HTML encoding was bypassed by the `safe` option, confirming the XSS vulnerability.
