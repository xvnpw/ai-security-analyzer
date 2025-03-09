## Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via Component Rendering

* Description:
    1. An attacker can craft a malicious string containing JavaScript code.
    2. This malicious string is then passed as data to a django-unicorn component, potentially through user input or URL parameters.
    3. The django-unicorn component renders a template that includes this data without proper sanitization.
    4. When the template is rendered and sent to the user's browser, the malicious JavaScript code embedded in the data is executed.

* Impact:
    * **Critical**:  Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser in the context of the web application. This can lead to account takeover, data theft, malware injection, and other serious security breaches.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    * HTML encoding of updated field values is applied by default. ([views.md#safe], [changelog.md#v0-36-0])

* Missing Mitigations:
    * While HTML encoding is the default, the documentation ([views.md#safe]) indicates that developers can explicitly opt-in to bypass encoding using `safe` Meta attribute or `safe` template filter. If developers use these bypass mechanisms without careful consideration of input sanitization, XSS vulnerabilities can be introduced. There is no clear guidance in the documentation on when and how to use these "safe" mechanisms securely.
    * There is no clear documentation that highlights the risks of using `safe` filter or Meta attribute and best practices for developers.

* Preconditions:
    * A developer must use the `safe` template filter or `safe` Meta attribute in a django-unicorn component template to render user-controlled data without proper output sanitization.
    * The attacker needs to find a vector to inject malicious JavaScript code into the data that is rendered by the vulnerable component.

* Source Code Analysis:
    1. **`django_unicorn\components\unicorn_template_response.py`**: This file is responsible for rendering the component and handling HTML encoding.
    2. **`UnicornTemplateResponse.render()`**: This method is called to render the component.
    3. **`sanitize_html(init)`**: Inside `render()`, the `sanitize_html` function is used to encode initial data being sent to the client-side JavaScript:
        ```python
        json_tag.string = sanitize_html(init)
        ```
    4. **`views.md#safe`**: Documentation mentions `safe` Meta attribute:
        ```
        By default, unicorn HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.
        ```
    5. **`templates.md#templates`**: Documentation mentions `safe` template filter:
        ```html
        <!-- safe-example.html -->
        <div>
          <input unicorn:model="something_safe" />
          {{ something_safe|safe }}
        </div>
        ```
    6. **`v0.36.0` in `changelog.md`**:  Mentions Security fix: for CVE-2021-42053 to prevent XSS attacks and Breaking changes: responses will be HTML encoded going forward.
    7. **Conclusion**: The framework defaults to HTML-encoding to mitigate XSS. However, developers can bypass this using `safe` mechanisms. If `safe` is used with user-provided data without careful sanitization on the backend, XSS is possible.

* Security Test Case:
    1. Create a django-unicorn component that renders a variable named `user_input` in its template and mark it as safe, either with `|safe` filter or `safe` Meta attribute:
        ```html
        {# vulnerable_component.html #}
        <div>
            {{ user_input|safe }}
        </div>
        ```
        ```python
        # vulnerable_component.py
        from django_unicorn.components import UnicornView

        class VulnerableComponentView(UnicornView):
            user_input = ""
        ```
    2. In a Django view, render the vulnerable component and pass user-controlled input to the `user_input` variable:
        ```python
        # views.py
        from django.shortcuts import render
        from .components import VulnerableComponentView

        def vulnerable_view(request):
            user_controlled_data = request.GET.get('input', '') # User input from query parameter
            return render(request, 'vulnerable_template.html', {'user_input_template': user_controlled_data})
        ```
        ```html
        {# vulnerable_template.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'vulnerable-component' user_input=user_input_template %}
        </body>
        </html>
        ```
        ```python
        # urls.py
        from django.urls import path
        from . import views
        from unicorn.components.vulnerable_component import VulnerableComponentView

        urlpatterns = [
            path('vulnerable/', views.vulnerable_view, name='vulnerable_view'),
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    3. As an attacker, access the vulnerable view with a crafted URL that includes malicious JavaScript in the `input` parameter:
        ```
        https://example.com/vulnerable/?input=<script>alert("XSS")</script>
        ```
    4. Observe that an alert box with "XSS" is displayed in the browser, indicating successful execution of the injected JavaScript code, confirming XSS vulnerability.
