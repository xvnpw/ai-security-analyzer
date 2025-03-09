## Vulnerability: Server-Side Cross-Site Scripting (XSS) in component rendering

This vulnerability allows an attacker to inject malicious JavaScript code into a Django Unicorn component, leading to Server-Side Cross-Site Scripting (XSS). When a component is rendered on the server side, and it includes unsanitized user-provided data marked as safe, the injected script executes in the user's browser. This can occur when developers mistakenly use the `safe` attribute in the component's `Meta` class or the `safe` template filter with user inputs, bypassing Django's default HTML auto-escaping.  Specifically, user input bound to a component property via `unicorn:model` can become a vector if rendered unsafely in the template.

### Description

- An attacker can inject malicious JavaScript code through user-controlled input fields within a Django Unicorn component. This is typically achieved by providing a crafted input string into a form field that is bound to a component's property using the `unicorn:model` directive.
- When the component is rendered or re-rendered on the server-side, particularly after user interaction triggers an update, the injected JavaScript code is included in the HTML response sent to the user's browser.
- Django templates, by default, apply HTML auto-escaping to prevent XSS. However, Django Unicorn provides mechanisms for developers to explicitly bypass this escaping, namely the `safe` attribute within the `Meta` class of a component and the `safe` template filter.
- If a developer uses the `safe` attribute in a component's `Meta` class to mark a property as safe, or uses the `safe` template filter on user-provided data within the component's template, and this data is not properly sanitized, then the injected JavaScript code will be rendered as raw HTML.
- Upon receiving the server response and rendering the component in the browser, the injected JavaScript code executes within the user's browser context. This occurs because the server-rendered HTML includes the malicious script directly in the page source.

### Impact

- **High**. Successful exploitation of this XSS vulnerability can have severe consequences:
    - **Account Takeover**: Attackers can steal user session cookies or other authentication tokens, enabling them to hijack user accounts and gain unauthorized access.
    - **Data Theft and Manipulation**: Malicious scripts can access sensitive data, including user information and application data, and potentially modify or exfiltrate this data to attacker-controlled servers.
    - **Website Defacement**: Attackers can alter the visual appearance and content of the website, displaying misleading or harmful information, damaging the website's reputation and user trust.
    - **Redirection to Malicious Websites**: Users can be redirected to attacker-controlled websites that may host phishing scams, malware, or further exploit the user's system.
    - **Execution of Arbitrary JavaScript Code**:  The attacker gains the ability to execute arbitrary JavaScript code within the victim's browser, allowing for a wide range of malicious activities limited only by the Same-Origin Policy and browser capabilities. This can lead to further attacks, including but not limited to keylogging, formjacking, and drive-by downloads.

### Vulnerability Rank

- High

### Currently Implemented Mitigations

- **Default HTML Encoding**: Django Unicorn, by default, automatically HTML-encodes updated field values when rendering components. This is a primary defense against XSS attacks as it prevents raw HTML and JavaScript within user input from being interpreted as code by the browser. This default behavior is documented in `docs\source\views.md` and was implemented as a security fix in version 0.36.0 (mentioned in `docs\source\changelog.md`).
- **CSRF Protection**: Django Unicorn uses CSRF (Cross-Site Request Forgery) tokens to protect its endpoints. While CSRF protection is crucial for preventing CSRF attacks, it does not directly mitigate Server-Side XSS vulnerabilities. CSRF protection ensures that requests to the server originate from legitimate user sessions, but it does not sanitize or validate the data processed and rendered by the server, which is the root cause of this XSS vulnerability. CSRF protection is mentioned in `docs\source\faq.md` and `docs\source\troubleshooting.md`.

### Missing Mitigations

- **Explicit Input Sanitization and Validation**: Django Unicorn does not enforce built-in input sanitization or validation beyond Django's template auto-escaping. While Django's auto-escaping is active by default, it is insufficient when developers explicitly bypass it. There is no mandatory or readily available mechanism within Django Unicorn to sanitize user inputs specifically for XSS prevention before rendering, especially when `safe` is used.
- **Warning Against `safe` Misuse**: The documentation (`docs\source\views.md`) mentions the `safe` attribute and filter and how to use them to disable HTML encoding for specific fields or template variables. However, there is a lack of prominent warnings or best practices guidance in the documentation regarding the security risks associated with using `safe` with user-provided or untrusted content. Developers might unknowingly misuse `safe`, believing it is safe for certain use cases without fully understanding the XSS implications when dealing with user inputs.
- **Context-Aware Output Encoding**: While default HTML encoding is present, context-aware output encoding, which adjusts encoding based on the specific HTML context (e.g., HTML tags, attributes, JavaScript contexts), is not explicitly mentioned as a built-in feature or best practice. Deeper context-aware encoding could provide more robust protection in complex scenarios.
- **Content Security Policy (CSP)**: There is no mention of Content Security Policy (CSP) in the provided documentation. Implementing and recommending CSP headers would be a significant enhancement as CSP acts as an additional layer of security to reduce the risk and impact of XSS attacks by controlling the sources from which the browser is allowed to load resources.
- **Developer Education on Secure Coding Practices**:  There's a need for more explicit educational material within Django Unicorn's documentation to guide developers on secure coding practices related to XSS prevention, especially when using features like `safe`. This should include clear examples and recommendations on how to properly sanitize user inputs and avoid common pitfalls when working with dynamic content and Django templates.

### Preconditions

- A Django application using the Django Unicorn library must be deployed and accessible to attackers.
- A Django Unicorn component must be implemented and used within a template to render data that can be influenced by user input. This often involves components that use `unicorn:model` to bind user input fields to component properties.
- The developer must have either:
    - Not implemented any input sanitization or output encoding beyond Django Unicorn's default HTML encoding when rendering user-provided data.
    - Explicitly bypassed Django's default HTML encoding by using the `safe` attribute in the component's `Meta` class or the `safe` template filter on user-provided data within the template. This is a critical precondition because it is the explicit disabling of default protection that creates the vulnerability.
- An attacker needs to be able to control or influence the data that is rendered by the vulnerable component. This is typically achieved through user input fields that are bound to component properties using `unicorn:model`.

### Source Code Analysis

- **`django_unicorn\templatetags\unicorn.py` & `django_unicorn\components\unicorn_template_response.py`**: These files are responsible for the template rendering process of Django Unicorn components.  `UnicornTemplateResponse.render()` handles the rendering of the component's template using Django's template engine. Django's template engine, by default, applies HTML auto-escaping, which is a baseline security measure.
- **`django_unicorn\views\__init__.py`**: The `message` view function is the core handler for AJAX requests in Django Unicorn. When a user interacts with a component, this view processes the request, deserializes the data, calls the appropriate component methods, and importantly, re-renders the component. The `_process_component_request` function within this view is crucial as it orchestrates the component rendering process after user interactions. It uses `component.render(request=request)` to obtain the rendered HTML. This rendering step utilizes Django's template engine and thus inherits its default auto-escaping behavior.
- **`docs\source\views.md` - `Meta.safe`**: This documentation explicitly describes the `Meta.safe` attribute within Django Unicorn components. It clearly states that developers can use this attribute to selectively disable HTML encoding for specific component fields. While intended for rendering trusted HTML, this feature can be a significant vulnerability if misused with untrusted user input. The documentation example, while showing the usage, lacks strong warnings about the security implications of using `safe` with user-generated content.
- **`docs\source\templates.md` - `Templates are normal Django HTML templates`**: This documentation section reinforces that Django Unicorn utilizes standard Django HTML templates for rendering components. While this leverages Django's built-in security features like auto-escaping, it also means developers must be vigilant about secure template practices, especially concerning user input and the usage of `safe` features.

```python
    # django_unicorn\views\__init__.py - _process_component_request

    # ...
    # Get set of attributes that should be marked as `safe`
    safe_fields = []
    if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
        if isinstance(component.Meta.safe, Sequence):
            for field_name in component.Meta.safe:
                if field_name in component._attributes().keys():
                    safe_fields.append(field_name)

    # Mark safe attributes as such before rendering
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))  # noqa: S308

    # Pass the current request so that it can be used inside the component template
    rendered_component = component.render(request=request)
    # ...
```
- The code snippet above from `django_unicorn\views\__init__.py` highlights the processing of `Meta.safe`. It demonstrates that if a field name is listed in `Meta.safe` and its value is a string, the code explicitly calls `mark_safe(value)` from `django.utils.safestring`. `mark_safe` is a Django function that marks a string as safe for HTML rendering, instructing Django's template engine to bypass HTML escaping for this string. If a component variable, such as `user_input`, contains user-provided data and is marked as safe using `Meta: safe = ("user_input", )`, then any HTML or JavaScript code within `user_input` will be rendered without escaping, directly leading to a Server-Side XSS vulnerability.

### Security Test Case

1. **Create a Django Unicorn component that displays user input and incorrectly marks it as safe**:

    ```python
    # example_app/components/xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input", ) # Simulate developer mistake, marking user input as safe.

        def set_input(self, input_value):
            self.user_input = input_value
    ```

    ```html
    {# example_app/templates/unicorn/xss-test.html #}
    <div>
        <input type="text" unicorn:model="user_input" id="user_input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```

2. **Create a Django template to include the component**:

    ```html
    {# example_app/templates/index.html #}
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

3. **Set up URL and view to render the template** (as provided in the initial description):

    ```python
    # example_app/views.py
    from django.shortcuts import render

    def index(request):
        return render(request, 'index.html')
    ```
    ```python
    # example_app/urls.py
    from . import views
    from django.urls import path

    urlpatterns = [
        path('', views.index, name='index'),
    ]
    ```
    ```python
    # project/urls.py (include necessary imports from the initial description)
    from django.contrib import admin
    from django.urls import path, include
    from example_app import urls as example_app_urls
    import django_unicorn.urls

    urlpatterns = [
        path('admin/', admin.site.urls),
        path("unicorn/", include(django_unicorn.urls)),
        path('', include(example_app_urls)),
    ]
    ```

4. **Access the page in a web browser** (e.g., `http://localhost:8000/` if using default Django development server) and enter the following XSS payload into the input field: `<img src=x onerror=alert('XSS Vulnerability!')>`

5. **Observe the result**: An alert box should pop up with the message "XSS Vulnerability!". This confirms that the JavaScript code was executed, successfully demonstrating a Server-Side XSS vulnerability.

    **Alternative Test Payload**: For a less intrusive test, inject: `<script>document.getElementById('output').textContent = 'XSSed!';</script>`. Verify if the text within the `div` with `id="output"` changes to "XSSed!".

6. **Verify Mitigation (Default Encoding)**: Remove or comment out `class Meta: safe = ("user_input", )` from the `XssTestView` component. Repeat steps 4 and 5.  Observe that the alert box no longer appears, and the injected code is rendered as plain text in the `<div>`, like `&lt;img src=x onerror=alert('XSS Vulnerability!')&gt;`. This demonstrates that Django Unicorn's default HTML encoding effectively prevents the XSS vulnerability when `safe` is not misused.

This test case clearly demonstrates how a developer's incorrect use of the `safe` attribute in Django Unicorn can create a Server-Side XSS vulnerability and how the default HTML encoding normally protects against it.
