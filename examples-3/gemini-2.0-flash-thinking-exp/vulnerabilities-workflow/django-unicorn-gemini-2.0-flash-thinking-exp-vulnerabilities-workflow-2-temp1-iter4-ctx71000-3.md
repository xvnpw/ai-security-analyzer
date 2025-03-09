- Vulnerability Name: Cross-Site Scripting (XSS) due to unsafe usage of `safe` meta attribute

- Description:
    1. django-unicorn by default HTML encodes component data to prevent XSS, as stated in `changelog.md` for version 0.36.0 and `views.md`.
    2. The `safe` meta attribute in `UnicornView` or the `|safe` template filter can be used to explicitly disable HTML encoding for specific component properties or template variables, as documented in `views.md`.
    3. If a developer uses the `safe` meta attribute or `|safe` filter on a component property or template variable that is derived from unsanitized user input, it can lead to Cross-Site Scripting (XSS).
    4. An attacker can inject malicious JavaScript code as user input.
    5. If this input is bound to a component property marked as `safe` or rendered with `|safe` filter, the JavaScript code will be rendered without HTML encoding.
    6. When a user views the page, the injected JavaScript code will be executed in their browser, leading to XSS.

- Impact:
    - Successful XSS attack can allow the attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to stealing user session cookies, performing actions on behalf of the user, defacing the website, or redirecting the user to malicious websites.
    - In the context of django-unicorn, if an admin user is targeted, the attacker might gain administrative privileges depending on the application's functionalities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, django-unicorn HTML encodes all component data, as mentioned in `changelog.md` and `views.md`, which is a significant mitigation against XSS.
    - The documentation in `views.md` warns against putting sensitive data into public properties and mentions `Meta.exclude` and `Meta.javascript_exclude` as ways to control data exposure, which indirectly helps in reducing the attack surface for XSS.
    - The server-side code uses `sanitize_html` function in `django_unicorn/utils.py` to sanitize component data before sending it to the frontend, as seen in `django_unicorn/views/__init__.py`. However, this sanitization is bypassed for properties marked as `safe`.

- Missing Mitigations:
    - There is no explicit server-side sanitization of user inputs within the django-unicorn library itself when the `safe` attribute is used.
    - The library relies on developers to use Django's form validation and to be careful when using the `safe` meta attribute or `|safe` template filter.
    - There is no built-in mechanism to automatically detect or warn developers about potential unsafe usage of `safe` with user-controlled data.

- Preconditions:
    1. The developer must use the `safe` meta attribute in `UnicornView` or the `|safe` template filter in the template.
    2. The component property marked as `safe` or template variable rendered with `|safe` filter must be directly or indirectly populated with unsanitized user input.
    3. An attacker must be able to provide malicious JavaScript code as user input.

- Source Code Analysis:
    - **django_unicorn/serializer.py**: The `dumps` function serializes data and by default HTML encodes it.
    - **django_unicorn/views/__init__.py**:
        - The `message` view in `django_unicorn/views/__init__.py` processes component requests.
        - The `_process_component_request` function within `message` view is responsible for handling actions and rendering the component.
        - Inside `_process_component_request`, after actions are processed, the code retrieves `safe_fields` from `component.Meta.safe`.
        - It iterates through `safe_fields` and uses `mark_safe` from `django.utils.safestring` to mark the corresponding component attributes as safe.
        ```python
        # django_unicorn/views/__init__.py
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
        ```
        - This code block explicitly disables HTML escaping for properties listed in `Meta.safe`, making them vulnerable to XSS if they contain unsanitized user input.
        - The `_process_component_request` function also calls `sanitize_html(component_data)` to sanitize the component data. However, `mark_safe` is applied after sanitization, effectively bypassing it for `safe` fields.
    - **django_unicorn/components/unicorn_view.py**: The `UnicornView` class and its `Meta` class define the `safe` attribute, allowing developers to specify properties that should not be HTML encoded.
    - **django_unicorn/templatetags/unicorn.py**: The `unicorn` template tag is used to render components in Django templates. It does not perform any additional HTML encoding or sanitization beyond what is already handled by Django's template engine, which by default HTML encodes variables unless `|safe` filter is used or the variable is marked as safe.
    - **django_unicorn/views/action_parsers/sync_input.py**: The `sync_input.handle` function sets component properties based on user input from the frontend. This is where user-provided data is directly bound to component properties. If these properties are marked as `safe`, any malicious script in the user input will be rendered without encoding.

- Security Test Case:

    1. Create a new Django app and integrate django-unicorn as per the documentation's "Getting Started" and "Installation" guides.
    2. Create a new unicorn component named `unsafe_safe_component` using `python manage.py startunicorn myapp unsafe_safe_component`.
    3. Modify the component view `myapp/components/unsafe_safe_component.py` to include a property `unsafe_data` and a `Meta` class with `safe = ("unsafe_data",)`.

    ```python
    # myapp/components/unsafe_safe_component.py
    from django_unicorn.components import UnicornView

    class UnsafeSafeComponentView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",)

        def mount(self):
            if "user_input" in self.component_kwargs:
                self.unsafe_data = self.component_kwargs["user_input"]
    ```

    4. Modify the component template `myapp/templates/unicorn/unsafe-safe-component.html` to render the `unsafe_data` property:

    ```html
    {# myapp/templates/unicorn/unsafe-safe-component.html #}
    <div>
        <p>Unsafe Data: {{ unsafe_data }}</p>
    </div>
    ```

    5. Create a Django view in `myapp/views.py` to render a template that includes the `unsafe_safe_component` and passes user input as a component kwarg.

    ```python
    # myapp/views.py
    from django.shortcuts import render
    from django.http import HttpRequest

    def unsafe_view(request: HttpRequest):
        user_input = request.GET.get("input", "")
        return render(request, "myapp/unsafe_template.html", {"user_input": user_input})
    ```

    6. Create a Django template `myapp/templates/myapp/unsafe_template.html`:

    ```html
    {# myapp/templates/myapp/unsafe_template.html #}
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Unsafe Safe XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        <h1>Unsafe Safe Component Test</h1>
        {% unicorn 'unsafe-safe-component' user_input=user_input %}
    </body>
    </html>
    ```

    7. Configure `urls.py` in `myapp` and project-level `urls.py` to include the new view.

    ```python
    # myapp/urls.py
    from django.urls import path
    from . import views

    urlpatterns = [
        path('unsafe/', views.unsafe_view, name='unsafe_view'),
    ]
    ```

    ```python
    # project/urls.py
    from django.contrib import admin
    from django.urls import path, include

    urlpatterns = [
        path('admin/', admin.site.urls),
        path('unicorn/', include('django_unicorn.urls')),
        path('unsafe-xss/', include('myapp.urls')), # Include myapp urls
    ]
    ```

    8. Run the Django development server (`python manage.py runserver`).
    9. Access the URL `/unsafe-xss/unsafe/?input=<script>alert("XSS Vulnerability")</script>` in a web browser.
    10. Observe that an alert box with "XSS Vulnerability" is displayed, proving that JavaScript code injected via the `input` query parameter was executed. This is because `unsafe_data` was marked as `safe`, and user-provided input was passed to it without sanitization, resulting in XSS.

This test case demonstrates a successful XSS attack due to the unsafe usage of the `safe` meta attribute. Developers need to be extremely cautious when using `safe` and ensure that data marked as safe is either inherently safe or properly sanitized before being rendered.
