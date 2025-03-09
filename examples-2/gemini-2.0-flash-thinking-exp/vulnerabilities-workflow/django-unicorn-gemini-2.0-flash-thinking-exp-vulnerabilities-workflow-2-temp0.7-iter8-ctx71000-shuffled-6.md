- Vulnerability Name: Cross-Site Scripting (XSS) through Unsafe Template Rendering of `unicorn:model` Data
- Description:
    - Step 1: An attacker crafts malicious JavaScript code, for example: `<img src=x onerror=alert('XSS')>`.
    - Step 2: The attacker inputs this malicious code into a form field within a Django template that is bound to a component property using `unicorn:model`, such as `<input type="text" unicorn:model="user_input">`.
    - Step 3: The user interacts with the component in a way that triggers a server-side update. This could be an input event like `keyup`, `change`, or a blur event, or by triggering an action call that re-renders the component.
    - Step 4: Django-unicorn processes the user input, updates the component's property (`user_input` in this example) on the server-side, and re-renders the component. The `set_property_value` function in `django_unicorn/views/action_parsers/utils.py` and `set_property_from_data` in `django_unicorn/views/utils.py` handle updating component properties based on user input from requests, without performing explicit sanitization at this stage.
    - Step 5: The component template, if it directly renders the `user_input` property within the HTML structure, for example: `<div>{{ user_input }}</div>`, will interpolate the attacker-controlled malicious JavaScript code into the HTML.
    - Step 6: Because the template rendering doesn't perform HTML escaping by default (unless explicitly handled by Django template engine or unicorn), the malicious JavaScript code is injected into the DOM as raw HTML. Django's template engine auto-escaping is the primary mechanism for HTML encoding, but developers might inadvertently bypass it.
    - Step 7: The injected script executes in the victim's browser when the component is re-rendered and the DOM is updated, leading to Cross-Site Scripting. This can result in session hijacking, cookie theft, redirection to malicious websites, or other malicious actions.
- Impact:
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of a user's browser session within the application.
    - This can lead to a wide range of attacks, including:
        - Account takeover by stealing session cookies, session storage tokens, or credentials.
        - Defacement of the web page, altering content and potentially misleading users.
        - Redirection of users to malicious websites, potentially for phishing or malware distribution.
        - Data theft, including sensitive user information displayed on the page or accessible through API calls made by the JavaScript.
        - Installation of malware or drive-by downloads by injecting scripts that exploit browser vulnerabilities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Default HTML Encoding: Django-unicorn documentation states that "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks." This relies on Django's automatic escaping in templates, which is active by default.
    - Opt-out via `safe` Filter/Meta: The library provides mechanisms (`Meta.safe` on the component or the `|safe` template filter) for developers to explicitly disable HTML encoding for specific component properties.
    - CSRF Protection: Django's built-in CSRF protection is mentioned in the documentation as a general security measure for form submissions.
    - `sanitize_html` function: The library includes `django_unicorn/utils.py` with a `sanitize_html` function, used in `django_unicorn/components/unicorn_template_response.py` for sanitizing component initialization script data.
- Missing Mitigations:
    - Explicit Emphasis on Sanitization: The documentation should more strongly emphasize the risks of XSS and the necessity of sanitizing user inputs, especially when using `Meta.safe` or `|safe`.
    - Clear Best Practices for Developers: Provide detailed guidelines on avoiding XSS, particularly when bypassing default sanitization. Include examples of secure sanitization practices when using `safe` and clarify appropriate use cases.
    - Security Test Cases in Documentation and Test Suite: Enhance documentation and test suite with more comprehensive security test cases demonstrating XSS vulnerabilities and prevention methods, covering both default encoding and `safe` usage scenarios.
- Preconditions:
    - The Django application uses django-unicorn for frontend components.
    - A component template renders user-derived data bound via `unicorn:model`.
    - Developers either:
        - Rely solely on default Django template escaping, which might be insufficient in all cases.
        - Use `safe` options (`Meta.safe` or `|safe`) without proper sanitization, incorrectly assuming input safety.
- Source Code Analysis:
    - `django_unicorn/utils.py`'s `sanitize_html` function encodes HTML special characters for component initialization data in `<script>` tags.
    - `tests/views/test_process_component_request.py` includes tests (`test_html_entities_encoded`, `test_safe_html_entities_not_encoded`) verifying HTML encoding behavior, showing default encoding and `Meta.safe`'s disabling effect.
    - `tests/test_utils.py` tests `sanitize_html` function's encoding.
    - `django_unicorn/templatetags/unicorn.py`, `django_unicorn/components/unicorn_view.py`, and `django_unicorn/components/unicorn_template_response.py` handle component rendering. Django's template engine auto-escaping is the default, with `safe` options bypassing unicorn-enforced escaping. `sanitize_html` is for initial JSON data, not general template output.
    - `django_unicorn/views/action_parsers/utils.py`'s `set_property_value` and `django_unicorn/views/utils.py`'s `set_property_from_data` functions manage setting component properties from requests, and they do not include explicit sanitization of user input before it is passed to the component and potentially rendered in templates.
- Security Test Case:
    - Step 1: Set up Vulnerable Component and View:
        - Create `XssUnsafeModelView` component:
            ```python
            # components/xss_unsafe_model.py
            from django_unicorn.components import UnicornView

            class XssUnsafeModelView(UnicornView):
                user_input = ""
            ```
        - Create `unicorn/xss-unsafe-model.html` template:
            ```html
            {# templates/unicorn/xss-unsafe-model.html #}
            <div>
              <input type="text" unicorn:model="user_input" id="user-input">
              <div id="output">Unsafe Output: {{ user_input }}</div>
            </div>
            ```
        - Create `xss_unsafe_view` in `views.py`:
            ```python
            # views.py
            from django.shortcuts import render
            from .components import xss_unsafe_model

            def xss_unsafe_view(request):
                return render(request, 'xss_unsafe_template.html')
            ```
        - Create `xss_unsafe_template.html`:
            ```html
            {# templates/xss_unsafe_template.html #}
            {% load unicorn %}
            <!DOCTYPE html>
            <html>
            <head><title>XSS Test - Unsafe Model</title></head>
            <body>
              {% unicorn 'xss-unsafe-model' %}
              {% unicorn_scripts %}
            </body>
            </html>
            ```
        - Configure URL in `urls.py`:
            ```python
            # urls.py
            from django.urls import path
            from . import views

            urlpatterns = [
                path('xss-unsafe/', views.xss_unsafe_view, name='xss_unsafe_view'),
            ]
            ```
    - Step 2: Access Vulnerable Page: Go to `/xss-unsafe/` in a browser.
    - Step 3: Input XSS Payload: Enter `<img src=x onerror=alert('XSS-Unsafe-Model')>` in the `id="user-input"` field.
    - Step 4: Trigger Component Update: Interact with the input (blur, tab, etc.).
    - Step 5: Observe XSS Execution: Check for an alert box with 'XSS-Unsafe-Model'.
    - Expected Result: Alert box confirms XSS. Input via `unicorn:model` rendered unsafely, JavaScript payload executed.
    - This test demonstrates XSS due to unsafe rendering of `unicorn:model` bound user input, relying on default Django template behavior without explicit sanitization or safe options.
