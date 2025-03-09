- Vulnerability Name: Cross-Site Scripting (XSS) in Component Rendering via Template Variables

- Description:
    1. An attacker identifies a Django Unicorn component that renders user-controlled data directly into the HTML template without sufficient sanitization.
    2. The attacker crafts a malicious input containing JavaScript code, for example,  `<img src=x onerror=alert('XSS')>`.
    3. The attacker provides this malicious input through a form field, URL parameter, or any other mechanism that populates a template variable in the Django Unicorn component.
    4. When the component is rendered, the malicious JavaScript is injected into the HTML output because Django Unicorn does not sanitize template variables by default and relies on Django's auto-escaping, which might be bypassed depending on the context or if `safe` filter is used.
    5. If a user views the page containing this component, the malicious JavaScript code will be executed in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

- Impact:
    - High
    - An attacker can execute arbitrary JavaScript code in the browsers of users viewing the affected page.
    - This can lead to a wide range of attacks, including stealing session cookies, performing actions on behalf of the user, and defacing the website.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Django's default template auto-escaping is active, which mitigates some basic XSS attacks by escaping HTML special characters.
    - The documentation mentions security considerations and the necessity of CSRF tokens, but it doesn't explicitly warn against rendering unsanitized user input.
    - The changelog mentions a security fix for CVE-2021-42053 (v0.36.0) to prevent XSS attacks, indicating awareness and past fixes for XSS issues. It also mentions HTML encoding responses.

- Missing Mitigations:
    - Lack of explicit server-side sanitization of user inputs before rendering them in templates, especially for template variables that are intended to be rendered as HTML and not plain text.
    - No clear guidelines in the documentation to developers about sanitizing user inputs within Django Unicorn components to prevent XSS.
    - No built-in mechanism within Django Unicorn to automatically sanitize data rendered in templates. The `safe` filter is mentioned, implying developers need to be aware of when *not* to use it for security.

- Preconditions:
    - A Django Unicorn component must be rendering user-controlled data directly into a template variable.
    - The developer must not have manually sanitized the user-controlled data before passing it to the template or rendering it.
    - The attacker needs to find a way to inject malicious input that is processed by the vulnerable component.

- Source Code Analysis:
    - The provided files don't show specific code implementing sanitization for template variables within the Django Unicorn library itself.
    - `django_unicorn\templatetags\unicorn.py`: This file shows how components are rendered using Django templates, but doesn't include explicit sanitization. Django's template engine auto-escaping would be in effect here, but it is context-dependent and can be bypassed.
    - `django_unicorn\views\views.py`: The `render()` function in `UnicornView` and `UnicornTemplateResponse` are responsible for rendering the component, but these files do not show explicit sanitization of component data before rendering.
    - `django_unicorn\docs\source\templates.md`: This documentation mentions template tags and attributes but lacks a dedicated security section on data sanitization and XSS prevention for template variables. The mention of `safe` filter implies a risk of XSS if used improperly.
    - `django_unicorn\docs\source\changelog.md`: The mention of CVE-2021-42053 and HTML encoding fix in v0.36.0 confirms previous XSS concerns.

- Security Test Case:
    1. Create a Django Unicorn component that displays user input.

        ```python
        # example_app/components/xss_component.py
        from django_unicorn.components import UnicornView

        class XssView(UnicornView):
            user_input = ""
        ```

        ```html
        <!-- example_app/templates/unicorn/xss.html -->
        <div>
            <p>User Input: {{ user_input }}</p>
            <input type="text" unicorn:model="user_input" id="user-input">
        </div>
        ```

    2. Create a Django view to include this component in a page.

        ```python
        # example_app/views.py
        from django.shortcuts import render
        from example_app.components.xss_component import XssView

        def xss_test_view(request):
            return render(request, 'xss_test_page.html')
        ```

        ```html
        <!-- example_app/templates/xss_test_page.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss' %}
        </body>
        </html>
        ```

    3. Access the page and enter the following XSS payload into the input field: `<img src=x onerror=alert('XSS-test')>`
    4. Observe if the JavaScript `alert('XSS-test')` is executed when the component re-renders. If the alert box appears, it confirms the XSS vulnerability.
    5. Examine the HTML source of the page after entering the payload. If the injected JavaScript is present without HTML entity encoding, it further validates the vulnerability. E.g., look for `<p>User Input: <img src=x onerror=alert('XSS-test')></p>`.
