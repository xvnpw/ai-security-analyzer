- Vulnerability Name: Cross-Site Scripting (XSS) in Component Property Rendering

- Description:
    1. An attacker can inject malicious Javascript code into a component property, for example, by manipulating URL parameters or form inputs that get bound to a component property.
    2. When the component re-renders, the injected Javascript code is dynamically rendered into the HTML template without sufficient sanitization in specific contexts.
    3. If a user views the page with the malicious component, the injected Javascript code will be executed in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

- Impact:
    - High: Successful exploitation can lead to Cross-Site Scripting (XSS), allowing the attacker to execute arbitrary Javascript code in the victim's browser. This can result in session hijacking, defacement, redirection to malicious sites, or theft of sensitive information.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding is applied by default to component responses since version v0.36.0 (CVE-2021-42053) to prevent XSS. This is mentioned in `docs\source\changelog.md` and `docs\source\views.md` (not provided in project files, based on previous context). The `safe` attribute in `Meta` class or the `|safe` template filter can be used to opt-out of encoding for specific fields, as described in `docs\source\views.md` (not provided in project files, based on previous context).

- Missing Mitigations:
    - While default HTML encoding is a good general mitigation, context-aware output encoding is not explicitly implemented or enforced in all scenarios. It is important to ensure that encoding is applied correctly based on the context where the data is rendered in the template (e.g., HTML elements, attributes, Javascript code, CSS).
    - Consider using Content Security Policy (CSP) headers to further mitigate XSS risks by controlling the sources from which the browser is allowed to load resources.
    - Input validation and sanitization on the server-side should be enforced before data is used to update component properties, although Django forms validation is supported as documented in `docs\source\validation.md` (not provided in project files, based on previous context).

- Preconditions:
    - A Django Unicorn component is rendering user-controlled data dynamically in a template.
    - The rendered data is not properly sanitized or escaped before being included in the HTML output in certain contexts like HTML attributes or Javascript event handlers, even with default HTML encoding, context-aware encoding might be missing.

- Source Code Analysis:
    - The file `django_unicorn\views\__init__.py` (not provided in project files, based on previous context, assuming similar functionality) likely handles incoming requests and initiates the component rendering process. It interacts with `django_unicorn\components\unicorn_view.py` to manage component lifecycle and rendering.
    - `django_unicorn\components\unicorn_view.py`'s `render` method is responsible for rendering the component. It calls `render_to_response`, which utilizes `UnicornTemplateResponse` (file not provided).
    - Within `django_unicorn\components\unicorn_view.py`, the `get_context_data` method prepares the context for template rendering, including component attributes and methods. The `get_frontend_context_variables` method serializes component attributes for frontend updates.
    - The `_attributes` method in `django_unicorn\components\unicorn_view.py` retrieves public attributes of the component, which are then passed to the template. It's crucial to ensure that these attributes, especially if derived from user input, are properly encoded when rendered in the template.
    - The provided files do not contain the template rendering logic directly, specifically `UnicornTemplateResponse`, so the exact mechanism of HTML encoding and context-aware output encoding cannot be fully analyzed from these files alone. However, the documentation snippets (from `CURRENT_VULNERABILITIES`) indicate awareness of XSS risks and implementation of default HTML encoding as a general mitigation.
    - Deeper analysis of the template rendering process, specifically how template variables are handled and integrated with `morphdom` for DOM updates, is required to fully assess the robustness of XSS mitigations, especially regarding context-aware encoding in attributes and event handlers.

- Security Test Case:
    1. Create a Django Unicorn component that displays a property named `user_input` in its template:
        ```python
        # example_component.py
        from django_unicorn.components import UnicornView

        class ExampleComponentView(UnicornView):
            user_input = ""
        ```
        ```html
        <!-- example_component.html -->
        <div>
          <p>User Input: {{ user_input }}</p>
        </div>
        ```
    2. Create a view and template to include this component.
    3. In the view, set the `user_input` property based on a URL parameter:
        ```python
        # views.py
        from django.shortcuts import render
        from unicorn.components.example_component import ExampleComponentView

        def example_view(request):
            component = ExampleComponentView(component_name="example-component", component_id="example-component-id")
            component.user_input = request.GET.get('input', '')
            return render(request, 'example.html', {'unicorn': component})
        ```
        ```html
        <!-- example.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn component %}
        </body>
        </html>
        ```
    4. Access the URL with a malicious Javascript payload in the `input` parameter: `/example-url/?input=<script>alert("XSS")</script>`
    5. Inspect the rendered HTML source or use browser developer tools to see if the Javascript code is executed as an alert.
    6. If the alert "XSS" is displayed, it indicates that the input is not being properly sanitized, and the XSS vulnerability exists.
    7. To verify mitigation, check if the output in the HTML source is HTML-encoded (e.g., `&lt;script&gt;alert("XSS")&lt;/script&gt;` instead of `<script>alert("XSS")</script>`). If it is encoded, the default mitigation is working for simple text rendering.
    8. To test for context-aware encoding issues and bypass default mitigation, try to inject XSS in HTML attributes or event handlers if the framework allows rendering user input in such contexts. For example, modify `example_component.html` to include user input in an attribute:
        ```html
        <!-- example_component.html -->
        <div>
          <p title="{{ user_input }}">User Input: {{ user_input }}</p>
        </div>
        ```
        and access the URL with `/example-url/?input=" onclick="alert('XSS')"`. Then check if the `onclick` event is injected and executable, or properly encoded. Further tests can include event handlers like `onerror` in `<img>` tags and different HTML contexts to assess the completeness of XSS mitigation.
