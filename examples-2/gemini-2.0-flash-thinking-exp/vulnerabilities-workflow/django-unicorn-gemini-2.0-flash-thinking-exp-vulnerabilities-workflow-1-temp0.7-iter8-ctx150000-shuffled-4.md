### Vulnerability List for django-unicorn project:

* Vulnerability Name: Cross-Site Scripting (XSS) via unsafe HTML attributes in component templates

* Description:
    1. An attacker can inject malicious JavaScript code into HTML attributes within a django-unicorn component template.
    2. When the component is rendered or updated, the injected JavaScript will be executed in the user's browser.
    3. This can occur if user-controlled data is directly used to construct HTML attributes without proper sanitization in component templates.

* Impact:
    * High
    * An attacker can execute arbitrary JavaScript code in the context of a user's session.
    * This can lead to account hijacking, data theft, session manipulation, defacement of the website, or redirection to malicious sites.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    * Responses are HTML encoded going forward (since version 0.36.0) to prevent XSS attacks in rendered HTML content. This is mentioned in `docs\source\changelog.md` and `docs\source\views.md`.
    * The `safe` meta attribute and template filter are provided to explicitly allow unencoded HTML, requiring developers to opt-in to potentially unsafe behavior. This is documented in `docs\source\views.md`.

* Missing Mitigations:
    * The current HTML encoding mitigation primarily focuses on the content rendered within HTML tags. It does not explicitly prevent XSS vulnerabilities arising from dynamically constructed HTML attributes within component templates.
    * There is no explicit guidance or automated mechanism to prevent developers from using unsanitized user input directly within HTML attributes in component templates.

* Preconditions:
    * A developer must use user-controlled data to dynamically generate HTML attributes within a django-unicorn component template without proper sanitization.
    * An attacker needs to control or influence this user-controlled data, which is typically done by manipulating input fields that are bound to component properties used in attribute rendering.

* Source Code Analysis:
    1. **File: `django_unicorn\components\unicorn_template_response.py`**: This file is responsible for rendering django-unicorn components.
        - The `UnicornTemplateResponse.render` method renders the component's template.
        - It uses `BeautifulSoup` to parse and manipulate the HTML content.
        - It adds `unicorn:id`, `unicorn:name`, `unicorn:key`, `unicorn:checksum`, `unicorn:data`, and `unicorn:calls` attributes to the root element of the component. These attributes are essential for django-unicorn's functionality.
        - While the response content is encoded to prevent XSS in HTML content, there is no specific sanitization or encoding applied to the values being inserted into HTML attributes.
    2. **File: `django_unicorn\views\message.py`**: This file handles AJAX requests to the `/message` endpoint.
        - It receives user interactions and updates component state or calls methods.
        - It uses `ComponentRequest` to parse and validate the incoming request data.
        - It calls action parsers (like `call_method.py`) to process actions requested by the client.
        - The response includes the updated DOM and component data. While the DOM is re-rendered, the attribute values dynamically constructed in templates are not explicitly sanitized before being sent back to the client.
    3. **File: Example Templates (`example\unicorn\components` and `tests\templates`)**: Reviewing these templates, there's no consistent use of sanitization functions when dynamically constructing HTML attributes. This highlights the risk if developers are not explicitly aware of the need to sanitize attribute values.

    ```python
    # Example vulnerable code in a component template (hypothetical, not present in provided files, but illustrates the vulnerability)
    <div id="user-content" data-attribute="{{ user_provided_attribute }}">
        ...
    </div>
    ```
    In this example, if `user_provided_attribute` is directly derived from user input and contains malicious JavaScript (e.g., `<script>alert("XSS")</script>`), it will be injected into the `data-attribute` without sanitization. When the browser parses this HTML, or if JavaScript code interacts with this attribute, the malicious script can be executed, leading to XSS.

* Security Test Case:
    1. Create a django-unicorn component that dynamically sets an HTML attribute based on a component property.
    ```python
    # example_component.py
    from django_unicorn.components import UnicornView

    class ExampleComponentView(UnicornView):
        dynamic_attribute = ""
    ```
    ```html
    <!-- unicorn/example_component.html -->
    <div>
        <div id="test-attribute" data-custom="{{ dynamic_attribute }}">Test Attribute</div>
    </div>
    ```
    2. Create a view and template to render this component at a publicly accessible URL.
    ```python
    # views.py
    from django.shortcuts import render
    from django.views.generic import TemplateView
    from .components.example_component import ExampleComponentView  # adjust import path
    from django.urls import path

    class ExampleView(TemplateView):
        template_name = 'example.html'

        def get_context_data(self, **kwargs):
            context = super().get_context_data(**kwargs)
            context['component'] = ExampleComponentView(component_name="example-component", component_id="example-component-id")
            return context

    urlpatterns = [
        path('example/', ExampleView.as_view(), name='example-view'), # Publicly accessible URL
    ]

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
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            let maliciousAttribute = document.getElementById('test-attribute').getAttribute('data-custom');
            if (maliciousAttribute && maliciousAttribute.includes('<script>')) {
                alert('XSS Vulnerability Detected in HTML Attribute!');
            }
        });
        </script>
    </body>
    </html>
    ```
    3. Create a component action to set `dynamic_attribute` with malicious input.
    ```python
    # example_component.py (updated)
    from django_unicorn.components import UnicornView

    class ExampleComponentView(UnicornView):
        dynamic_attribute = ""

        def mount(self):
            pass

        def trigger_xss(self):
            self.dynamic_attribute = '<script>alert("XSS in attribute")</script>'
    ```
    ```html
    <!-- unicorn/example_component.html (updated) -->
    <div>
        <div id="test-attribute" data-custom="{{ dynamic_attribute }}">Test Attribute</div>
        <button unicorn:click="trigger_xss">Trigger XSS</button>
    </div>
    ```
    4. Access the page at the publicly accessible URL `/example/` in a browser as an external attacker.
    5. Click the "Trigger XSS" button. This simulates a user interaction that triggers the vulnerable code path.
    6. Observe if the alert box "XSS Vulnerability Detected in HTML Attribute!" appears, indicating that the JavaScript injected via the HTML attribute was executed.

* Missing Mitigations:
    * Implement automatic sanitization for user-provided data used within HTML attributes in component templates. This could involve using Django's built-in HTML escaping or a more robust sanitization library specifically for attributes.
    * Provide developer guidelines and documentation emphasizing the importance of sanitizing user inputs before using them in HTML attributes within django-unicorn components.
    * Consider adding template linting or security checks that warn developers about potentially unsafe attribute constructions.
