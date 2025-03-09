- Vulnerability Name: Unsafe HTML Rendering via `safe` Meta Option
- Description:
    1. A developer uses the `safe` Meta option in a Django Unicorn component to bypass HTML escaping for a specific component property.
    2. An attacker injects malicious JavaScript code into this component property, potentially through user input or a database record.
    3. When the component re-renders, the injected JavaScript is included in the HTML without proper sanitization because of the `safe` Meta option.
    4. The browser executes the malicious JavaScript code, leading to Cross-Site Scripting (XSS).
- Impact:
    - Cross-Site Scripting (XSS) vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view a page containing the vulnerable component.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the web page.
    - If an administrator account is compromised, it could lead to full control of the web application.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks. This is a global mitigation applied to all component properties unless explicitly overridden.
    - The documentation explicitly warns against using `safe` with user-controlled content and highlights the risk of XSS. The documentation for `safe` Meta option is described in `..\\django-unicorn\\docs\\source\\views.md` file under "Meta" section and includes a warning: "Never put sensitive data into a public property because that information will publicly available in the HTML source code, unless explicitly prevented with [`javascript_exclude`](views.md#javascript_exclude)."
    - Developers have to explicitly opt-in to disable HTML encoding by using the `safe` Meta option, indicating a conscious decision to bypass default security measures.
- Missing Mitigations:
    - While documentation warns against unsafe usage of `safe`, there are no built-in mechanisms to prevent developers from using `safe` on user-controlled data.
    - There is no dynamic analysis or linting tool provided by django-unicorn to detect potentially unsafe usages of the `safe` Meta option.
- Preconditions:
    - A Django Unicorn component uses the `safe` Meta option for a property that is influenced by user input or data from an untrusted source.
    - An attacker must be able to inject malicious JavaScript code into the data source that populates the component property marked as `safe`.
- Source Code Analysis:
    1. File: `..\\django-unicorn\\docs\\source\\views.md`
        - The documentation for `safe` Meta option is described in `views.md` file under "Meta" section.
        - It clearly states: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
        - It also includes a warning: "Never put sensitive data into a public property because that information will publicly available in the HTML source code, unless explicitly prevented with [`javascript_exclude`](views.md#javascript_exclude)."
    2. File: `..\\django-unicorn\\docs\\source\\safe-example.py` and `..\\django-unicorn\\docs\\source\\safe-example.html`
        - Example code demonstrates how to use `safe` Meta option.
        - `SafeExampleView` component sets `something_safe` property and marks it as safe in `Meta` class.
        - `safe-example.html` template renders `something_safe` property.
        - This example highlights the usage of `safe` and implicitly the potential risk if misused.
    3. File: `..\\django-unicorn\\example\\unicorn\\components\\text_inputs.py`
        - Example component `TextInputsView` defines property `testing_xss = "Whatever </script> <script>alert('uh oh')</script>"`.
        - This property is not marked as `safe` in Meta class, so it will be HTML encoded by default when rendered in template. However, if a developer were to add `testing_xss` to the `safe` tuple in Meta, it would become vulnerable to XSS if the value was dynamically set from an untrusted source.
    4. Code flow during rendering:
        - When a component is rendered or re-rendered, the template engine processes the component's template (`safe-example.html` or any template using a component with `safe` option).
        - For properties marked as `safe` in the component's `Meta` class (`something_safe` in `SafeExampleView`), the template engine will render the property's value directly into the HTML without HTML encoding.
        - If the `something_safe` property contains malicious JavaScript (e.g., `<script>alert("XSS")</script>`), it will be inserted into the HTML as is.
        - The browser, upon receiving the HTML, will execute the embedded JavaScript code, leading to XSS.
- Security Test Case:
    1. Create a Django Unicorn component that uses the `safe` Meta option, similar to `SafeExampleView` from documentation.
        ```python
        # unsafe_component.py
        from django_unicorn.components import UnicornView

        class UnsafeComponentView(UnicornView):
            unsafe_data = ""

            class Meta:
                safe = ("unsafe_data", )
        ```
        ```html
        <!-- unsafe_component.html -->
        <div>
          <input unicorn:model="unsafe_data" type="text" id="unsafe_data_input" />
          {{ unsafe_data }}
        </div>
        ```
    2. Create a Django view and template to include this `UnsafeComponentView`.
        ```python
        # views.py
        from django.shortcuts import render
        from .components.unsafe_component import UnsafeComponentView

        def unsafe_view(request):
            return render(request, 'unsafe_template.html')
        ```
        ```html
        <!-- unsafe_template.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'unsafe-component' %}
        </body>
        </html>
        ```
    3. Access the page in a browser where the `unsafe_template.html` is rendered.
    4. In the input field (`unsafe_data_input`), enter the following JavaScript code: `<script>alert("XSS Vulnerability");</script>`.
    5. Click outside the input field to trigger `unicorn:model` update (or type something else in another field if lazy modifier is used).
    6. Observe that an alert box with the message "XSS Vulnerability" appears in the browser. This confirms that the JavaScript code was executed, demonstrating the XSS vulnerability.
