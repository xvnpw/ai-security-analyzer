- Vulnerability Name: Cross-Site Scripting (XSS) through Unsafe Output via `safe` Meta Option

- Description:
    1. A Django Unicorn component is designed to render dynamic content, potentially including user-controlled data, within a Django template.
    2. Developers can use the `safe` Meta option within a component to explicitly declare certain component properties as "safe" for HTML rendering, bypassing Django Unicorn's default HTML encoding.
    3. If a developer incorrectly marks a property containing user-controlled data as `safe` without proper sanitization, it creates an XSS vulnerability.
    4. An attacker injects malicious JavaScript code into the user-controlled data. This data could originate from various sources such as database records, URL parameters, or form inputs.
    5. When a component processes a message request or during initial rendering, the `_process_component_request` function in `django_unicorn/views/__init__.py` reads the `safe_fields` list from the component's `Meta` class.
    6. Within `_process_component_request`, for each field listed in `safe_fields`, the code checks if the attribute exists in the component's attributes. If it does, `mark_safe` from `django.utils.html` is applied to the attribute's value. This is done in `django_unicorn/views/__init__.py` inside the `_process_component_request` function, specifically in the section that handles `safe_fields`.
    7. When the component re-renders, the template receives the property value marked as safe. Django templates, recognizing the `mark_safe` flag, render the content without HTML encoding.
    8. Consequently, the injected JavaScript code is executed in the user's browser because the output is not sanitized due to the misused `safe` Meta option and `mark_safe`.

- Impact:
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code within a user's browser session.
    - This can lead to severe security consequences, including:
        - Session hijacking: Stealing session cookies to impersonate the user.
        - Cookie theft: Accessing sensitive information stored in cookies.
        - Redirection to malicious websites: Redirecting users to attacker-controlled sites for phishing or malware distribution.
        - Defacement: Altering the visual appearance of the web page.
        - Unauthorized actions: Performing actions on behalf of the user, such as data modification or financial transactions.
        - Information disclosure: Accessing sensitive user data or application secrets.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Default HTML Encoding**: Django Unicorn, by default, automatically HTML encodes component output. This behavior, introduced in version 0.36.0 as a fix for CVE-2021-42053, effectively prevents XSS in most cases.
    - **Opt-in `safe` Meta Option**: Developers must explicitly enable the `safe` Meta option for specific component properties to disable HTML encoding. This design intends to provide flexibility for developers who genuinely need to render unencoded HTML, but it shifts the responsibility for security to the developer.

- Missing Mitigations:
    - **Developer Warning**: There is no built-in mechanism to warn developers against using the `safe` option on properties that handle user-controlled data. Developers might unknowingly introduce XSS vulnerabilities by misusing this feature.
    - **Documentation Enhancement**: The documentation lacks a clear and prominent warning about the security risks associated with the `safe` Meta option. It should emphasize best practices and explicitly advise against using `safe` for user-controlled data without rigorous sanitization.
    - **Automated Security Checks**: The project lacks automated security checks or linters that could detect potentially unsafe usage of the `safe` Meta option. Static analysis tools could be integrated to identify components where `safe` is used in conjunction with user inputs.

- Preconditions:
    - **User-Controlled Data Rendering**: A Django Unicorn component must be designed to render user-controlled data in its template.
    - **Misuse of `safe` Meta Option**: The component developer must have incorrectly configured the `safe` Meta option for a property that displays user-controlled data without implementing proper sanitization.
    - **Data Injection Point**: An attacker needs to find a way to inject malicious JavaScript code into the source of the user-controlled data. This could be through various input vectors, such as:
        - Database: Injecting malicious scripts into database fields that are subsequently displayed by the component.
        - URL Parameters: Crafting URLs with malicious scripts in parameters that are bound to component properties.
        - Form Inputs: Submitting forms containing malicious scripts in input fields that are processed by the component.

- Source Code Analysis:
    1. **`django_unicorn/views/__init__.py` - `_process_component_request` function:**
        - This function is central to handling component requests and preparing the component for rendering.
        - It retrieves the list of fields marked as `safe` from the component's `Meta` class.
        - The critical part is the loop that iterates through `safe_fields`. Inside this loop, `mark_safe` is applied to the corresponding component attribute.
        ```python
        # django_unicorn/views/__init__.py
        from django.utils.html import mark_safe

        def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
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
            # ...
        ```
        - The vulnerability stems directly from the unconditional use of `mark_safe` on fields listed in `safe_fields`. If a developer mistakenly includes a user-controlled property in `safe_fields`, any malicious script in that property will be marked as safe and rendered without encoding.

    2. **`tests/views/test_process_component_request.py` - `test_safe_html_entities_not_encoded` function:**
        - This test explicitly demonstrates the vulnerability.
        - It creates a `FakeComponentSafe` component where the `hello` property is marked as `safe` in the `Meta` class.
        - The test injects HTML content (`<b>test1</b>`) into the `hello` property via a `syncInput` action.
        - It then asserts that the rendered DOM in the response contains the unencoded HTML (`<b>test1</b>`), proving that `mark_safe` bypasses HTML encoding when the `safe` Meta option is used.

        ```python
        # tests/views/test_process_component_request.py
        from tests.views.message.utils import post_and_get_response
        from django_unicorn.components import UnicornView

        class FakeComponentSafe(UnicornView):
            template_name = "templates/test_component_variable.html"
            hello = ""

            class Meta:
                safe = ("hello",)

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
            assert "<b>test1</b>" in response["dom"] # Asserting unencoded HTML in DOM
        ```

    **Vulnerability Flow Diagram:**

    ```
    Developer Configures `safe` Meta Option --> User Input (Malicious Script) --> Component Property (marked as `safe`) --> `_process_component_request` applies `mark_safe` --> Template Rendering (no HTML encoding) --> User Browser (malicious script execution)
    ```

- Security Test Case:
    1. **Setup Project**: Ensure you have a Django project with Django Unicorn installed and a running Django development server.
    2. **Create Vulnerable Component**: Create a new Django Unicorn component named `unsafe_component` within a Django app (e.g., `test_app`).
    3. **Define Vulnerable View**: In `test_app/components/unsafe_component.py`, define the component view as follows:
        ```python
        from django_unicorn.components import UnicornView

        class UnsafeComponentView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",) # Intentionally mark user_input as safe
        ```
    4. **Create Component Template**: Create the template for `unsafe_component` at `test_app/templates/unicorn/unsafe_component.html`:
        ```html
        <div>
            <input type="text" unicorn:model="user_input" id="unsafe-input">
            <div id="unsafe-output">User Input: {{ user_input }}</div>
        </div>
        ```
    5. **Integrate Component into Page**: Create a Django view and template to include the `unsafe_component`.
        - View in `test_app/views.py`:
            ```python
            from django.shortcuts import render

            def unsafe_home(request):
                return render(request, 'test_app/unsafe_home.html')
            ```
        - Template `test_app/templates/test_app/unsafe_home.html`:
            ```html
            {% load unicorn %}
            {% csrf_token %}
            <html>
            <head>
                {% unicorn_scripts %}
            </head>
            <body>
                {% unicorn 'unsafe-component' %}
            </body>
            </html>
            ```
    6. **Configure URLs**: Update `urls.py` in `test_app` and the project-level `urls.py` to include the `unsafe_home` view and Django Unicorn URLs.
    7. **Run Django Server**: Start the Django development server using `python manage.py runserver`.
    8. **Access Vulnerable Page**: Open a web browser and navigate to the URL corresponding to the `unsafe_home` view (e.g., `http://127.0.0.1:8000/unsafe_home/`).
    9. **Inject XSS Payload**: In the input field of the `unsafe_component`, enter the following XSS payload: `<script>alert('XSS Vulnerability via safe Meta!')</script>`.
    10. **Trigger Re-render**: Click outside the input field or perform any action that triggers a Django Unicorn update and component re-render.
    11. **Observe Exploitation**: Observe that an alert box with the message "XSS Vulnerability via safe Meta!" is displayed in the browser. This confirms that the injected JavaScript code was executed because the `user_input` property, marked as `safe`, was rendered without HTML encoding.
